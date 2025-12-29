use bytes::Buf;
use rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
use thiserror::Error;

// QUIC version constants (RFC 9000, RFC 9369)
#[allow(dead_code)]
const VERSION_DRAFT23: u32 = 0xff000017; // Draft 23
#[allow(dead_code)]
const VERSION_DRAFT24: u32 = 0xff000018; // Draft 24
#[allow(dead_code)]
const VERSION_DRAFT25: u32 = 0xff000019; // Draft 25
#[allow(dead_code)]
const VERSION_DRAFT26: u32 = 0xff00001a; // Draft 26
#[allow(dead_code)]
const VERSION_DRAFT27: u32 = 0xff00001b; // Draft 27
#[allow(dead_code)]
const VERSION_DRAFT28: u32 = 0xff00001c; // Draft 28
const VERSION_DRAFT29: u32 = 0xff00001d; // Draft 29
const VERSION1: u32 = 0x1; // QUIC v1 (RFC 9000)
const VERSION2: u32 = 0x6b3343cf; // QUIC v2 (RFC 9369)

// QUIC frame types
const FRAME_TYPE_PADDING: u8 = 0x00;
const FRAME_TYPE_PING: u8 = 0x01;
const FRAME_TYPE_CRYPTO: u8 = 0x06;
const FRAME_TYPE_CONNECTION_CLOSE: u8 = 0x1c;
const FRAME_TYPE_CONNECTION_CLOSE_APP: u8 = 0x1d;

/// Errors that can occur during QUIC parsing
#[derive(Debug, Error)]
enum QuicParseError {
    #[error("Not a QUIC long header packet")]
    NotLongHeader,
    #[error("Unsupported QUIC version: {0:#x}")]
    UnsupportedVersion(u32),
    #[error("Not an Initial packet")]
    NotInitialPacket,
    #[error("Header decryption failed")]
    DecryptionFailed,
    #[error("No CRYPTO frame found in packet")]
    NoCryptoFrame,
    #[error("TLS handshake parsing failed")]
    TlsParseError,
    #[error("Insufficient data to parse")]
    InsufficientData,
}

/// Map QUIC wire version to rustls version
fn version_to_rustls(version: u32) -> Option<rustls::quic::Version> {
    match version {
        VERSION_DRAFT23..=VERSION_DRAFT29 => Some(rustls::quic::Version::V1Draft),
        VERSION1 => Some(rustls::quic::Version::V1),
        VERSION2 => Some(rustls::quic::Version::V1), // QUIC v2 uses same initial secrets as v1
        _ => None,
    }
}

/// Decode a QUIC variable-length integer (RFC 9000 Section 16)
fn decode_varint<B: Buf>(r: &mut B) -> Option<u64> {
    if !r.has_remaining() {
        return None;
    }
    let mut buf = [0; 8];
    buf[0] = r.get_u8();
    let tag = buf[0] >> 6;
    buf[0] &= 0b0011_1111;
    let x = match tag {
        0b00 => u64::from(buf[0]),
        0b01 => {
            if r.remaining() < 1 {
                return None;
            }
            r.copy_to_slice(&mut buf[1..2]);
            u64::from(u16::from_be_bytes(buf[..2].try_into().unwrap()))
        }
        0b10 => {
            if r.remaining() < 3 {
                return None;
            }
            r.copy_to_slice(&mut buf[1..4]);
            u64::from(u32::from_be_bytes(buf[..4].try_into().unwrap()))
        }
        0b11 => {
            if r.remaining() < 7 {
                return None;
            }
            r.copy_to_slice(&mut buf[1..8]);
            u64::from_be_bytes(buf)
        }
        _ => unreachable!(),
    };
    Some(x)
}

/// Parse QUIC Initial packet to extract SNI from ClientHello
///
/// This function attempts to extract the Server Name Indication (SNI) from
/// a QUIC Initial packet by:
/// 1. Parsing the QUIC long header
/// 2. Decrypting the packet using Initial secrets (RFC 9001)
/// 3. Finding and parsing the CRYPTO frame containing TLS ClientHello
/// 4. Extracting the SNI extension from the ClientHello
///
/// Returns Some(hostname) if SNI is successfully extracted, None otherwise.
pub fn parse_host(remaining: &[u8]) -> Option<String> {
    match parse_host_internal(remaining) {
        Ok(host) => Some(host),
        Err(e) => {
            tracing::debug!("QUIC parse error: {}", e);
            None
        }
    }
}

/// Internal implementation with detailed error handling
fn parse_host_internal(remaining: &[u8]) -> Result<String, QuicParseError> {
    use byteorder::ReadBytesExt;
    use std::io::Read;

    let mut buffer = std::io::Cursor::new(remaining);

    // Parse QUIC long header (RFC 9000 Section 17.2)
    let type_byte = buffer
        .read_u8()
        .map_err(|_| QuicParseError::InsufficientData)?;

    // Check for long header format (bit 7 = 1)
    let is_long_header = type_byte & 0x80 > 0;
    // Check for fixed bit (bit 6 = 1)
    let has_fixed_bit = type_byte & 0x40 > 0;

    if !is_long_header || !has_fixed_bit {
        return Err(QuicParseError::NotLongHeader);
    }

    // Read version
    let mut version_bytes = [0u8; 4];
    buffer
        .read_exact(&mut version_bytes)
        .map_err(|_| QuicParseError::InsufficientData)?;
    let version_number = u32::from_be_bytes(version_bytes);

    // Validate version is supported
    let rustls_version = version_to_rustls(version_number)
        .ok_or(QuicParseError::UnsupportedVersion(version_number))?;

    // Check packet type (bits 4-5) - must be Initial (0x0)
    let packet_type = (type_byte & 0x30) >> 4;
    if packet_type != 0x0 {
        return Err(QuicParseError::NotInitialPacket);
    }

    // Parse connection IDs
    let dest_conn_id_len = buffer
        .read_u8()
        .map_err(|_| QuicParseError::InsufficientData)? as usize;
    let mut dest_conn_id = vec![0u8; dest_conn_id_len];
    buffer
        .read_exact(&mut dest_conn_id)
        .map_err(|_| QuicParseError::InsufficientData)?;

    let src_conn_id_len = buffer
        .read_u8()
        .map_err(|_| QuicParseError::InsufficientData)? as usize;
    let mut src_conn_id = vec![0u8; src_conn_id_len];
    buffer
        .read_exact(&mut src_conn_id)
        .map_err(|_| QuicParseError::InsufficientData)?;

    // Parse token
    let token_len = decode_varint(&mut buffer).ok_or(QuicParseError::InsufficientData)? as usize;
    let mut token = vec![0u8; token_len];
    buffer
        .read_exact(&mut token)
        .map_err(|_| QuicParseError::InsufficientData)?;

    // Parse packet length
    let packet_len = decode_varint(&mut buffer).ok_or(QuicParseError::InsufficientData)?;
    let hdr_len = buffer.position() as usize;

    // Read encrypted packet number (up to 4 bytes)
    let mut orig_pn_bytes = [0u8; 4];
    buffer
        .read_exact(&mut orig_pn_bytes)
        .map_err(|_| QuicParseError::InsufficientData)?;

    // Derive Initial secrets and decrypt header (RFC 9001 Section 5)
    let key_len = 16; // AES-128-GCM sample length
    let keys = TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .quic_suite()
        .unwrap()
        .keys(&dest_conn_id, rustls::Side::Client, rustls_version);

    // Decrypt header to get actual packet number length
    let mut first_byte = remaining[0];
    let mut pn = orig_pn_bytes;
    keys.local
        .header
        .decrypt_in_place(
            &remaining[hdr_len + 4..hdr_len + 4 + key_len],
            &mut first_byte,
            &mut pn,
        )
        .map_err(|_| QuicParseError::DecryptionFailed)?;

    // Extract packet number length (bits 0-1 of first byte)
    let packet_number_len = 1 + (first_byte & 0b11) as usize;

    // Validate packet number length (1-4 bytes per RFC 9000)
    if packet_number_len > 4 {
        return Err(QuicParseError::DecryptionFailed);
    }

    // Decode packet number from decrypted bytes
    let packet_number = match packet_number_len {
        1 => u64::from(pn[0]),
        2 => u64::from(u16::from_be_bytes([pn[0], pn[1]])),
        3 => u64::from(u32::from_be_bytes([0, pn[0], pn[1], pn[2]])),
        4 => u64::from(u32::from_be_bytes([pn[0], pn[1], pn[2], pn[3]])),
        _ => return Err(QuicParseError::DecryptionFailed),
    };

    // Reconstruct header with decrypted first byte and packet number
    let mut header = remaining[..hdr_len + packet_number_len].to_vec();
    header[0] = first_byte;
    header[hdr_len..(hdr_len + packet_number_len)].copy_from_slice(&pn[..packet_number_len]);

    // Extract and decrypt payload
    let payload_end = (packet_len as usize + hdr_len).min(remaining.len());
    let mut payload = remaining[hdr_len + packet_number_len..payload_end].to_vec();

    keys.local
        .packet
        .decrypt_in_place(packet_number, &header, &mut payload)
        .map_err(|_| QuicParseError::DecryptionFailed)?;

    // Parse frames to find CRYPTO frame
    parse_frames_for_crypto(&payload)
}

/// Parse QUIC frames looking for CRYPTO frame with TLS ClientHello
fn parse_frames_for_crypto(payload: &[u8]) -> Result<String, QuicParseError> {
    use byteorder::ReadBytesExt;
    use std::io::Read;

    let mut cursor = std::io::Cursor::new(payload);

    // Iterate through frames until we find CRYPTO or run out of data
    while cursor.position() < payload.len() as u64 {
        let frame_type = cursor
            .read_u8()
            .map_err(|_| QuicParseError::InsufficientData)?;

        match frame_type {
            FRAME_TYPE_PADDING => {
                // PADDING frame: just skip (RFC 9000 Section 19.1)
                continue;
            }
            FRAME_TYPE_PING => {
                // PING frame: no additional data (RFC 9000 Section 19.2)
                continue;
            }
            FRAME_TYPE_CRYPTO => {
                // CRYPTO frame: contains TLS handshake data (RFC 9000 Section 19.6)
                let offset = decode_varint(&mut cursor).ok_or(QuicParseError::InsufficientData)?;

                // For Initial packets, ClientHello should start at offset 0
                // but we'll be more lenient and accept any offset
                let length = decode_varint(&mut cursor).ok_or(QuicParseError::InsufficientData)?;

                if length > cursor.remaining() as u64 {
                    return Err(QuicParseError::InsufficientData);
                }

                let mut crypto_data = vec![0u8; length as usize];
                cursor
                    .read_exact(&mut crypto_data)
                    .map_err(|_| QuicParseError::InsufficientData)?;

                // Parse TLS handshake to extract SNI
                // Only parse if offset is 0 (first CRYPTO frame)
                if offset == 0 {
                    return parse_handshake_host(&crypto_data).ok_or(QuicParseError::TlsParseError);
                }
            }
            FRAME_TYPE_CONNECTION_CLOSE | FRAME_TYPE_CONNECTION_CLOSE_APP => {
                // CONNECTION_CLOSE frame: connection is closing
                // No point continuing to parse
                return Err(QuicParseError::NoCryptoFrame);
            }
            _ => {
                // Unknown or unhandled frame type
                // Try to skip it by reading the frame-specific data
                // Most frames have a length field as varint
                if let Some(length) = decode_varint(&mut cursor) {
                    let skip_len = length.min(cursor.remaining() as u64) as usize;
                    cursor.set_position(cursor.position() + skip_len as u64);
                } else {
                    // Can't determine frame length, give up
                    break;
                }
            }
        }
    }

    Err(QuicParseError::NoCryptoFrame)
}

/// Parse TLS handshake message to extract SNI
fn parse_handshake_host(remaining: &[u8]) -> Option<String> {
    if let Ok((_remaining, msg)) = tls_parser::parse_tls_message_handshake(remaining) {
        if let Some(host) = super::tls_parse::parse_tls_msg(&msg) {
            return Some(host);
        }
    }

    None
}
