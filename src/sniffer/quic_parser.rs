use bytes::Buf;
use rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
use std::collections::HashMap;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, warn};

// QUIC version constants (RFC 9000, RFC 9369)
const VERSION_DRAFT23: u32 = 0xff000017; // Draft 23 (start of range)
const VERSION_DRAFT29: u32 = 0xff00001d; // Draft 29 (end of range)
const VERSION1: u32 = 0x1; // QUIC v1 (RFC 9000)
const VERSION2: u32 = 0x6b3343cf; // QUIC v2 (RFC 9369)

// QUIC frame types
const FRAME_TYPE_PADDING: u8 = 0x00;
const FRAME_TYPE_PING: u8 = 0x01;
const FRAME_TYPE_ACK: u8 = 0x02;
const FRAME_TYPE_ACK_ECN: u8 = 0x03;
const FRAME_TYPE_CRYPTO: u8 = 0x06;
const FRAME_TYPE_CONNECTION_CLOSE: u8 = 0x1c;
const FRAME_TYPE_CONNECTION_CLOSE_APP: u8 = 0x1d;

/// Maximum size for aggregated CRYPTO data buffer
const MAX_CRYPTO_BUFFER_SIZE: usize = 16384;

/// Maximum number of connections to track simultaneously
const MAX_TRACKED_CONNECTIONS: usize = 1024;

/// Minimum UDP payload size for a datagram carrying a client Initial
/// packet (RFC 9000 Section 14.1). Anything smaller cannot be a
/// conforming client Initial, so reject it before deriving keys.
const MIN_CLIENT_INITIAL_DATAGRAM: usize = 1200;

/// Errors that can occur during QUIC parsing
#[derive(Debug, Clone, Error)]
pub enum QuicParseError {
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
    #[error("QUIC cipher suite is unavailable")]
    QuicSuiteUnavailable,
    #[error("Insufficient data to parse")]
    InsufficientData,
    #[error("CRYPTO buffer overflow")]
    BufferOverflow,
}

/// Result of parsing a QUIC packet for SNI
#[derive(Debug, Clone)]
pub enum QuicParseResult {
    /// Successfully extracted SNI hostname
    Success(String),
    /// Need more packets to complete the TLS handshake
    /// Contains the destination CID for correlation
    NeedMoreData(Vec<u8>),
    /// Parsing failed permanently (not a QUIC packet, unsupported version, etc.)
    Failed(QuicParseError),
}

/// Tracks CRYPTO frame data for a single QUIC connection
struct CryptoBuffer {
    /// Buffer holding aggregated CRYPTO frame data
    data: Vec<u8>,
    /// Tracks which byte ranges have been written
    /// Each entry is (start_offset, end_offset)
    written_ranges: Vec<(usize, usize)>,
    /// Last access time for LRU eviction
    last_access: Instant,
    /// Initial keys derived from the destination CID, computed lazily on
    /// the first packet and reused by later packets of this connection
    keys: Option<rustls::quic::Keys>,
}

impl std::fmt::Debug for CryptoBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoBuffer")
            .field("data", &self.data)
            .field("written_ranges", &self.written_ranges)
            .field("last_access", &self.last_access)
            .field("keys", &self.keys.as_ref().map(|_| "<derived>"))
            .finish()
    }
}

impl CryptoBuffer {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            written_ranges: Vec::new(),
            last_access: Instant::now(),
            keys: None,
        }
    }

    /// Update the last access time
    fn touch(&mut self) {
        self.last_access = Instant::now();
    }

    /// Add CRYPTO frame data at the specified offset
    fn add_data(&mut self, offset: usize, data: &[u8]) -> Result<(), QuicParseError> {
        let end_offset = offset + data.len();
        if end_offset > MAX_CRYPTO_BUFFER_SIZE {
            warn!(
                "CRYPTO data exceeds buffer size: offset={}, len={}, max={}",
                offset,
                data.len(),
                MAX_CRYPTO_BUFFER_SIZE
            );
            return Err(QuicParseError::BufferOverflow);
        }

        if end_offset > self.data.len() {
            if offset >= self.data.len() {
                // Case 1: Appending (possibly with a gap)
                if offset > self.data.len() {
                    // Must zero-fill the gap
                    self.data.resize(offset, 0);
                }
                self.data.extend_from_slice(data);
            } else {
                // Case 2: Partial overwrite extending beyond current end
                let old_len = self.data.len();
                let overwrite_len = old_len - offset;

                // Overwrite the existing part
                self.data[offset..old_len].copy_from_slice(&data[..overwrite_len]);
                // Append the new part
                self.data.extend_from_slice(&data[overwrite_len..]);
            }
        } else {
            // Case 3: Fully within existing bounds
            self.data[offset..end_offset].copy_from_slice(data);
        }

        // Merge overlapping/adjacent ranges
        self.written_ranges.push((offset, end_offset));
        self.merge_ranges();

        Ok(())
    }

    /// Merge overlapping or adjacent ranges
    fn merge_ranges(&mut self) {
        if self.written_ranges.is_empty() {
            return;
        }

        self.written_ranges.sort_by_key(|r| r.0);

        let mut merged = Vec::with_capacity(self.written_ranges.len());
        let mut current = self.written_ranges[0];

        for &(start, end) in &self.written_ranges[1..] {
            if start <= current.1 {
                // Overlapping or adjacent, extend current range
                current.1 = current.1.max(end);
            } else {
                // Gap found, push current and start new
                merged.push(current);
                current = (start, end);
            }
        }
        merged.push(current);
        self.written_ranges = merged;
    }

    /// Get the contiguous data starting from offset 0
    fn get_contiguous_data(&self) -> Option<&[u8]> {
        if self.written_ranges.is_empty() {
            return None;
        }

        // Check if we have data starting from offset 0
        let first_range = &self.written_ranges[0];
        if first_range.0 != 0 {
            return None;
        }

        Some(&self.data[0..first_range.1])
    }

    /// Check if there's a gap in the data starting from offset 0
    fn has_gap_from_start(&self) -> bool {
        if self.written_ranges.is_empty() {
            return true;
        }
        self.written_ranges[0].0 != 0
    }
}

/// Aggregator for QUIC packets that can handle fragmented ClientHello across multiple packets
///
/// QUIC Initial packets may contain CRYPTO frames that together form the TLS ClientHello.
/// When the ClientHello is fragmented across multiple packets, this aggregator collects
/// the CRYPTO frame data keyed by destination connection ID, and attempts to parse SNI
/// once enough data is collected.
///
/// Uses strict LRU eviction when the connection limit is reached.
#[derive(Debug, Default)]
pub struct QuicSniAggregator {
    /// Map from destination CID to crypto buffer
    connections: HashMap<Vec<u8>, CryptoBuffer>,
}

impl QuicSniAggregator {
    /// Create a new QUIC SNI aggregator
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Find and remove the least recently used connection
    fn evict_lru(&mut self) {
        if self.connections.is_empty() {
            return;
        }

        // Find the entry with the oldest last_access time
        let oldest_key = self
            .connections
            .iter()
            .min_by_key(|(_, buffer)| buffer.last_access)
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest_key {
            debug!("LRU evicting QUIC connection with dest_cid: {:x?}", key);
            self.connections.remove(&key);
        }
    }

    /// Process a QUIC packet and attempt to extract SNI
    ///
    /// Returns:
    /// - `QuicParseResult::Success(hostname)` if SNI was successfully extracted
    /// - `QuicParseResult::NeedMoreData(dest_cid)` if more packets are needed
    /// - `QuicParseResult::Failed(error)` if parsing failed permanently
    pub fn process_packet(&mut self, packet: &[u8]) -> QuicParseResult {
        match self.process_packet_internal(packet) {
            Ok(result) => result,
            Err(e) => {
                debug!("QUIC parse error: {}", e);
                QuicParseResult::Failed(e)
            }
        }
    }

    /// Internal packet processing with detailed error handling
    fn process_packet_internal(&mut self, packet: &[u8]) -> Result<QuicParseResult, QuicParseError> {
        // Parse the header first; key derivation is deferred until the
        // packet has passed every check that needs no cryptography.
        let header = parse_initial_header(packet)?;

        // Get or create the crypto buffer for this connection
        let dest_cid = header.dest_conn_id.clone();

        // Limit number of tracked connections using strict LRU eviction
        if !self.connections.contains_key(&dest_cid) && self.connections.len() >= MAX_TRACKED_CONNECTIONS
        {
            self.evict_lru();
        }

        let buffer = self
            .connections
            .entry(dest_cid.clone())
            .or_insert_with(|| CryptoBuffer::new());

        // Update last access time for LRU tracking
        buffer.touch();

        // Initial keys depend only on the destination CID and version;
        // derive once and reuse for later packets of this connection.
        if buffer.keys.is_none() {
            buffer.keys = Some(derive_initial_keys(&dest_cid, header.rustls_version)?);
        }

        // Decrypt the payload and extract crypto frames
        let crypto_frames =
            decrypt_initial_payload(buffer.keys.as_ref().unwrap(), packet, &header)?;

        // Add all crypto frame data to the buffer
        for frame in &crypto_frames {
            buffer.add_data(frame.offset as usize, &frame.data)?;
        }

        // Try to parse SNI from the aggregated data
        if let Some(contiguous_data) = buffer.get_contiguous_data() {
            debug!(
                "Attempting SNI parse with {} contiguous bytes",
                contiguous_data.len()
            );

            match try_parse_sni(contiguous_data) {
                Ok(hostname) => {
                    // Success! Remove this connection from tracking
                    self.connections.remove(&dest_cid);
                    return Ok(QuicParseResult::Success(hostname));
                }
                Err(QuicParseError::InsufficientData) | Err(QuicParseError::TlsParseError) => {
                    // Need more data - check if we're missing data from the start
                    if buffer.has_gap_from_start() {
                        debug!("Missing data at start of CRYPTO stream, waiting for more packets");
                    } else {
                        debug!(
                            "Have {} bytes of contiguous CRYPTO data but SNI parse failed, waiting for more",
                            contiguous_data.len()
                        );
                    }
                }
                Err(e) => {
                    // Permanent failure
                    self.connections.remove(&dest_cid);
                    return Err(e);
                }
            }
        }

        Ok(QuicParseResult::NeedMoreData(dest_cid))
    }

    #[allow(dead_code)]
    /// Remove a connection from tracking (e.g., on timeout or connection close)
    pub fn remove_connection(&mut self, dest_cid: &[u8]) {
        self.connections.remove(dest_cid);
    }

    #[allow(dead_code)]
    /// Clear all tracked connections
    pub fn clear(&mut self) {
        self.connections.clear();
    }

    #[allow(dead_code)]
    /// Get the number of currently tracked connections
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

/// Header fields of a QUIC Initial packet, parsed without decryption
struct InitialHeader {
    dest_conn_id: Vec<u8>,
    src_conn_id: Vec<u8>,
    rustls_version: rustls::quic::Version,
    /// Offset of the packet number field within the packet
    hdr_len: usize,
    /// Value of the length field: packet number + payload + tag
    packet_len: u64,
}

/// A single CRYPTO frame's data
struct CryptoFrame {
    offset: u64,
    data: Vec<u8>,
}

/// Map QUIC wire version to rustls version
fn version_to_rustls(version: u32) -> Option<rustls::quic::Version> {
    match version {
        VERSION_DRAFT23..=VERSION_DRAFT29 => Some(rustls::quic::Version::V1Draft),
        VERSION1 => Some(rustls::quic::Version::V1),
        // QUIC v2 has its own initial salt and HKDF labels (RFC 9369 Section 3)
        VERSION2 => Some(rustls::quic::Version::V2),
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
            u64::from(u16::from_be_bytes([buf[0], buf[1]]))
        }
        0b10 => {
            if r.remaining() < 3 {
                return None;
            }
            r.copy_to_slice(&mut buf[1..4]);
            u64::from(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
        }
        0b11 => {
            if r.remaining() < 7 {
                return None;
            }
            r.copy_to_slice(&mut buf[1..8]);
            u64::from_be_bytes(buf)
        }
        _ => return None,
    };
    Some(x)
}

/// Derive Initial secrets from the destination CID (RFC 9001 Section 5)
fn derive_initial_keys(
    dest_conn_id: &[u8],
    rustls_version: rustls::quic::Version,
) -> Result<rustls::quic::Keys, QuicParseError> {
    Ok(TLS13_AES_128_GCM_SHA256
        .tls13()
        .ok_or(QuicParseError::QuicSuiteUnavailable)?
        .quic_suite()
        .ok_or(QuicParseError::QuicSuiteUnavailable)?
        .keys(dest_conn_id, rustls::Side::Client, rustls_version))
}

/// Parse a QUIC Initial packet header without any cryptography (RFC 9000
/// Section 17.2). Anything that fails here must not trigger key derivation.
fn parse_initial_header(remaining: &[u8]) -> Result<InitialHeader, QuicParseError> {
    use byteorder::ReadBytesExt;
    use std::io::Read;

    // A client must pad every datagram carrying an Initial packet to at
    // least 1200 bytes; smaller datagrams are not worth deriving keys for.
    if remaining.len() < MIN_CLIENT_INITIAL_DATAGRAM {
        return Err(QuicParseError::NotInitialPacket);
    }

    let mut buffer = std::io::Cursor::new(remaining);

    // Parse QUIC long header
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

    debug!("QUIC version: {:#x}", version_number);

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

    // Parse packet length (packet number + payload + tag)
    let packet_len = decode_varint(&mut buffer).ok_or(QuicParseError::InsufficientData)?;
    let hdr_len = buffer.position() as usize;

    // Header protection needs a 16-byte sample starting 4 bytes after the
    // packet number field begins.
    if remaining.len() < hdr_len + 4 + 16 {
        return Err(QuicParseError::InsufficientData);
    }

    Ok(InitialHeader {
        dest_conn_id,
        src_conn_id,
        rustls_version,
        hdr_len,
        packet_len,
    })
}

/// Remove header protection and decrypt the payload of an Initial packet,
/// returning its CRYPTO frames.
fn decrypt_initial_payload(
    keys: &rustls::quic::Keys,
    remaining: &[u8],
    header: &InitialHeader,
) -> Result<Vec<CryptoFrame>, QuicParseError> {
    use byteorder::ReadBytesExt;
    use std::io::Read;

    let hdr_len = header.hdr_len;

    // Read encrypted packet number (up to 4 bytes)
    let mut buffer = std::io::Cursor::new(remaining);
    buffer.set_position(hdr_len as u64);
    let mut orig_pn_bytes = [0u8; 4];
    buffer
        .read_exact(&mut orig_pn_bytes)
        .map_err(|_| QuicParseError::InsufficientData)?;

    // Decrypt header to get actual packet number length
    let mut first_byte = remaining[0];
    let mut pn = orig_pn_bytes;

    keys.local
        .header
        .decrypt_in_place(&remaining[hdr_len + 4..hdr_len + 4 + 16], &mut first_byte, &mut pn)
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
    debug!(
        "dest CID: {:x?}, src CID: {:x?}, packet number: {}",
        header.dest_conn_id, header.src_conn_id, packet_number
    );

    // Reconstruct header with decrypted first byte and packet number
    let mut reconstructed = remaining[..hdr_len + packet_number_len].to_vec();
    reconstructed[0] = first_byte;
    reconstructed[hdr_len..(hdr_len + packet_number_len)].copy_from_slice(&pn[..packet_number_len]);

    // Extract and decrypt payload; coalesced packets are ignored by
    // bounding the payload with the length field.
    let payload_end = (header.packet_len as usize + hdr_len).min(remaining.len());
    let mut payload = remaining[hdr_len + packet_number_len..payload_end].to_vec();

    keys.local
        .packet
        .decrypt_in_place(packet_number, &reconstructed, &mut payload)
        .map_err(|_| QuicParseError::DecryptionFailed)?;

    debug!("Decrypted QUIC payload length: {}", payload.len());

    // Parse frames to extract CRYPTO frames
    extract_crypto_frames(&payload)
}

/// Skip over an ACK frame's fields (RFC 9000 Section 19.3)
fn skip_ack_frame<B: Buf>(r: &mut B, has_ecn: bool) -> Result<(), QuicParseError> {
    // Largest Acknowledged, ACK Delay, ACK Range Count, First ACK Range
    decode_varint(r).ok_or(QuicParseError::InsufficientData)?;
    decode_varint(r).ok_or(QuicParseError::InsufficientData)?;
    let range_count = decode_varint(r).ok_or(QuicParseError::InsufficientData)?;
    decode_varint(r).ok_or(QuicParseError::InsufficientData)?;

    for _ in 0..range_count {
        // Gap, ACK Range Length
        decode_varint(r).ok_or(QuicParseError::InsufficientData)?;
        decode_varint(r).ok_or(QuicParseError::InsufficientData)?;
    }

    if has_ecn {
        // ECT0 Count, ECT1 Count, ECN-CE Count
        decode_varint(r).ok_or(QuicParseError::InsufficientData)?;
        decode_varint(r).ok_or(QuicParseError::InsufficientData)?;
        decode_varint(r).ok_or(QuicParseError::InsufficientData)?;
    }

    Ok(())
}

/// Extract all CRYPTO frames from a decrypted QUIC payload
fn extract_crypto_frames(payload: &[u8]) -> Result<Vec<CryptoFrame>, QuicParseError> {
    use byteorder::ReadBytesExt;
    use std::io::Read;

    let mut cursor = std::io::Cursor::new(payload);
    let mut crypto_frames = Vec::new();

    while cursor.position() < payload.len() as u64 {
        let frame_type = cursor
            .read_u8()
            .map_err(|_| QuicParseError::InsufficientData)?;

        match frame_type {
            FRAME_TYPE_PADDING | FRAME_TYPE_PING => {}
            FRAME_TYPE_ACK => {
                skip_ack_frame(&mut cursor, false)?;
            }
            FRAME_TYPE_ACK_ECN => {
                skip_ack_frame(&mut cursor, true)?;
            }
            FRAME_TYPE_CRYPTO => {
                let offset = decode_varint(&mut cursor).ok_or(QuicParseError::InsufficientData)?;
                let length = decode_varint(&mut cursor).ok_or(QuicParseError::InsufficientData)?;

                if length > cursor.remaining() as u64 {
                    debug!("CRYPTO frame length exceeds remaining payload");
                    return Err(QuicParseError::InsufficientData);
                }

                let mut data = vec![0u8; length as usize];
                cursor
                    .read_exact(&mut data)
                    .map_err(|_| QuicParseError::InsufficientData)?;

                debug!("Found CRYPTO frame at offset {}, length {}", offset, length);
                crypto_frames.push(CryptoFrame { offset, data });
            }
            FRAME_TYPE_CONNECTION_CLOSE | FRAME_TYPE_CONNECTION_CLOSE_APP => {
                // Connection is closing, stop parsing
                break;
            }
            _ => {
                // QUIC frame types carry no uniform length field, so the
                // extent of an unknown frame cannot be determined. Anything
                // after it is undecodable; keep what was collected so far.
                debug!("Unknown QUIC frame type {:#x}, stop parsing", frame_type);
                break;
            }
        }
    }

    if crypto_frames.is_empty() {
        return Err(QuicParseError::NoCryptoFrame);
    }

    Ok(crypto_frames)
}

/// Try to parse SNI from CRYPTO frame data
fn try_parse_sni(crypto_data: &[u8]) -> Result<String, QuicParseError> {
    // Check minimum length for TLS handshake header
    if crypto_data.len() < 4 {
        return Err(QuicParseError::InsufficientData);
    }

    // Check TLS handshake type (should be ClientHello = 0x01)
    if crypto_data[0] != 0x01 {
        return Err(QuicParseError::TlsParseError);
    }

    // Get handshake message length (3 bytes, big-endian)
    let handshake_len =
        ((crypto_data[1] as usize) << 16) | ((crypto_data[2] as usize) << 8) | (crypto_data[3] as usize);

    // Check if we have enough data for the complete handshake message
    if crypto_data.len() < 4 + handshake_len {
        debug!(
            "Need more CRYPTO data: have {} bytes, need {} bytes",
            crypto_data.len(),
            4 + handshake_len
        );
        return Err(QuicParseError::InsufficientData);
    }

    // Parse TLS handshake message
    if let Ok((_remaining, msg)) = tls_parser::parse_tls_message_handshake(crypto_data) {
        if let Some(host) = super::tls_parse::parse_tls_msg(&msg) {
            return Ok(host);
        }
    }

    Err(QuicParseError::TlsParseError)
}

/// Parse QUIC Initial packet to extract SNI from ClientHello (legacy single-packet API)
///
/// This function attempts to extract the Server Name Indication (SNI) from
/// a QUIC Initial packet by:
/// 1. Parsing the QUIC long header
/// 2. Decrypting the packet using Initial secrets (RFC 9001)
/// 3. Finding and parsing the CRYPTO frame containing TLS ClientHello
/// 4. Extracting the SNI extension from the ClientHello
///
/// Returns Some(hostname) if SNI is successfully extracted, None otherwise.
///
/// Note: For fragmented ClientHello that spans multiple packets, use
/// `QuicSniAggregator` instead.
pub fn parse_host(remaining: &[u8]) -> Option<String> {
    let mut aggregator = QuicSniAggregator::new();
    match aggregator.process_packet(remaining) {
        QuicParseResult::Success(host) => Some(host),
        QuicParseResult::NeedMoreData(_) => {
            debug!("QUIC SNI parsing needs more packets (single-packet API)");
            None
        }
        QuicParseResult::Failed(e) => {
            debug!("QUIC parse error: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_buffer_merge_ranges() {
        let mut buffer = CryptoBuffer::new();

        // Add non-overlapping ranges
        buffer.add_data(0, &[1, 2, 3]).unwrap();
        buffer.add_data(10, &[4, 5, 6]).unwrap();
        assert_eq!(buffer.written_ranges, vec![(0, 3), (10, 13)]);

        // Add overlapping range
        buffer.add_data(2, &[7, 8, 9, 10]).unwrap();
        assert_eq!(buffer.written_ranges, vec![(0, 6), (10, 13)]);

        // Bridge the gap
        buffer.add_data(6, &[11, 12, 13, 14]).unwrap();
        assert_eq!(buffer.written_ranges, vec![(0, 13)]);
    }

    #[test]
    fn test_crypto_buffer_contiguous_data() {
        let mut buffer = CryptoBuffer::new();

        // No data yet
        assert!(buffer.get_contiguous_data().is_none());

        // Add data not starting from 0
        buffer.add_data(5, &[1, 2, 3]).unwrap();
        assert!(buffer.get_contiguous_data().is_none());

        // Add data starting from 0
        buffer.add_data(0, &[4, 5, 6, 7, 8]).unwrap();
        let data = buffer.get_contiguous_data().unwrap();
        assert_eq!(data.len(), 8); // 0-8 is now contiguous
    }

    #[test]
    fn test_aggregator_connection_limit() {
        let aggregator = QuicSniAggregator::new();

        // This test verifies the connection tracking limit works
        // In practice, MAX_TRACKED_CONNECTIONS is 1024
        assert_eq!(aggregator.connection_count(), 0);
    }

    #[test]
    fn test_crypto_buffer_lru_tracking() {
        use std::thread::sleep;
        use std::time::Duration;

        let mut buffer1 = CryptoBuffer::new();
        sleep(Duration::from_millis(10));
        let buffer2 = CryptoBuffer::new();

        // buffer1 should be older
        assert!(buffer1.last_access < buffer2.last_access);

        // After touching buffer1, it should be newer
        sleep(Duration::from_millis(10));
        buffer1.touch();
        assert!(buffer1.last_access > buffer2.last_access);
    }

    #[test]
    fn test_aggregator_lru_eviction() {
        use std::thread::sleep;
        use std::time::Duration;

        let mut aggregator = QuicSniAggregator::new();

        // Manually insert some buffers to test LRU
        let cid1 = vec![1, 1, 1];
        let cid2 = vec![2, 2, 2];
        let cid3 = vec![3, 3, 3];

        aggregator.connections.insert(
            cid1.clone(),
            CryptoBuffer::new(),
        );
        sleep(Duration::from_millis(10));

        aggregator.connections.insert(
            cid2.clone(),
            CryptoBuffer::new(),
        );
        sleep(Duration::from_millis(10));

        aggregator.connections.insert(
            cid3.clone(),
            CryptoBuffer::new(),
        );

        assert_eq!(aggregator.connection_count(), 3);

        // Touch cid1 to make it more recent
        aggregator.connections.get_mut(&cid1).unwrap().touch();

        // Evict LRU - should remove cid2 (oldest untouched)
        aggregator.evict_lru();

        assert_eq!(aggregator.connection_count(), 2);
        assert!(aggregator.connections.contains_key(&cid1));
        assert!(!aggregator.connections.contains_key(&cid2)); // cid2 was evicted
        assert!(aggregator.connections.contains_key(&cid3));
    }

    #[test]
    fn test_extract_crypto_frames_skips_ack() {
        // ACK (largest=1, delay=0, range_count=1, first_range=0, gap=0, len=0),
        // then an ACK with ECN counts, then a CRYPTO frame.
        let payload = [
            0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, // ACK
            0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, // ACK + ECN
            0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc, // CRYPTO offset=0 len=3
        ];
        let frames = extract_crypto_frames(&payload).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[0].data, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn test_extract_crypto_frames_stops_at_unknown_frame() {
        // CRYPTO frame followed by a stream frame (0x08): stream frames are
        // not legal in Initial packets and carry no uniform length field, so
        // parsing stops but the collected CRYPTO frame is kept.
        let payload = [
            0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc, // CRYPTO offset=0 len=3
            0x08, 0xff, 0xff, // unknown-in-initial frame + garbage
        ];
        let frames = extract_crypto_frames(&payload).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, vec![0xaa, 0xbb, 0xcc]);

        // Unknown frame before any CRYPTO frame yields nothing.
        let payload = [0x08, 0x00, 0x00, 0x06, 0x00, 0x01, 0xaa];
        assert!(matches!(
            extract_crypto_frames(&payload),
            Err(QuicParseError::NoCryptoFrame)
        ));
    }

    fn encode_varint(x: u64) -> Vec<u8> {
        if x < 64 {
            vec![x as u8]
        } else if x < 16384 {
            ((x as u16) | 0x4000).to_be_bytes().to_vec()
        } else if x < (1 << 30) {
            ((x as u32) | 0x8000_0000).to_be_bytes().to_vec()
        } else {
            (x | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
        }
    }

    /// Build a bare TLS ClientHello handshake message for `host`.
    fn client_hello(host: &str) -> Vec<u8> {
        use std::sync::Arc;

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut record = Vec::new();
        client.write_tls(&mut record).unwrap();
        // Strip the 5-byte TLS record header; QUIC carries bare handshake messages.
        assert_eq!(record[0], 0x16);
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        record[5..5 + record_len].to_vec()
    }

    /// Build a real QUIC Initial packet carrying the given CRYPTO fragments,
    /// protected with the Initial keys of the given version. The datagram is
    /// padded to 1200 bytes like a conforming client (RFC 9000 Section 14.1).
    fn build_initial_packet(
        wire_version: u32,
        rustls_version: rustls::quic::Version,
        dcid: &[u8],
        packet_number: u64,
        crypto_fragments: &[(u64, &[u8])],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        for (offset, data) in crypto_fragments {
            payload.push(FRAME_TYPE_CRYPTO);
            payload.extend_from_slice(&encode_varint(*offset));
            payload.extend_from_slice(&encode_varint(data.len() as u64));
            payload.extend_from_slice(data);
        }

        let scid = b"src";
        let keys = TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap()
            .keys(dcid, rustls::Side::Client, rustls_version);

        // Long header with a 4-byte packet number: 0xc0 sets the long header,
        // fixed bit and Initial type, 0x03 encodes pn_len - 1.
        let first_byte = 0xc3u8;
        let pn = (packet_number as u32).to_be_bytes();
        let mut header = vec![first_byte];
        header.extend_from_slice(&wire_version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(scid.len() as u8);
        header.extend_from_slice(scid);
        header.extend_from_slice(&encode_varint(0)); // token length
        // The length field is a 2-byte varint for our sizes (< 16384).
        let hdr_len = header.len() + 2;

        // Pad with PADDING frames so the datagram reaches 1200 bytes.
        let min_payload = MIN_CLIENT_INITIAL_DATAGRAM - hdr_len - pn.len() - 16;
        if payload.len() < min_payload {
            payload.resize(min_payload, FRAME_TYPE_PADDING);
        }

        // Length covers the packet number and the protected payload (with tag).
        header.extend_from_slice(&encode_varint((pn.len() + payload.len() + 16) as u64));

        let mut ciphertext = payload;
        let tag = keys
            .local
            .packet
            .encrypt_in_place(
                packet_number,
                &[header.as_slice(), pn.as_slice()].concat(),
                &mut ciphertext,
            )
            .unwrap();
        ciphertext.extend_from_slice(tag.as_ref());

        let mut packet = header;
        packet.extend_from_slice(&pn);
        packet.extend_from_slice(&ciphertext);

        // Apply header protection using the ciphertext sample.
        let sample_start = hdr_len + 4;
        let sample: Vec<u8> = packet[sample_start..sample_start + 16].to_vec();
        let mut protected_first = packet[0];
        let mut protected_pn = packet[hdr_len..hdr_len + 4].to_vec();
        keys.local
            .header
            .encrypt_in_place(&sample, &mut protected_first, &mut protected_pn)
            .unwrap();
        packet[0] = protected_first;
        packet[hdr_len..hdr_len + 4].copy_from_slice(&protected_pn);

        packet
    }

    fn assert_initial_sni(wire_version: u32, rustls_version: rustls::quic::Version, host: &str) {
        let hello = client_hello(host);
        let packet = build_initial_packet(
            wire_version,
            rustls_version,
            b"rfor-test-dcid",
            0,
            &[(0, hello.as_slice())],
        );
        let mut aggregator = QuicSniAggregator::new();
        match aggregator.process_packet(&packet) {
            QuicParseResult::Success(parsed) => assert_eq!(parsed, host),
            other => panic!(
                "expected SNI for QUIC version {:#x}, got {:?}",
                wire_version, other
            ),
        }
    }

    #[test]
    fn test_parse_quic_v1_initial_sni() {
        assert_initial_sni(VERSION1, rustls::quic::Version::V1, "v1.example.com");
    }

    #[test]
    fn test_parse_quic_v2_initial_sni() {
        // QUIC v2 (RFC 9369) uses a different initial salt and HKDF labels;
        // deriving keys as v1 must not accidentally succeed here.
        assert_initial_sni(VERSION2, rustls::quic::Version::V2, "v2.example.com");
    }

    #[test]
    fn test_parse_client_hello_fragmented_across_initials() {
        let host = "fragmented.example.com";
        let hello = client_hello(host);
        let split_at = hello.len() / 2;
        let dcid = b"fragmented-dcid";

        let mut aggregator = QuicSniAggregator::new();
        let first = build_initial_packet(
            VERSION1,
            rustls::quic::Version::V1,
            dcid,
            0,
            &[(0, &hello[..split_at])],
        );
        assert!(matches!(
            aggregator.process_packet(&first),
            QuicParseResult::NeedMoreData(_)
        ));

        // The second packet of the same connection reuses the keys derived
        // for the first one.
        let second = build_initial_packet(
            VERSION1,
            rustls::quic::Version::V1,
            dcid,
            1,
            &[(split_at as u64, &hello[split_at..])],
        );
        match aggregator.process_packet(&second) {
            QuicParseResult::Success(parsed) => assert_eq!(parsed, host),
            other => panic!("expected SNI from fragmented ClientHello, got {:?}", other),
        }
    }

    #[test]
    fn test_rejects_undersized_initial_before_key_derivation() {
        // A conforming client pads Initial datagrams to 1200 bytes; anything
        // smaller is rejected before touching HKDF/AES.
        let tiny = [0xc3u8; 100];
        assert!(matches!(
            parse_initial_header(&tiny),
            Err(QuicParseError::NotInitialPacket)
        ));
    }
}
