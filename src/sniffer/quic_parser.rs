use bytes::Buf;
use rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;

const VERSION_DRAFT29: u32 = 0xff00001d;
const VERSION1: u32 = 0x1;

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

pub fn parse_host(remaining: &[u8]) -> Option<String> {
    use byteorder::ReadBytesExt;
    use std::io::Read;

    let mut buffer = std::io::Cursor::new(remaining);

    let type_byte = buffer.read_u8().ok()?;

    let is_long_header = type_byte & 0x80 > 0;
    if !is_long_header || type_byte & 0x40 == 0 {
        return None;
    }

    let mut version_bytes = [0u8; 4];
    buffer.read(&mut version_bytes).ok()?;
    let version_number = u32::from_be_bytes(version_bytes);
    if version_number != 0 && type_byte & 0x40 == 0 {
        return None;
    }

    if version_number != VERSION_DRAFT29 && version_number != VERSION1 {
        return None;
    }

    if (type_byte & 0x30) >> 4 != 0x0 {
        return None;
    }

    let dest_conn_id_len = buffer.read_u8().ok()? as usize;
    let mut dest_conn_id = vec![0u8; dest_conn_id_len as usize];
    buffer.read(&mut dest_conn_id).ok()?;

    let src_conn_id_len = buffer.read_u8().ok()?;
    let mut src_conn_id = vec![0u8; src_conn_id_len as usize];
    buffer.read(&mut src_conn_id).ok()?;

    let token_len = decode_varint(&mut buffer)?;

    let mut token = vec![0u8; token_len as usize];
    buffer.read(&mut token).ok()?;

    let packet_len = decode_varint(&mut buffer)?;
    let hdr_len = buffer.position() as usize;

    let mut orig_pn_bytes = vec![0u8; 4];
    buffer.read(&mut orig_pn_bytes).ok()?;

    let key_len = 16;
    let keys = TLS13_AES_128_GCM_SHA256.tls13().unwrap()
        .quic_suite().unwrap()
        .keys(&dest_conn_id, rustls::Side::Client, match version_number {
            VERSION_DRAFT29 => rustls::quic::Version::V1Draft,
            VERSION1 => rustls::quic::Version::V1,
            _ => return None,
        });

    let mut first_byte = remaining[0];
    let mut pn = orig_pn_bytes.clone();
    match keys.local.header.decrypt_in_place(
        &remaining[hdr_len + 4..hdr_len + 4 + key_len], 
        &mut first_byte, &mut pn) {
        Err(_) => {
            return None;
        },
        _ => {}
    }

    let packet_number_len = 1 + (first_byte & 0b11) as usize;
    if packet_number_len != 1 {
        return None;
    }

    let packet_number = pn[0];
    if packet_number != 0 && packet_number != 1 {
        return None;
    }

    let mut header = remaining[..hdr_len + packet_number_len].to_vec();
    header[0] = first_byte;
    header[hdr_len + packet_number_len - 1] = pn[0];

    let mut payload = remaining[hdr_len + packet_number_len..(packet_len as usize + hdr_len)].to_vec();

    keys.local.packet.decrypt_in_place(
        packet_number as u64,
        &header, 
        &mut payload).ok()?;

    let mut payload = std::io::Cursor::new(payload);
    let frame_type = payload.read_u8().ok()?;
    if frame_type != 0x06 {
        // The first packet sent by a client always includes a CRYPTO 
        // frame that contains the start or all of the first 
        // cryptographic handshake message. The first CRYPTO frame 
        // sent always begins at an offset of 0;
        return None;
    }

    let offset = decode_varint(&mut payload)?;
    if offset != 0 {
        return None;
    }

    let length = decode_varint(&mut payload)?;
    if length > payload.remaining() as u64 {
        return None;
    }

    let mut crypto_data = vec![0u8; length as usize];
    payload.read_exact(&mut crypto_data).ok()?;

    return parse_handshake_host(&crypto_data);
}

fn parse_handshake_host(remaining: &[u8]) -> Option<String> {
    if let Ok((_remaining, msg)) = tls_parser::parse_tls_message_handshake(remaining) {
        if let Some(host) = super::tls_parse::parse_tls_msg(&msg) {
            return Some(host);
        }
    }

    return None;
}
