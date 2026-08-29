//! DNS query sniffer.
//!
//! Extracts the queried domain (QNAME of the first question) from DNS
//! messages so that intercepted DNS traffic (UDP/TCP port 53) can be
//! routed with the regular domain rules (DOMAIN/DOMAIN-SUFFIX/GEOSITE).
//!
//! Only standard queries (QR=0, OPCODE=0) are accepted; responses and
//! other message types are ignored to avoid false positives.
const DNS_HEADER_LEN: usize = 12;
/// Safety limit for compression pointer jumps inside a QNAME.
const MAX_POINTER_JUMPS: usize = 8;

/// Parse a DNS message carried over UDP (raw DNS payload).
pub fn parse_host(packet: &[u8]) -> Option<String> {
    parse_dns_query(packet)
}

/// Parse a DNS message carried over TCP (2-byte big-endian length prefix).
pub fn parse_host_tcp(packet: &[u8]) -> Option<String> {
    if packet.len() < 2 {
        return None;
    }
    let msg_len = u16::from_be_bytes([packet[0], packet[1]]) as usize;
    if msg_len == 0 || msg_len > packet.len() - 2 {
        return None;
    }
    parse_dns_query(&packet[2..2 + msg_len])
}

fn parse_dns_query(msg: &[u8]) -> Option<String> {
    if msg.len() < DNS_HEADER_LEN {
        return None;
    }

    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0f;
    if is_response || opcode != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }

    let (name, _) = parse_name(msg, DNS_HEADER_LEN, 0)?;
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Parse a (possibly compressed) domain name starting at `offset`.
/// Returns the lower-cased domain and the offset right after the name
/// (following the initial encoding, not the pointer target).
fn parse_name(msg: &[u8], offset: usize, jumps: usize) -> Option<(String, usize)> {
    if jumps > MAX_POINTER_JUMPS {
        return None;
    }

    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut next_offset = None;

    loop {
        let len = *msg.get(pos)? as usize;
        match len & 0xc0 {
            0xc0 => {
                // Compression pointer
                let hi = *msg.get(pos + 1)? as usize;
                let ptr = ((len & 0x3f) << 8) | hi;
                if ptr >= msg.len() {
                    return None;
                }
                if next_offset.is_none() {
                    next_offset = Some(pos + 2);
                }
                let (target, _) = parse_name(msg, ptr, jumps + 1)?;
                if !target.is_empty() {
                    labels.push(target);
                }
                break;
            }
            0x00 => {
                if len == 0 {
                    if next_offset.is_none() {
                        next_offset = Some(pos + 1);
                    }
                    break;
                }
                let label = msg.get(pos + 1..pos + 1 + len)?;
                if !label
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return None;
                }
                labels.push(std::str::from_utf8(label).ok()?.to_lowercase());
                pos += 1 + len;
            }
            _ => return None,
        }
    }

    Some((labels.join("."), next_offset?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a standard DNS query for the given domain (A record, IN class).
    fn build_query(domain: &str) -> Vec<u8> {
        let mut msg = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: standard query, RD
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        for label in domain.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0); // root label
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        msg
    }

    #[test]
    fn parse_udp_query() {
        let msg = build_query("www.Example.com");
        assert_eq!(parse_host(&msg), Some("www.example.com".to_string()));
    }

    #[test]
    fn parse_tcp_query() {
        let msg = build_query("a.b.cn");
        let mut tcp = (msg.len() as u16).to_be_bytes().to_vec();
        tcp.extend_from_slice(&msg);
        assert_eq!(parse_host_tcp(&tcp), Some("a.b.cn".to_string()));
    }

    #[test]
    fn reject_response() {
        let mut msg = build_query("www.example.com");
        msg[2] = 0x81; // QR=1
        assert_eq!(parse_host(&msg), None);
    }

    #[test]
    fn reject_garbage() {
        assert_eq!(parse_host(b""), None);
        assert_eq!(parse_host(&[0u8; 5]), None);
        assert_eq!(parse_host_tcp(&[0x00]), None);
        assert_eq!(parse_host_tcp(&[0xff, 0xff, 0x00]), None);
    }

    #[test]
    fn reject_empty_question() {
        let mut msg = build_query("www.example.com");
        msg[5] = 0x00; // QDCOUNT = 0
        assert_eq!(parse_host(&msg), None);
    }

    #[test]
    fn parse_compressed_qname() {
        // A compression pointer inside the question section is unusual but
        // legal; make sure we handle pointers defensively.
        let mut msg = build_query("www.example.com");
        msg[5] = 0x02; // QDCOUNT = 2
        // second question reuses the first QNAME via a pointer to offset 12
        msg.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(parse_host(&msg), Some("www.example.com".to_string()));
    }

    #[test]
    fn reject_invalid_labels() {
        let mut msg = build_query("www.example.com");
        msg[15] = 0x01; // invalid label byte
        assert_eq!(parse_host(&msg), None);
    }
}
