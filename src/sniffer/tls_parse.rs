use tls_parser::{
    parse_tls_extension, parse_tls_message_handshake, TlsExtension, TlsMessage, TlsMessageHandshake,
};

use super::HostParseResult;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const TLS_CLIENT_HELLO_TYPE: u8 = 1;

pub fn parse_host(remaining: &[u8]) -> Option<String> {
    match parse_host_result(remaining) {
        HostParseResult::Found(host) => Some(host),
        HostParseResult::NeedMore | HostParseResult::NotProtocol => None,
    }
}

pub fn parse_host_result(remaining: &[u8]) -> HostParseResult {
    if remaining.is_empty() {
        return HostParseResult::NeedMore;
    }
    if remaining[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return HostParseResult::NotProtocol;
    }
    if remaining.len() >= 2 && remaining[1] != 3 {
        return HostParseResult::NotProtocol;
    }

    let mut offset = 0;
    let mut handshake = Vec::new();

    loop {
        if remaining.len() - offset < TLS_RECORD_HEADER_LEN {
            return HostParseResult::NeedMore;
        }
        if remaining[offset] != TLS_HANDSHAKE_CONTENT_TYPE || remaining[offset + 1] != 3 {
            return HostParseResult::NotProtocol;
        }

        let record_len =
            u16::from_be_bytes([remaining[offset + 3], remaining[offset + 4]]) as usize;
        let record_end = offset + TLS_RECORD_HEADER_LEN + record_len;
        if remaining.len() < record_end {
            return HostParseResult::NeedMore;
        }

        handshake.extend_from_slice(&remaining[offset + TLS_RECORD_HEADER_LEN..record_end]);
        if handshake.len() >= 4 {
            if handshake[0] != TLS_CLIENT_HELLO_TYPE {
                return HostParseResult::NotProtocol;
            }
            let handshake_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            let message_len = 4 + handshake_len;
            if handshake.len() >= message_len {
                return match parse_tls_message_handshake(&handshake[..message_len]) {
                    Ok((_remaining, msg)) => parse_tls_msg(&msg)
                        .map(HostParseResult::Found)
                        .unwrap_or(HostParseResult::NotProtocol),
                    Err(_) => HostParseResult::NotProtocol,
                };
            }
        }

        offset = record_end;
        if offset == remaining.len() {
            return HostParseResult::NeedMore;
        }
    }
}

pub fn parse_tls_msg(msg: &TlsMessage) -> Option<String> {
    let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg else {
        return None;
    };

    if let Some(mut remaining) = ch.ext {
        while let Ok((remaining2, ext)) = parse_tls_extension(remaining) {
            remaining = remaining2;
            if let TlsExtension::SNI(sni) = ext {
                return sni
                    .first()
                    .and_then(|entry| std::str::from_utf8(entry.1).ok())
                    .map(str::to_string);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn client_hello(host: &str) -> Vec<u8> {
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        hello
    }

    fn split_record(record: &[u8]) -> Vec<u8> {
        assert_eq!(record[0], TLS_HANDSHAKE_CONTENT_TYPE);
        let payload_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), TLS_RECORD_HEADER_LEN + payload_len);
        let split_at = payload_len / 2;
        let mut split = Vec::with_capacity(record.len() + TLS_RECORD_HEADER_LEN);

        for payload in [
            &record[TLS_RECORD_HEADER_LEN..TLS_RECORD_HEADER_LEN + split_at],
            &record[TLS_RECORD_HEADER_LEN + split_at..],
        ] {
            split.extend_from_slice(&record[..3]);
            split.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            split.extend_from_slice(payload);
        }

        split
    }

    #[test]
    fn parses_fragmented_client_hello() {
        let hello = client_hello("fragmented.example");
        assert_eq!(
            parse_host_result(&hello[..hello.len() - 1]),
            HostParseResult::NeedMore
        );
        assert_eq!(
            parse_host_result(&hello),
            HostParseResult::Found("fragmented.example".to_string())
        );
    }

    #[test]
    fn parses_client_hello_across_records() {
        let hello = client_hello("records.example");
        assert_eq!(
            parse_host_result(&split_record(&hello)),
            HostParseResult::Found("records.example".to_string())
        );
    }
}
