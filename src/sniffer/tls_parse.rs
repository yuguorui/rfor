use tls_parser::{parse_tls_extension, TlsExtension, TlsMessage, TlsMessageHandshake};

pub fn parse_host(remaining: &[u8]) -> Option<String> {
    if let Ok((_remaining, tls)) = tls_parser::parse_tls_plaintext(remaining) {
        for msg in tls.msg {
            if let Some(host) = parse_tls_msg(&msg) {
                return Some(host);
            }
        }
    }

    return None;
}

pub fn parse_tls_msg(msg: &TlsMessage) -> Option<String> {
    match msg {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
            if let Some(mut remaining) = ch.ext {
                while let Ok((remaining2, ext)) = parse_tls_extension(remaining) {
                    remaining = remaining2;
                    if let TlsExtension::SNI(sni) = ext {
                        for s in sni {
                            return std::str::from_utf8(s.1).ok().map(|s| s.to_string());
                        }
                    }
                }
            }
        }
        _ => {}
    }

    None
}