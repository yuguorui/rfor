mod http_parse;
mod tls_parse;

pub fn parse_host(remaining: &[u8]) -> Option<String> {
    if let Some(host) = http_parse::parse_host(remaining) {
        return Some(host);
    }

    if let Some(host) = tls_parse::parse_host(remaining) {
        return Some(host);
    }
    None
}
