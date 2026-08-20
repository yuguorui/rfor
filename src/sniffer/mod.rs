mod http_parse;
mod quic_parser;
mod tls_parse;

use std::io;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};

const TCP_SNIFF_MAX_BYTES: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum HostParseResult {
    Found(String),
    NeedMore,
    NotProtocol,
}

pub struct SniffedTcp {
    pub host: Option<String>,
    pub data: Vec<u8>,
}

// Re-export QUIC aggregator for cross-packet SNI parsing
#[cfg(target_os = "linux")]
pub use quic_parser::{QuicParseResult, QuicSniAggregator};

pub fn parse_tcp_host(data: &[u8]) -> HostParseResult {
    let http_result = http_parse::parse_host_result(data);
    if matches!(http_result, HostParseResult::Found(_)) {
        return http_result;
    }

    let tls_result = tls_parse::parse_host_result(data);
    if matches!(tls_result, HostParseResult::Found(_)) {
        return tls_result;
    }

    if matches!(http_result, HostParseResult::NeedMore)
        || matches!(tls_result, HostParseResult::NeedMore)
    {
        HostParseResult::NeedMore
    } else {
        HostParseResult::NotProtocol
    }
}

pub async fn sniff_tcp(
    stream: &mut TcpStream,
    timeout: Duration,
) -> io::Result<Option<SniffedTcp>> {
    sniff_tcp_with_limits(stream, timeout, TCP_SNIFF_MAX_BYTES).await
}

async fn sniff_tcp_with_limits(
    stream: &mut TcpStream,
    timeout: Duration,
    max_bytes: usize,
) -> io::Result<Option<SniffedTcp>> {
    let deadline = Instant::now() + timeout;
    let mut data = Vec::with_capacity(max_bytes.min(4096));
    let mut chunk = [0u8; 4096];

    loop {
        match parse_tcp_host(&data) {
            HostParseResult::Found(host) => {
                return Ok(Some(SniffedTcp {
                    host: Some(host),
                    data,
                }));
            }
            HostParseResult::NotProtocol => {
                return Ok(Some(SniffedTcp { host: None, data }));
            }
            HostParseResult::NeedMore => {}
        }

        if data.len() >= max_bytes {
            return Ok(Some(SniffedTcp { host: None, data }));
        }

        let remaining = max_bytes - data.len();
        let read_len = remaining.min(chunk.len());
        let read_result = timeout_at(deadline, stream.read(&mut chunk[..read_len])).await;

        match read_result {
            Err(_) => return Ok(Some(SniffedTcp { host: None, data })),
            Ok(Ok(0)) if data.is_empty() => return Ok(None),
            Ok(Ok(0)) => return Ok(Some(SniffedTcp { host: None, data })),
            Ok(Ok(size)) => data.extend_from_slice(&chunk[..size]),
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
                ) =>
            {
                return Ok(None);
            }
            Ok(Err(err)) => return Err(err),
        }
    }
}

pub fn parse_host(remaining: &[u8]) -> Option<String> {
    if let Some(host) = http_parse::parse_host(remaining) {
        return Some(host);
    }

    if let Some(host) = tls_parse::parse_host(remaining) {
        return Some(host);
    }

    if let Some(host) = quic_parser::parse_host(remaining) {
        return Some(host);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn connected_streams() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        (client.await.unwrap(), server)
    }

    #[tokio::test]
    async fn reads_and_caches_fragmented_http() {
        let (mut client, mut server) = connected_streams().await;
        let first = b"GET / HTTP/1.1\r\n";
        let second = b"Host: split.example\r\n\r\n";
        client.write_all(first).await.unwrap();

        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            client.write_all(second).await.unwrap();
        });
        let sniffed = sniff_tcp_with_limits(&mut server, Duration::from_secs(1), 1024)
            .await
            .unwrap()
            .unwrap();
        writer.await.unwrap();

        assert_eq!(sniffed.host.as_deref(), Some("split.example"));
        assert_eq!(sniffed.data, [first.as_slice(), second.as_slice()].concat());
    }

    #[tokio::test]
    async fn waits_for_delayed_first_byte() {
        let (mut client, mut server) = connected_streams().await;
        let request = b"GET / HTTP/1.1\r\nHost: delayed.example\r\n\r\n";
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            client.write_all(request).await.unwrap();
        });
        let sniffed = sniff_tcp_with_limits(&mut server, Duration::from_secs(1), 1024)
            .await
            .unwrap()
            .unwrap();
        writer.await.unwrap();

        assert_eq!(sniffed.host.as_deref(), Some("delayed.example"));
        assert_eq!(sniffed.data, request);
    }

    #[tokio::test]
    async fn returns_partial_data_when_deadline_expires() {
        let (mut client, mut server) = connected_streams().await;
        let partial = b"GET / HTTP/1.1\r\nHost: partial";
        client.write_all(partial).await.unwrap();
        let sniffed = sniff_tcp_with_limits(&mut server, Duration::from_millis(20), 1024)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(sniffed.host, None);
        assert_eq!(sniffed.data, partial);
    }

    #[tokio::test]
    async fn leaves_data_arriving_after_deadline_in_socket() {
        let (mut client, mut server) = connected_streams().await;
        let request = b"GET / HTTP/1.1\r\nHost: late.example\r\n\r\n";
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            client.write_all(request).await.unwrap();
        });
        let sniffed = sniff_tcp_with_limits(&mut server, Duration::from_millis(10), 1024)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(sniffed.host, None);
        assert!(sniffed.data.is_empty());
        writer.await.unwrap();
        let mut received = vec![0; request.len()];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(received, request);
    }

    #[tokio::test]
    async fn falls_back_when_deadline_expires() {
        let (_client, mut server) = connected_streams().await;
        let sniffed = sniff_tcp_with_limits(&mut server, Duration::from_millis(20), 1024)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(sniffed.host, None);
        assert!(sniffed.data.is_empty());
    }

    #[tokio::test]
    async fn enforces_buffer_limit() {
        let (mut client, mut server) = connected_streams().await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: too-long.example\r\n\r\n")
            .await
            .unwrap();
        let sniffed = sniff_tcp_with_limits(&mut server, Duration::from_secs(1), 16)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(sniffed.host, None);
        assert_eq!(sniffed.data.len(), 16);
    }

    #[tokio::test]
    async fn returns_none_when_client_closes_without_data() {
        let (client, mut server) = connected_streams().await;
        drop(client);

        assert!(
            sniff_tcp_with_limits(&mut server, Duration::from_secs(1), 1024)
                .await
                .unwrap()
                .is_none()
        );
    }
}
