use anyhow::Result;
use socket2::SockRef;

pub async fn handle_intercept_sock(_sock: &tokio::net::TcpSocket) -> tokio::io::Result<()> {
    Ok(())
}

pub fn tproxy_bind_src(_sock: SockRef, _src_sock: std::net::SocketAddr) -> tokio::io::Result<()> {
    Ok(())
}

pub async fn tproxy_worker() -> Result<()> {
    Ok(())
}
