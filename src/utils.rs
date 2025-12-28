#![allow(dead_code)]

use ipnet::{IpNet, Ipv6Net, PrefixLenError};
use tokio::io::AsyncWriteExt;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

use anyhow::Result;

use crate::rules::RouteContext;
use crate::get_settings;

use std::io;

use anyhow::anyhow;
use tracing;

use std::convert::TryInto;

pub fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Option<[T; N]> {
    v.try_into().ok()
}

pub trait ToV6Net {
    fn to_ipv6_net(&self) -> Result<Ipv6Net, PrefixLenError>;
}

impl ToV6Net for IpAddr {
    fn to_ipv6_net(&self) -> Result<Ipv6Net, PrefixLenError> {
        match self {
            IpAddr::V4(v4) => Ipv6Net::new(v4.to_ipv6_mapped(), 128),
            IpAddr::V6(v6) => Ipv6Net::new(v6.to_owned(), 128),
        }
    }
}

impl ToV6Net for IpNet {
    fn to_ipv6_net(&self) -> Result<Ipv6Net, PrefixLenError> {
        match self {
            IpNet::V4(v4) => Ipv6Net::new(v4.addr().to_ipv6_mapped(), 128 - 32 + v4.prefix_len()),
            IpNet::V6(v6) => Ok(v6.to_owned()),
        }
    }
}

pub trait ToV6SockAddr {
    fn to_ipv6_sockaddr(&self) -> SocketAddr;
}

impl ToV6SockAddr for SocketAddr {
    fn to_ipv6_sockaddr(&self) -> SocketAddr {
        match self {
            SocketAddr::V4(v4) => {
                SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            e @ SocketAddr::V6(_) => *e,
        }
    }
}

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.contains(" ") || !domain.contains(".") {
        return false;
    }
    return true;
}

pub fn to_io_err(sock_err: fast_socks5::SocksError) -> std::io::Error {
    match sock_err {
        fast_socks5::SocksError::Io(io_err) => {
            return io_err;
        }
        other_err => {
            return std::io::Error::new(std::io::ErrorKind::Other, other_err.to_string());
        }
    };
}

pub async fn transfer_tcp(in_sock: &mut TcpStream, rt_context: RouteContext) -> Result<()> {
    let mut out_sock = match get_settings()
        .read()
        .await
        .routetable
        .get_tcp_sock(&rt_context)
        .await
    {
        Ok(sock) => sock,
        Err(err) => match err.kind() {
            std::io::ErrorKind::PermissionDenied => {
                return Ok(());
            }
            _ => {
                return Err(err.into());
            }
        },
    };

    // Use zero-copy splice on Linux, fallback to tokio copy on other platforms
    #[cfg(target_os = "linux")]
    let _ = _copy_bidirectional(in_sock, &mut out_sock).await;

    #[cfg(not(target_os = "linux"))]
    let _ = tokio::io::copy_bidirectional(in_sock, &mut out_sock).await;

    Ok(())
}

/*
 * _copy_bidirectional is a zero-copy implementation of io::copy_bidirectional.
 *
 * It uses a pipe to transfer data between the two sockets. The original implementation comes from
 * [midori](https://github.com/zephyrchien/midori/blob/master/src/io/zero_copy.rs),
 * but removed the unsafe code.
 *
 * This is Linux-specific due to the use of splice() system call.
 */
#[cfg(target_os = "linux")]
async fn _copy_bidirectional(inbound: &mut TcpStream, outbound: &mut TcpStream) -> Result<()> {
    use tokio::io::Interest;
    use tokio::net::tcp::{ReadHalf, WriteHalf};
    use std::os::unix::io::AsRawFd;
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

    const PIPE_BUF_SIZE: usize = 512 * 1024;

    struct Pipe(OwnedFd, OwnedFd);

    impl Pipe {
        fn create() -> io::Result<Self> {
            match nix::unistd::pipe2(nix::fcntl::OFlag::O_NONBLOCK) {
                Ok((fd1, fd2)) => Ok(Pipe(fd1, fd2)),
                Err(err) => Err(err.into()),
            }
        }
    }

    #[inline]
    fn splice_n<Fd1: AsFd, Fd2: AsFd>(r: Fd1, w: Fd2, n: usize, has_more_data: bool) -> std::io::Result<usize> {
        let flags = nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK
            | if has_more_data {
                nix::fcntl::SpliceFFlags::SPLICE_F_MORE
            } else {
                nix::fcntl::SpliceFFlags::empty()
            };

        match nix::fcntl::splice(r, None, w, None, n, flags) {
            Err(err) => Err(err.into()),
            Ok(ret) => Ok(ret),
        }
    }

    async fn zero_copy(r: ReadHalf<'_>, mut w: WriteHalf<'_>) -> io::Result<usize> {
        // create pipe
        let pipe = Pipe::create()?;
        let (ref rpipe, ref wpipe) = (pipe.0, pipe.1);
        // rw ref
        let rx = r.as_ref();
        let wx = w.as_ref();
        // rw raw fd
        let rfd = rx.as_raw_fd();
        let wfd = wx.as_raw_fd();

        let mut bytes = 0;

        loop {
            // SAFETY: The raw fd is valid for the duration of the async_io closure
            // since rx is borrowed for the entire call
            let mut n = rx.async_io(Interest::READABLE, || {
                let borrowed_rfd = unsafe { BorrowedFd::borrow_raw(rfd) };
                splice_n(borrowed_rfd, wpipe, PIPE_BUF_SIZE, false)
            }).await?;

            if n == 0 {
                w.shutdown().await?;
                return Ok(bytes);
            }

            bytes += n;

            while n > 0 {
                // SAFETY: The raw fd is valid for the duration of the async_io closure
                // since wx is borrowed for the entire call
                n -= wx.async_io(Interest::WRITABLE, || {
                    let borrowed_wfd = unsafe { BorrowedFd::borrow_raw(wfd) };
                    splice_n(rpipe, borrowed_wfd, n, false)
                }).await?;
            }
        }
    }

    let (ri, wi) = inbound.split();
    let (ro, wo) = outbound.split();

    let client_to_server = async {
        zero_copy(ri, wo).await?;
        Ok::<(), std::io::Error>(())
    };

    let server_to_client = async {
        zero_copy(ro, wi).await?;
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::try_join!(client_to_server, server_to_client);

    Ok(())
}

#[cfg(unix)]
pub fn geteuid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

#[cfg(not(unix))]
pub fn geteuid() -> u32 {
    // On non-Unix platforms, return 0 (simulating root) as there's no euid concept
    0
}

#[cfg(unix)]
pub async fn receive_signal() -> Result<()> {
    use tokio::signal::unix::signal;
    use tokio::signal::unix::SignalKind;

    let mut sighang = signal(SignalKind::hangup())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    let signal_name = tokio::select! {
        _ = sighang.recv() => "SIGHUP",
        _ = sigint.recv() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
    };

    tracing::error!("Received signal: {}", signal_name);

    Err(anyhow!("Received signal: {}", signal_name))
}

#[cfg(not(unix))]
pub async fn receive_signal() -> Result<()> {
    // On non-Unix platforms, just wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    tracing::error!("Received signal: CTRL_C");
    Err(anyhow!("Received signal: CTRL_C"))
}

pub fn to_target_addr(target_addr: fast_socks5::util::target_addr::TargetAddr) -> crate::rules::TargetAddr {
    match target_addr {
        fast_socks5::util::target_addr::TargetAddr::Ip(sock_addr) => crate::rules::TargetAddr::Ip(sock_addr),
        fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => crate::rules::TargetAddr::Domain(domain, port, None),
    }
}

pub async fn rfor_bind_addr() -> String {
    match crate::get_settings().read().await.disable_ipv6 {
        false => "[::]:0".to_owned(),
        true => "0.0.0.0:0".to_owned(),
    }
}