#![allow(dead_code)]

use boomphf::Mphf;
use ipnet::{IpNet, Ipv6Net, PrefixLenError};
use std::fmt::Debug;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;
use tokio::{
    io::Interest,
    net::tcp::{ReadHalf, WriteHalf},
};

use anyhow::Result;

use crate::rules::RouteContext;
use crate::SETTINGS;

use std::io;
use std::ops::Drop;
use std::os::unix::io::AsRawFd;

use anyhow::anyhow;

const PIPE_BUF_SIZE: usize = 512 * 1024;

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

/// A HashSet data structure where the mapping between keys is encoded in a Mphf. This lets us store the keys in dense
/// arrays, with ~3 bits/item overhead in the Mphf.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BoomHashSet<K: Hash> {
    mphf: Mphf<K>,
    keys: Vec<K>,
}

pub async fn transfer_tcp(in_sock: &mut TcpStream, rt_context: RouteContext) -> Result<()> {
    let mut out_sock = match SETTINGS
        .read()
        .await
        .outbounds
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

    // let _ = tokio::io::copy_bidirectional(in_sock, &mut out_sock).await;
    let _ = _copy_bidirectional(in_sock, &mut out_sock).await;

    Ok(())
}

/*
 * _copy_bidirectional is a zero-copy implementation of io::copy_bidirectional.
 *
 * It uses a pipe to transfer data between the two sockets. The original implementation comes from
 * [midori](https://github.com/zephyrchien/midori/blob/master/src/io/zero_copy.rs),
 * but removed the unsafe code.
 */
async fn _copy_bidirectional(inbound: &mut TcpStream, outbound: &mut TcpStream) -> Result<()> {
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

struct Pipe(i32, i32);

impl Drop for Pipe {
    fn drop(&mut self) {
        nix::unistd::close(self.0).unwrap_or(());
        nix::unistd::close(self.1).unwrap_or(());
    }
}

impl Pipe {
    fn create() -> io::Result<Self> {
        match nix::unistd::pipe2(nix::fcntl::OFlag::O_NONBLOCK) {
            Ok((fd1, fd2)) => Ok(Pipe(fd1, fd2)),
            Err(err) => Err(err.into()),
        }
    }
}

use std::convert::TryInto;

pub fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Option<[T; N]> {
    v.try_into().ok()
}

#[inline]
fn splice_n(r: i32, w: i32, n: usize, has_more_data: bool) -> std::io::Result<usize> {
    let flags = nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK
        | if has_more_data {
            nix::fcntl::SpliceFFlags::SPLICE_F_MORE
        } else {
            nix::fcntl::SpliceFFlags::empty()
        };

    match nix::fcntl::splice(r, None, w, None, n, flags) {
        Err(err) => return Err(err.into()),
        Ok(ret) => return Ok(ret),
    }
}

pub async fn zero_copy(r: ReadHalf<'_>, w: WriteHalf<'_>) -> io::Result<()>
where
{
    // create pipe
    let pipe = Pipe::create()?;
    let (rpipe, wpipe) = (pipe.0, pipe.1);
    // rw ref
    let rx = r.as_ref();
    let wx = w.as_ref();
    // rw raw fd
    let rfd = rx.as_raw_fd();
    let wfd = wx.as_raw_fd();

    loop {
        let mut n;

        rx.readable().await?;
        match splice_n(rfd, wpipe, PIPE_BUF_SIZE, false) {
            Ok(ret) => {
                if ret > 0 {
                    n = ret;
                } else {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "zero_copy"));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                let _ = rx.try_io(Interest::READABLE, || {
                    Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""))
                        as std::io::Result<()>
                });
                continue;
            }
            Err(err) => {
                return Err(err);
            }
        }

        while n > 0 {
            wx.writable().await?;
            match splice_n(rpipe, wfd, n, false) {
                Ok(ret) => {
                    n -= ret;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    let _ = wx.try_io(Interest::WRITABLE, || {
                        Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""))
                            as std::io::Result<()>
                    });
                    continue;
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
    }
}

pub fn geteuid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap()
}

pub async fn receive_signal() -> Result<()> {
    use tokio::signal::unix::signal;
    use tokio::signal::unix::SignalKind;
    let mut sighang = signal(SignalKind::hangup())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sighang.recv() => {},
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }

    Err(anyhow!("Recieved signal"))
}
