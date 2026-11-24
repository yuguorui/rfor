#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "macos"
))]
mod common;

#[cfg(target_os = "freebsd")]
mod ipfw_freebsd;

#[cfg(target_os = "openbsd")]
pub(crate) mod pf_openbsd;

#[cfg(target_os = "macos")]
pub(crate) mod utun_macos;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
mod tproxy_unix;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub use tproxy_unix::*;

#[cfg(target_os = "macos")]
mod tproxy_macos;

#[cfg(target_os = "macos")]
pub use tproxy_macos::*;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "macos"
)))]
mod tproxy_others;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "macos"
)))]
pub use tproxy_others::*;
