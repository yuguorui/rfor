#[cfg(target_os = "freebsd")]
mod ipfw_freebsd;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod tproxy_unix;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub use tproxy_unix::*;

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
mod tproxy_others;

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub use tproxy_others::*;
