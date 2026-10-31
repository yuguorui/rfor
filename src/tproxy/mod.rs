#[cfg(target_os = "freebsd")]
mod ipfw_freebsd;

#[cfg(target_os = "openbsd")]
pub(crate) mod pf_openbsd;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
mod tproxy_unix;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub use tproxy_unix::*;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
mod tproxy_others;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
pub use tproxy_others::*;
