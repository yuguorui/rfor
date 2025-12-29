#[cfg(target_os = "linux")]
mod tproxy_linux;

#[cfg(target_os = "linux")]
pub use tproxy_linux::*;

#[cfg(not(target_os = "linux"))]
mod tproxy_others;

#[cfg(not(target_os = "linux"))]
pub use tproxy_others::*;
