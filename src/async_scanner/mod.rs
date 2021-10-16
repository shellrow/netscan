#[cfg(not(target_os="windows"))]
pub mod unix;

#[cfg(not(target_os="windows"))]
pub mod port_scan;
#[cfg(not(target_os="windows"))]
pub mod host_scan;
