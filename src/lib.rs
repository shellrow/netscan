#[macro_use]
extern crate log;

mod base_type;
mod define;
mod interface;
mod packet;
mod scanner;
mod async_scanner;

pub use base_type::{PortScanType, ScanStatus};
pub use base_type::{PortScanResult, HostScanResult};
pub use scanner::{PortScanner, HostScanner};

#[cfg(not(target_os="windows"))]
pub use async_scanner::{AsyncPortScanner, AsyncHostScanner};

