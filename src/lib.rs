#[macro_use]
extern crate log;

mod base_type;
mod define;
mod interface;
mod packet;
mod scanner;

#[cfg(target_family="unix")]
mod async_scanner;

pub use base_type::{PortScanType, ScanStatus};
pub use base_type::{PortScanResult, HostScanResult};
pub use base_type::{PortStatus, PortInfo};
pub use scanner::{PortScanner, HostScanner};

#[cfg(target_family="unix")]
pub use async_scanner::{AsyncPortScanner, AsyncHostScanner};
