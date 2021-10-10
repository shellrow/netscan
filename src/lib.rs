#[macro_use]
extern crate log;

mod interface;
mod arp;
mod ethernet;
mod ipv4;
mod tcp;
mod icmp;
mod udp;
mod packet;
mod port;
mod host;
mod scanner;

pub use scanner::shared::{PortScanType, ScanStatus};
pub use scanner::shared::{PortScanResult, HostScanResult};
pub use scanner::blocking::{PortScanner, HostScanner};

#[cfg(not(target_os="windows"))]
pub use scanner::async_sc::{AsyncPortScanner, AsyncHostScanner};

pub use scanner::async_sc2::{AsyncPortScanner2, AsyncHostScanner2};
