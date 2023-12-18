use crate::pcap::PacketFrame;
use std::net::IpAddr;
use std::time::Duration;

use crate::host::{HostInfo, PortStatus};

/// Status of scan task
#[derive(Clone, Debug, PartialEq)]
pub enum ScanStatus {
    Ready,
    Done,
    Timeout,
    Error,
}

/// Result of scan
#[derive(Clone, Debug)]
pub struct ScanResult {
    /// List of scanned HostInfo and their respective PortInfo
    pub hosts: Vec<HostInfo>,
    /// Time taken to scan
    pub scan_time: Duration,
    /// Status of the scan task
    pub scan_status: ScanStatus,
    /// Captured packet fingerprints
    pub fingerprints: Vec<PacketFrame>,
}

impl ScanResult {
    pub fn new() -> ScanResult {
        ScanResult {
            hosts: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Ready,
            fingerprints: vec![],
        }
    }
    /// Returns IP addresses from the scan result
    pub fn get_hosts(&self) -> Vec<IpAddr> {
        let mut hosts: Vec<IpAddr> = vec![];
        for host in self.hosts.clone() {
            hosts.push(host.ip_addr);
        }
        hosts
    }
    /// Get open ports of the specified IP address from the scan results
    pub fn get_open_ports(&self, ip_addr: IpAddr) -> Vec<u16> {
        let mut open_ports: Vec<u16> = vec![];
        self.hosts.iter().for_each(|host_info| {
            if host_info.ip_addr == ip_addr {
                host_info
                    .ports
                    .iter()
                    .for_each(|port_info| match port_info.status {
                        PortStatus::Open => {
                            open_ports.push(port_info.port);
                        }
                        _ => {}
                    });
            }
        });
        open_ports
    }
}
