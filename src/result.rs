use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
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

/// Result of host scan
#[derive(Clone, Debug)]
pub struct HostScanResult {
    /// Hosts that responded
    pub hosts: Vec<HostInfo>,
    /// Time taken to scan
    pub scan_time: Duration,
    /// Status of the scan task
    pub scan_status: ScanStatus,
}

impl HostScanResult {
    pub fn new() -> HostScanResult {
        HostScanResult {
            hosts: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Ready,
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
}

/// Result of port scan
#[derive(Clone, Debug)]
pub struct PortScanResult {
    /// List of scanned HostInfo and their respective port scan results.
    pub results: Vec<HostInfo>,
    /// Time taken to scan
    pub scan_time: Duration,
    /// Status of the scan task
    pub scan_status: ScanStatus,
}

impl PortScanResult {
    pub fn new() -> PortScanResult {
        PortScanResult {
            results: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Ready,
        }
    }
    /// Get open ports of the specified IP address from the scan results
    pub fn get_open_ports(&self, ip_addr: IpAddr) -> Vec<u16> {
        let mut open_ports: Vec<u16> = vec![];
        self.results.iter().for_each(|host_info| {
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

#[derive(Clone, Debug)]
pub(crate) struct ScanResult {
    pub host_scan_result: HostScanResult,
    pub port_scan_result: PortScanResult,
    pub ip_set: HashSet<IpAddr>,
    pub socket_set: HashSet<SocketAddr>,
}

impl ScanResult {
    pub fn new() -> ScanResult {
        ScanResult {
            host_scan_result: HostScanResult::new(),
            port_scan_result: PortScanResult::new(),
            ip_set: HashSet::new(),
            socket_set: HashSet::new(),
        }
    }
}
