use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::collections::{HashSet, HashMap};

/// Status of scan task 
#[derive(Clone, Debug, PartialEq)]
pub enum ScanStatus {
    Ready,
    Done,
    Timeout,
    Error,
}

/// Status of the scanned port 
#[derive(Clone, Copy, Debug)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

/// Information about the scanned host 
#[derive(Clone, Copy, Debug)]
pub struct HostInfo {
    /// IP address of the host
    pub ip_addr: IpAddr,
    /// IP Time to Live (Hop Limit)
    pub ttl: u8,
}

/// Information about the scanned port 
#[derive(Clone, Copy, Debug)]
pub struct PortInfo {
    /// Port number
    pub port: u16,
    /// Port status
    pub status: PortStatus,
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
        HostScanResult{
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
    /// HashMap of scanned IP addresses and their respective port scan results.
    pub result_map: HashMap<IpAddr, Vec<PortInfo>>,
    /// Time taken to scan
    pub scan_time: Duration,
    /// Status of the scan task
    pub scan_status: ScanStatus,
}

impl PortScanResult {
    pub fn new() -> PortScanResult {
        PortScanResult{
            result_map: HashMap::new(),
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Ready,
        }
    }
    /// Get open ports of the specified IP address from the scan results
    pub fn get_open_ports(&self, ip_addr: IpAddr) -> Vec<u16> {
        let mut open_ports: Vec<u16> = vec![];
        if let Some(ports) = self.result_map.get(&ip_addr) {
            for port_info in ports {
                match port_info.status {
                    PortStatus::Open => {
                        open_ports.push(port_info.port);
                    },
                    _ => {},
                }
            }
        }
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
