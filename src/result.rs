use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::collections::{HashSet, HashMap};

/// Status of scan task 
#[derive(Clone, Debug)]
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
    pub ip_addr: IpAddr,
    pub ttl: u8,
}

/// Information about the scanned port 
#[derive(Clone, Copy, Debug)]
pub struct PortInfo {
    pub port: u16,
    pub status: PortStatus,
}

/// Result of host scan 
#[derive(Clone, Debug)]
pub struct HostScanResult {
    pub hosts: Vec<HostInfo>,
    pub scan_time: Duration,
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
    pub result_map: HashMap<IpAddr, Vec<PortInfo>>,
    pub scan_time: Duration,
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

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct ScanResult {
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
