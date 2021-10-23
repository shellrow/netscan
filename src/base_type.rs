use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use pnet::datalink::MacAddr;
use crate::define::DEFAULT_SRC_PORT;

/// Scan task status for each scanner 
#[derive(Clone, Copy, Debug)]
pub enum ScanStatus {
    Ready,
    Done,
    Timeout,
    Error,
}

/// Type of port scan 
/// 
/// Supports TCP SYN Scan, TCP CONNECT Scan
#[derive(Clone, Copy, Debug)]
pub enum PortScanType {
    SynScan,
    ConnectScan,
}

/// Status of port that responded 
#[derive(Clone, Copy, Debug)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

/// Information on each port that responded
#[derive(Clone, Copy, Debug)]
pub struct PortInfo {
    pub port: u16,
    pub status: PortStatus,
}

/// Result of HostScanner::run_scan  
#[derive(Clone, Debug)]
pub struct HostScanResult {
    /// List of up host  
    pub up_hosts: Vec<IpAddr>,
    /// Time from start to end of scan  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

impl HostScanResult {
    pub fn new() -> HostScanResult {
        HostScanResult{
            up_hosts: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Ready,
        }
    }
}

/// Result of PortScanner::run_scan  
#[derive(Clone, Debug)]
pub struct PortScanResult {
    /// List of open port  
    pub ports: Vec<PortInfo>,
    /// Time from start to end of scan  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

impl PortScanResult {
    pub fn new() -> PortScanResult {
        PortScanResult{
            ports: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Ready,
        }
    }
}

#[allow(dead_code)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

pub struct ScanSetting {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_ips: Vec<IpAddr>,
    pub src_port: u16,
    pub dst_ports: Vec<u16>,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub protocol: Protocol,
    pub scan_type: Option<PortScanType>,
}

impl ScanSetting {
    #[allow(dead_code)]
    pub fn new() -> ScanSetting {
        ScanSetting {
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ips: vec![],
            src_port: DEFAULT_SRC_PORT,
            dst_ports: vec![],
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            protocol: Protocol::Tcp,
            scan_type: Some(PortScanType::SynScan),
        }
    }
}

pub struct ScanResult {
    pub hosts: Vec<IpAddr>,
    pub ports: Vec<PortInfo>,
}

impl ScanResult {
    pub fn new() -> ScanResult {
        ScanResult {
            hosts: vec![],
            ports: vec![],
        }
    }
}
