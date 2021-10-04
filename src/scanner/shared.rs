use std::time::Duration;
use crate::status::ScanStatus;

/// Type of port scan 
/// 
/// Supports SynScan, ConnectScan
#[derive(Clone, Copy)]
pub enum PortScanType {
    SynScan,
    ConnectScan,
}

/// Result of HostScanner::run_scan  
#[derive(Clone)]
pub struct HostScanResult {
    /// List of up host  
    pub up_hosts: Vec<String>,
    /// Time from start to end of scan  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

/// Result of PortScanner::run_scan  
#[derive(Clone)]
pub struct PortScanResult {
    /// List of open port  
    pub open_ports: Vec<u16>,
    /// Time from start to end of scan  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}
