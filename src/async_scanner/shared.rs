use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use crate::base_type::{PortScanType, HostScanResult, PortScanResult};
use crate::async_scanner::{scan_ports, scan_hosts};
use crate::define::DEFAULT_SRC_PORT;

/// Structure for async host scan with various options.   
/// 
/// Currently only Unix-Like OS is supported.
/// 
/// Should be constructed using AsyncHostScanner::new 
#[derive(Clone, Debug)]
pub struct AsyncHostScanner {
    /// Source IP Address  
    pub src_ip: IpAddr,
    /// Destination IP Addresses 
    pub dst_ips: Vec<IpAddr>,
    /// Timeout setting of host scan  
    pub timeout: Duration,
    /// Timeout setting of host scan  
    pub wait_time: Duration,
    /// Result of host scan  
    pub scan_result: HostScanResult,
}

impl AsyncHostScanner {
    pub fn new(src_ip: IpAddr) -> Result<AsyncHostScanner, String> {
        Ok(
            AsyncHostScanner {
                src_ip: src_ip,
                dst_ips: vec![],
                timeout: Duration::from_millis(30000),
                wait_time: Duration::from_millis(100),
                scan_result: HostScanResult::new(),
            }
        )
    }
    /// Set source IP address
    pub fn set_src_ip(&mut self, ip_addr: IpAddr) {
        self.src_ip = ip_addr;
    }
    /// Add destination host to list
    pub fn add_dst_ip(&mut self, ip_addr: IpAddr) {
        self.dst_ips.push(ip_addr);
    }
    /// Set the destination host list 
    /// (Replace the entire destination list) 
    pub fn set_dst_ips(&mut self, ips: Vec<IpAddr>) {
        self.dst_ips = ips;
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    /// Set scan wait time  
    pub fn set_wait_time(&mut self, wait_time: Duration) {
        self.wait_time = wait_time;
    }
    /// Set scan result 
    pub fn set_scan_result(&mut self, scan_result: HostScanResult) {
        self.scan_result = scan_result;
    }
    /// Get source IP address
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    /// Get destination hosts
    pub fn get_dst_ips(&self) -> Vec<IpAddr> {
        self.dst_ips.clone()
    }
    /// Get timeout 
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    /// Get wait time
    pub fn get_wait_time(&self) -> Duration {
        self.wait_time
    }
    /// Get scan result
    pub fn get_scan_result(&self) -> HostScanResult {
        self.scan_result.clone()
    }
    /// Run scan with current settings 
    /// 
    /// Results are stored in AsyncHostScanner::scan_result
    pub async fn run_scan(&mut self) {
        let start_time = Instant::now();
        let (up_hosts, status) = scan_hosts(self.clone()).await;
        let scan_time = Instant::now().duration_since(start_time);
        self.scan_result.up_hosts = up_hosts;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = scan_time;
    }
}

/// Structure for async port scan with various options.   
/// 
/// Currently only Unix-Like OS is supported.
/// 
/// Should be constructed using AsyncPortScanner::new 
#[derive(Clone, Debug)]
pub struct AsyncPortScanner {
    /// Source IP Address  
    pub src_ip: IpAddr,
    /// Destination IP Address  
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination ports
    pub dst_ports: Vec<u16>,
    /// Type of port scan. Default is PortScanType::SynScan  
    pub scan_type: PortScanType,
    /// Timeout setting of port scan   
    pub timeout: Duration,
    /// Wait time after send task is finished
    pub wait_time: Duration,
    /// Packet send rate
    pub send_rate: Duration,
    /// Result of port scan  
    pub scan_result: PortScanResult,
}

impl AsyncPortScanner {
    /// Construct new AsyncPortScanner 
    pub fn new(src_ip: IpAddr) -> Result<AsyncPortScanner, String> {
        Ok(
            AsyncPortScanner {
                src_ip: src_ip,
                dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                src_port: DEFAULT_SRC_PORT,
                dst_ports: vec![],
                scan_type: PortScanType::SynScan,
                timeout: Duration::from_millis(30000),
                wait_time: Duration::from_millis(100),
                send_rate: Duration::from_millis(30000),
                scan_result: PortScanResult::new(),
            }
        )
    }
    /// Set source IP address  
    pub fn set_src_ip(&mut self, ip_addr: IpAddr) {
        self.src_ip = ip_addr;
    }
    /// Set destination IP address 
    pub fn set_dst_ip(&mut self, ip_addr: IpAddr) {
        self.dst_ip = ip_addr;
    }
    /// Set source port number 
    pub fn set_src_port(&mut self, port: u16) {
        self.src_port = port;
    }
    /// Add destination port 
    pub fn add_dst_port(&mut self, port: u16) {
        self.dst_ports.push(port);
    }
    /// Set range of destination ports (by start and end)
    pub fn set_dst_port_range(&mut self, start_port: u16, end_port: u16) {
        for i in start_port..end_port + 1 {
            self.add_dst_port(i);
        }
    }
    /// Set the destination port list 
    /// (Replace the entire destination list) 
    pub fn set_dst_ports(&mut self, ports: Vec<u16>) {
        self.dst_ports = ports;
    }
    /// Set PortScanType. Default is PortScanType::SynScan
    pub fn set_scan_type(&mut self, scan_type: PortScanType) {
        self.scan_type = scan_type;
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    /// Set scan wait-time  
    pub fn set_wait_time(&mut self, wait_time: Duration) {
        self.wait_time = wait_time;
    }
    /// Set packet send rate
    pub fn set_send_rate(&mut self, send_rate: Duration) {
        self.send_rate = send_rate;
    }
    /// Set scan result
    pub fn set_scan_result(&mut self, scan_result: PortScanResult) {
        self.scan_result = scan_result;
    }
    /// Get source ip address
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    /// Get destination ip address
    pub fn get_dst_ip(&self) -> IpAddr {
        self.dst_ip
    }
    /// Get source port
    pub fn get_src_port(&self) -> u16 {
        self.src_port
    }
    /// Get destination ports
    pub fn get_dst_ports(&self) -> Vec<u16> {
        self.dst_ports.clone()
    }
    /// Get PortScanType
    pub fn get_scan_type(&self) -> PortScanType {
        self.scan_type
    }
    /// Get timeout
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    /// Get wait-time
    pub fn get_wait_time(&self) -> Duration {
        self.wait_time
    }
    /// Get send rate
    pub fn get_send_rate(&self) -> Duration {
        self.send_rate
    }
    /// Get scan result
    pub fn get_scan_result(&self) -> PortScanResult {
        self.scan_result.clone()
    }
    /// Run scan with current settings 
    /// 
    /// Results are stored in AsyncPortScanner::scan_result
    pub async fn run_scan(&mut self) {
        let start_time = Instant::now();
        let (ports, status) = scan_ports(self.clone()).await;
        let scan_time = Instant::now().duration_since(start_time);
        self.scan_result.ports = ports;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = scan_time;
    }
}
