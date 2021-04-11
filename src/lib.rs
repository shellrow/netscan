#[macro_use]
extern crate log;

mod interface;
mod arp;
mod ethernet;
mod ipv4;
mod icmp;
mod tcp;
mod udp;
mod packet;
mod status;
mod port;
mod host;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use default_net;

pub use tcp::PortScanType;
pub use status::ScanStatus;

/// Result of HostScanner::new
pub type NewHostScannerResult = Result<HostScanner, String>;

/// Result of PortScanner::new
pub type NewPortScannerResult = Result<PortScanner, String>;

/// Structure for host scan  
/// 
/// Should be constructed using HostScanner::new 
pub struct HostScanner {
    /// Source IP Address.  
    src_ipaddr: IpAddr,
    /// List of target host.  
    target_hosts: Vec<IpAddr>,
    /// Timeout setting of host scan.  
    timeout: Duration,
    /// Result of host scan.  
    scan_result: HostScanResult,
}

/// Structure for port scan.  
/// 
/// Should be constructed using PortScanner::new 
pub struct PortScanner {
    /// Index of network interface.  
    if_index: u32,
    /// Name of network interface.  
    if_name: String,
    /// IP Address of target host.  
    target_ipaddr: Ipv4Addr, 
    /// Start port number of port range.  
    start_port_num: u16,
    /// End port number of port range.  
    end_port_num: u16,
    /// Type of port scan. Default is PortScanType::SynScan  
    scan_type: PortScanType,
    /// Source port number.  
    src_port_num: u16,
    /// Timeout setting of port scan.   
    timeout: Duration,
    /// Result of port scan.  
    scan_result: PortScanResult,
}

/// Result of HostScanner::run_scan  
#[derive(Clone)]
pub struct HostScanResult {
    /// List of up host.  
    pub up_hosts: Vec<String>,
    /// Time from start to end of scan.  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

/// Result of PortScanner::run_scan  
#[derive(Clone)]
pub struct PortScanResult {
    /// List of open port.  
    pub open_ports: Vec<String>,
    /// Time from start to end of scan.  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

impl HostScanner{
    /// Construct new HostScanner  
    pub fn new() -> NewHostScannerResult {
        let ini_scan_result = HostScanResult{
            up_hosts: vec![],
            scan_time: Duration::from_millis(1),
            scan_status: ScanStatus::Ready,
        };
        let host_scanner = HostScanner{
            src_ipaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            target_hosts: vec![],
            timeout: Duration::from_millis(30000),
            scan_result: ini_scan_result,
        };
        Ok(host_scanner)
    }
    /// Add target host to list.
    pub fn add_ipaddr(&mut self, ipaddr: &str) {
        let addr = ipaddr.parse::<IpAddr>();
        match addr {
            Ok(valid_addr) => {
                debug!("Address added {}", valid_addr);
                self.target_hosts.push(valid_addr);
            }
            Err(e) => {
                error!("Error adding ip address {}. Error: {}", ipaddr, e);
            }
        };
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    /// Set source IP Address 
    pub fn set_src_ipaddr(&mut self, src_ipaddr:IpAddr){
        self.src_ipaddr = src_ipaddr;
    }
    /// Run scan with current settings. 
    /// 
    /// Results are stored in HostScanner::scan_result
    pub fn run_scan(&mut self){
        let start_time = Instant::now();
        let (uphosts, status) = host::scan_hosts(&self.target_hosts, &self.timeout);
        self.scan_result.up_hosts = uphosts;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = Instant::now().duration_since(start_time);
    }
    /// Return scan result.
    pub fn get_result(&mut self) -> HostScanResult{
        return self.scan_result.clone();
    }
}

impl PortScanner{
    /// Construct new PortScanner. (with network interface index or name)
    /// 
    /// Specify None for default. `PortScanner::new(None, None)`
    pub fn new(_if_index: Option<u32>, _if_name: Option<&str>) -> NewPortScannerResult{
        let ini_scan_result = PortScanResult{
            open_ports: vec![],
            scan_time: Duration::from_millis(1),
            scan_status: ScanStatus::Ready,
        };
        let mut port_scanner = PortScanner{
            if_index: 0,
            if_name: String::new(),
            target_ipaddr: Ipv4Addr::new(127, 0, 0, 1), 
            start_port_num: 1,
            end_port_num: 1000,
            scan_type: PortScanType::SynScan,
            src_port_num: 65432,
            timeout: Duration::from_millis(30000),
            scan_result: ini_scan_result,
        };
        if _if_index == None && _if_name == None{
            let def_if_index = default_net::get_default_interface_index();
            if let Some(def_if_index) = def_if_index {
                port_scanner.if_index = def_if_index;
            }else{
                return Err("Failed to get default interface info.".to_string());
            }
        }else{
            if let Some(if_index) = _if_index {
                port_scanner.if_index = if_index;
            }
            if let Some(if_name) = _if_name {
                let if_index = interface::get_interface_index_by_name(if_name.to_string());
                if let Some(if_index) = if_index{
                    port_scanner.if_index = if_index;
                    port_scanner.if_name = if_name.to_string();
                }else{
                    return Err("Failed to get interface info by name.".to_string());
                }
            }
        }
        Ok(port_scanner)
    }
    /// Set IP address of target host
    pub fn set_target_ipaddr(&mut self, ipaddr: &str){
        let ipv4addr = ipaddr.parse::<Ipv4Addr>();
        match ipv4addr {
            Ok(valid_ipaddr) => {
                self.target_ipaddr = valid_ipaddr;
            }
            Err(e) => {
                error!("Error setting IP Address {}. Error: {}", ipaddr, e);
            }
        }
    }
    /// Set range of target ports (by start and end)
    pub fn set_range(&mut self, start: u16, end: u16){
        self.start_port_num = start;
        self.end_port_num = end;
    }
    /// Set scan type. Default is PortScanType::SynScan
    pub fn set_scan_type(&mut self, scan_type: PortScanType){
        self.scan_type = scan_type;
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    /// Set source port number 
    pub fn set_src_port(&mut self, src_port: u16){
        self.src_port_num = src_port;
    }
    /// Run scan with current settings. 
    /// 
    /// Results are stored in PortScanner::scan_result
    pub fn run_scan(&mut self){
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == self.if_index).next().expect("Failed to get Interface");
        let target_mac: pnet::datalink::MacAddr = arp::get_mac_through_arp(&interface, self.target_ipaddr);
        let mut iface_ip: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
        for ip in &interface.ips{
            match ip.ip() {
                IpAddr::V4(ipv4) => {
                    iface_ip = ipv4;
                    break;
                },
                /*
                IpAddr::V6(ipv6) => {
                    
                },
                */
                _ => {
                    continue;
                },
            }
        }
        if iface_ip == Ipv4Addr::new(127, 0, 0, 1) {
            error!("Error: Interface IP is IPv6 (or unknown) which is not currently supported");
        }
        let tcp_options: port::TcpOptions = port::TcpOptions {
            sender_mac: interface.mac.unwrap(),
            target_mac: target_mac,
            src_ip: iface_ip,
            dst_ip: self.target_ipaddr,    
            src_port: self.src_port_num,
            min_port_num: self.start_port_num,
            max_port_num: self.end_port_num,
            scan_type: self.scan_type,
            timeout: self.timeout,
        };
        let start_time = Instant::now();
        let (open_ports, status) = port::scan_ports(&interface, &tcp_options);
        self.scan_result.open_ports = open_ports;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = Instant::now().duration_since(start_time);
    }
    /// Return scan result.
    pub fn get_result(&mut self) -> PortScanResult{
        return self.scan_result.clone();
    }
}
