use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use default_net;
use pnet::datalink::MacAddr;
use crate::interface;
use crate::scanner::{scan_hosts, scan_ports};
use crate::base_type::{PortScanType, HostScanResult, PortScanResult, Protocol, ScanSetting};
use crate::define::DEFAULT_SRC_PORT;

/// Structure for host scan with various options.   
/// 
/// Should be constructed using HostScanner::new 
#[derive(Clone)]
pub struct HostScanner {
    /// Source IP Address  
    pub src_ip: IpAddr,
    /// List of target host  
    pub dst_ips: Vec<IpAddr>,
    /// Timeout setting of host scan  
    pub timeout: Duration,
    /// Timeout setting of host scan  
    pub wait_time: Duration,
    /// Result of host scan  
    pub scan_result: HostScanResult,
}

/// Structure for port scan with various options.  
/// 
/// Should be constructed using PortScanner::new 
#[derive(Clone)]
pub struct PortScanner {
    /// Index of network interface  
    pub if_index: u32,
    /// Name of network interface  
    pub if_name: String,
    /// Source MAC Address
    pub src_mac: MacAddr,
    /// Destination MAC Address
    pub dst_mac: MacAddr,
    /// Source IP Address  
    pub src_ip: IpAddr,
    /// Destination IP Address  
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port  
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

impl HostScanner {
    /// Construct new HostScanner  
    pub fn new() -> Result<HostScanner, String> {
        let host_scanner = HostScanner{
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ips: vec![],
            timeout: Duration::from_millis(10000),
            wait_time: Duration::from_millis(200),
            scan_result: HostScanResult::new(),
        };
        Ok(host_scanner)
    }
    /// Set source IP address 
    pub fn set_src_ip(&mut self, src_ipaddr:IpAddr){
        self.src_ip = src_ipaddr;
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
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    /// Set scan wait time  
    pub fn set_wait_time(&mut self, wait_time: Duration){
        self.wait_time = wait_time;
    }
    /// Set scan result
    pub fn set_scan_result(&mut self, scan_result: HostScanResult) {
        self.scan_result = scan_result;
    }
    /// Get source IP Address
    pub fn get_src_ip(&mut self) -> IpAddr {
        return self.src_ip.clone();
    }
    /// Get destination hosts
    pub fn get_dst_ips(&mut self) -> Vec<IpAddr> {
        return self.dst_ips.clone();
    }
    /// Get timeout 
    pub fn get_timeout(&mut self) -> Duration {
        return self.timeout.clone();
    }
    /// Get wait time
    pub fn get_wait_time(&mut self) -> Duration {
        return self.wait_time.clone();
    }
    /// Get scan result
    pub fn get_scan_result(&mut self) -> HostScanResult{
        return self.scan_result.clone();
    }
    /// Run scan with current settings 
    /// 
    /// Results are stored in HostScanner::scan_result
    pub fn run_scan(&mut self){
        let default_if = default_net::get_default_interface().unwrap();
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == default_if.index).next().expect("Failed to get Interface");
        let scan_setting: ScanSetting = ScanSetting {
            src_mac: default_if.mac.unwrap().parse::<pnet::datalink::MacAddr>().unwrap(),
            dst_mac: default_if.gateway.mac.expect("Failed to get gateway mac").parse::<pnet::datalink::MacAddr>().unwrap(),
            src_ip: self.src_ip.clone(),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ips: self.dst_ips.clone(),
            src_port: DEFAULT_SRC_PORT,
            dst_ports: vec![],
            timeout: self.timeout.clone(),
            wait_time: self.wait_time.clone(),
            send_rate: Duration::from_millis(1),
            protocol: Protocol::Icmp,
            scan_type: None,
        };
        let start_time = Instant::now();
        let (uphosts, status) = scan_hosts(&interface, &scan_setting);
        self.scan_result.up_hosts = uphosts;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = Instant::now().duration_since(start_time);
    }
}

impl PortScanner {
    /// Construct new PortScanner (with network interface name)
    /// 
    /// Specify None for default. `PortScanner::new(None)`
    pub fn new(if_name: Option<&str>) -> Result<PortScanner, String> {
        let mut port_scanner = PortScanner{
            if_index: 0,
            if_name: String::new(),
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 
            src_port: DEFAULT_SRC_PORT,
            dst_ports: vec![],
            scan_type: PortScanType::SynScan,
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(100),
            send_rate: Duration::from_millis(0),
            scan_result: PortScanResult::new(),
        };
        if let Some(if_name) = if_name {
            let if_index = interface::get_interface_index_by_name(if_name.to_string());
            if let Some(if_index) = if_index{
                port_scanner.if_index = if_index;
                port_scanner.if_name = if_name.to_string();
            }else{
                return Err("Failed to get interface info by name.".to_string());
            }
        }else{
            let def_if_index = default_net::get_default_interface_index();
            if let Some(def_if_index) = def_if_index {
                port_scanner.if_index = def_if_index;
            }else{
                return Err("Failed to get default interface info.".to_string());
            }
        }
        Ok(port_scanner)
    }
    /// Set source IP address  
    pub fn set_src_ip(&mut self, ip_addr: IpAddr) {
        self.src_ip = ip_addr;
    }
    /// Set destination IP address 
    pub fn set_dst_ip(&mut self, ip_addr: IpAddr){
        self.dst_ip = ip_addr;
    }
    /// Set source port number 
    pub fn set_src_port(&mut self, src_port: u16){
        self.src_port = src_port;
    }
    /// Add destination port 
    pub fn add_dst_port(&mut self, port_num: u16){
        self.dst_ports.push(port_num);
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
    pub fn set_scan_type(&mut self, scan_type: PortScanType){
        self.scan_type = scan_type;
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    /// Set scan wait-time  
    pub fn set_wait_time(&mut self, wait_time: Duration){
        self.wait_time = wait_time;
    }
    /// Set packet send rate
    pub fn set_send_rate(&mut self, send_rate: Duration){
        self.send_rate = send_rate;
    }
    /// Set scan result
    pub fn set_scan_result(&mut self, scan_result: PortScanResult) {
        self.scan_result = scan_result;
    }
    /// Get network interface index
    pub fn get_if_index(&mut self) -> u32 {
        return self.if_index.clone();
    }
    /// Get network interface name
    pub fn get_if_name(&mut self) -> String {
        return self.if_name.clone();
    }
    /// Get source ip address
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    /// Get destination ip address
    pub fn get_dst_ip(&mut self) -> IpAddr {
        return self.dst_ip.clone();
    }
    /// Get source port
    pub fn get_src_port(&self) -> u16 {
        self.src_port
    }
    /// Get destination ports
    pub fn get_dst_ports(&mut self) -> Vec<u16> {
        return self.dst_ports.clone();
    }
    /// Get PortScanType
    pub fn get_scan_type(&mut self) -> PortScanType {
        return self.scan_type.clone();
    }
    /// Get timeout
    pub fn get_timeout(&mut self) -> Duration {
        return self.timeout.clone();
    }
    /// Get wait-time
    pub fn get_wait_time(&mut self) -> Duration {
        return self.wait_time.clone();
    }
    /// Get send rate
    pub fn get_send_rate(&mut self) -> Duration {
        return self.send_rate.clone();
    }
    /// Get scan result
    pub fn get_scan_result(&mut self) -> PortScanResult {
        return self.scan_result.clone();
    }
    /// Run scan with current settings 
    /// 
    /// Results are stored in PortScanner::scan_result
    pub fn run_scan(&mut self) {
        let dst_mac = match self.scan_type {
            PortScanType::ConnectScan => {
                pnet::datalink::MacAddr::zero()
            },
            _ => {
                interface::get_default_gateway_macaddr()
            },
        };
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == self.if_index).next().expect("Failed to get Interface");    
        let mut iface_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        for ip in &interface.ips {
            match ip.ip() {
                IpAddr::V4(ipv4) => iface_ip = IpAddr::V4(ipv4),
                IpAddr::V6(ipv6) => iface_ip = IpAddr::V6(ipv6),
            }
        }
        self.src_mac = interface.mac.unwrap();
        self.dst_mac = dst_mac;
        self.src_ip = iface_ip;
        let scan_setting: ScanSetting = ScanSetting {
            src_mac: self.src_mac.clone(),
            dst_mac: self.dst_mac.clone(),
            src_ip: self.src_ip.clone(),
            dst_ip: self.dst_ip.clone(),
            dst_ips: vec![],
            src_port: self.src_port.clone(),
            dst_ports: self.dst_ports.clone(),
            timeout: self.timeout.clone(),
            wait_time: self.wait_time.clone(),
            send_rate: self.send_rate.clone(),
            protocol: Protocol::Tcp,
            scan_type: Some(self.scan_type.clone()),
        };
        let start_time = Instant::now();
        let (open_ports, status) = scan_ports(&interface, &scan_setting);
        self.scan_result.ports = open_ports;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = Instant::now().duration_since(start_time);
    }
}
