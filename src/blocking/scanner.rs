use std::net::IpAddr;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use crate::setting::{Destination, ScanType, DEFAULT_SRC_PORT, ScanSetting};
use crate::result::{HostScanResult, PortScanResult, ScanStatus};
use crate::blocking::{scan_hosts, scan_ports};
use crate::interface;

#[derive(Clone, Debug)]
pub struct HostScanner {
    pub if_index: u32,
    pub if_name: String,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub destinations: Vec<Destination>,
    pub scan_type: ScanType,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub scan_result: HostScanResult,
}

#[derive(Clone, Debug)]
pub struct PortScanner {
    pub if_index: u32,
    pub if_name: String,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],  
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub destinations: Vec<Destination>,
    pub scan_type: ScanType,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub scan_result: PortScanResult,
}

impl HostScanner {
    pub fn new(src_ip: IpAddr) -> Result<HostScanner, String> {
        let mut if_index: u32 = 0;
        let mut if_name: String = String::new();
        let mut src_mac: pnet_datalink::MacAddr = pnet_datalink::MacAddr::zero();
        for iface in pnet_datalink::interfaces() {
            for ip in iface.ips {
                if ip.ip() == src_ip {
                    if_index = iface.index;
                    if_name = iface.name;
                    src_mac = iface.mac.unwrap_or(pnet_datalink::MacAddr::zero());
                    break;
                }
            }   
        }
        if if_index == 0 || if_name.is_empty() || src_mac == pnet_datalink::MacAddr::zero() {
            return Err(String::from("Failed to create Scanner. Network Interface not found."));
        }
        let host_scanner = HostScanner {
            if_index: if_index,
            if_name: if_name,
            src_mac: src_mac.octets(),
            dst_mac: interface::get_default_gateway_macaddr(),
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            destinations: vec![],
            scan_type: ScanType::IcmpPingScan,
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            scan_result: HostScanResult::new(),
        };
        Ok(host_scanner)
    }
    pub fn set_src_ip(&mut self, src_ip: IpAddr){
        self.src_ip = src_ip;
    }
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip.clone()
    }
    pub fn add_destination(&mut self, dst: Destination){
        self.destinations.push(dst);
    }
    pub fn set_destinations(&mut self, dst: Vec<Destination>){
        self.destinations = dst;
    }
    pub fn get_destinations(&self) -> Vec<Destination> {
        self.destinations.clone()
    }
    pub fn set_scan_type(&mut self, scan_type: ScanType){
        self.scan_type = scan_type;
    }
    pub fn get_scan_type(&self) -> ScanType {
        self.scan_type.clone()
    } 
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    pub fn get_timeout(&self) -> Duration {
        self.timeout.clone()
    }  
    pub fn set_wait_time(&mut self, wait_time: Duration){
        self.wait_time = wait_time;
    }
    pub fn get_wait_time(&self) -> Duration {
        self.wait_time.clone()
    }
    pub fn set_send_rate(&mut self, send_rate: Duration){
        self.wait_time = send_rate;
    }
    pub fn get_send_rate(&self) -> Duration {
        self.send_rate.clone()
    }
    pub fn get_scan_result(&self) -> HostScanResult {
        self.scan_result.clone()
    }
    pub fn run_scan(&mut self){
        let mut ip_set: HashSet<IpAddr> = HashSet::new();
        for dst in self.destinations.clone() {
            ip_set.insert(dst.dst_ip);
        }
        let scan_setting: ScanSetting = ScanSetting {
            if_index: self.if_index.clone(),
            src_mac: pnet_datalink::MacAddr::from(self.src_mac),
            dst_mac: pnet_datalink::MacAddr::from(self.dst_mac),
            src_ip: self.src_ip.clone(),
            src_port: self.src_port.clone(),
            destinations: self.destinations.clone(),
            ip_set: ip_set,
            timeout: self.timeout.clone(),
            wait_time: self.wait_time.clone(),
            send_rate: self.send_rate.clone(),
            scan_type: self.scan_type.clone(),
        };
        let start_time = Instant::now();
        let mut result: HostScanResult = scan_hosts(scan_setting);
        result.scan_time = Instant::now().duration_since(start_time);
        if result.scan_time > self.timeout {
            result.scan_status = ScanStatus::Timeout;
        } else {
            result.scan_status = ScanStatus::Done;
        }
        self.scan_result = result;
    }
}

impl PortScanner {
    pub fn new(src_ip: IpAddr) -> Result<PortScanner, String> {
        let mut if_index: u32 = 0;
        let mut if_name: String = String::new();
        let mut src_mac: pnet_datalink::MacAddr = pnet_datalink::MacAddr::zero();
        for iface in pnet_datalink::interfaces() {
            for ip in iface.ips {
                if ip.ip() == src_ip {
                    if_index = iface.index;
                    if_name = iface.name;
                    src_mac = iface.mac.unwrap_or(pnet_datalink::MacAddr::zero());
                    break;
                }
            }   
        }
        if if_index == 0 || if_name.is_empty() || src_mac == pnet_datalink::MacAddr::zero() {
            return Err(String::from("Failed to create Scanner. Network Interface not found."));
        }
        let port_scanner = PortScanner {
            if_index: if_index,
            if_name: if_name,
            src_mac: src_mac.octets(),
            dst_mac: interface::get_default_gateway_macaddr(),
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            destinations: vec![],
            scan_type: ScanType::TcpSynScan,
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            scan_result: PortScanResult::new(),
        };
        Ok(port_scanner)
    }
    pub fn set_src_ip(&mut self, src_ip: IpAddr){
        self.src_ip = src_ip;
    }
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip.clone()
    }
    pub fn add_destination(&mut self, dst: Destination){
        self.destinations.push(dst);
    }
    pub fn set_destinations(&mut self, dst: Vec<Destination>){
        self.destinations = dst;
    }
    pub fn get_destinations(&self) -> Vec<Destination> {
        self.destinations.clone()
    }
    pub fn set_scan_type(&mut self, scan_type: ScanType){
        self.scan_type = scan_type;
    }
    pub fn get_scan_type(&self) -> ScanType {
        self.scan_type.clone()
    } 
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    pub fn get_timeout(&self) -> Duration {
        self.timeout.clone()
    }  
    pub fn set_wait_time(&mut self, wait_time: Duration){
        self.wait_time = wait_time;
    }
    pub fn get_wait_time(&self) -> Duration {
        self.wait_time.clone()
    }
    pub fn set_send_rate(&mut self, send_rate: Duration){
        self.wait_time = send_rate;
    }
    pub fn get_send_rate(&self) -> Duration {
        self.send_rate.clone()
    }
    pub fn get_scan_result(&self) -> PortScanResult {
        self.scan_result.clone()
    }
    pub fn run_scan(&mut self){
        let mut ip_set: HashSet<IpAddr> = HashSet::new();
        for dst in self.destinations.clone() {
            ip_set.insert(dst.dst_ip);
        }
        let scan_setting: ScanSetting = ScanSetting {
            if_index: self.if_index.clone(),
            src_mac: pnet_datalink::MacAddr::from(self.src_mac),
            dst_mac: pnet_datalink::MacAddr::from(self.dst_mac),
            src_ip: self.src_ip.clone(),
            src_port: self.src_port.clone(),
            destinations: self.destinations.clone(),
            ip_set: ip_set,
            timeout: self.timeout.clone(),
            wait_time: self.wait_time.clone(),
            send_rate: self.send_rate.clone(),
            scan_type: self.scan_type.clone(),
        };
        let start_time = Instant::now();
        let mut result: PortScanResult = scan_ports(scan_setting);
        result.scan_time = Instant::now().duration_since(start_time);
        if result.scan_time > self.timeout {
            result.scan_status = ScanStatus::Timeout;
        } else {
            result.scan_status = ScanStatus::Done;
        }
        self.scan_result = result;
    }
}
