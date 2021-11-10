use std::net::IpAddr;
use std::time::Duration;
use std::collections::HashSet;
use pnet_datalink::MacAddr;

pub const DEFAULT_SRC_PORT: u16 = 53443;

#[derive(Clone, Debug)]
pub enum ScanType {
    TcpSynScan,
    TcpConnectScan,
    IcmpPingScan,
    TcpPingScan,
    UdpPingScan,
}

#[derive(Clone, Debug)]
pub struct Destination {
    pub dst_ip: IpAddr,
    pub dst_ports: Vec<u16>,
}

impl Destination {
    pub fn new(ip_addr: IpAddr, ports: Vec<u16>) -> Destination {
        Destination {
            dst_ip: ip_addr,
            dst_ports: ports,
        }
    }
    pub fn new_with_port_range(ip_addr: IpAddr, start_port: u16, end_port: u16) -> Destination {
        let mut ports: Vec<u16> = vec![];
        for i in start_port..end_port + 1 {
            ports.push(i);
        }
        Destination {
            dst_ip: ip_addr,
            dst_ports: ports,
        }
    }
    pub fn set_dst_ip(&mut self, ip_addr: IpAddr) {
        self.dst_ip = ip_addr;
    }
    pub fn get_dst_ip(&self) -> IpAddr {
        self.dst_ip.clone()
    }
    pub fn set_dst_port(&mut self, ports: Vec<u16>) {
        self.dst_ports = ports;
    }
    pub fn get_dst_port(&self) -> Vec<u16> {
        self.dst_ports.clone()
    }
}

#[derive(Clone, Debug)]
pub struct ScanSetting {
    pub if_index: u32,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub destinations: Vec<Destination>,
    pub ip_set: HashSet<IpAddr>,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub scan_type: ScanType,
}

impl ScanSetting {

}
