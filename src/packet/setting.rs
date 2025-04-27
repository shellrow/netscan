use netdev::mac::MacAddr;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug)]
pub struct PacketBuildSetting {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub hop_limit: u8,
    #[allow(dead_code)]
    pub payload: Vec<u8>,
    pub ip_packet: bool,
}

impl PacketBuildSetting {
    pub fn new() -> Self {
        Self {
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            hop_limit: 64,
            payload: Vec::new(),
            ip_packet: false,
        }
    }
}
