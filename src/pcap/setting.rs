use std::net::IpAddr;
use std::collections::HashSet;
use std::time::Duration;
use nex::packet::{ip::IpNextLevelProtocol, ethernet::EtherType};
use nex::net::interface::Interface;

/// Packet capture options
#[derive(Debug, Clone)]
pub struct PacketCaptureSetting {
    /// Interface index
    pub interface_index: u32,
    /// Source IP addresses to filter. If empty, all source IP addresses will be captured
    pub src_ips: HashSet<IpAddr>,
    /// Destination IP addresses to filter. If empty, all destination IP addresses will be captured
    pub dst_ips: HashSet<IpAddr>,
    /// Source ports to filter. If empty, all source ports will be captured
    pub src_ports: HashSet<u16>,
    /// Destination ports to filter. If empty, all destination ports will be captured
    pub dst_ports: HashSet<u16>,
    /// Ether types to filter. If empty, all ether types will be captured
    pub ether_types: HashSet<EtherType>,
    /// IP protocols to filter. If empty, all IP protocols will be captured
    pub ip_protocols: HashSet<IpNextLevelProtocol>,
    /// Capture duration limit
    pub capture_timeout: Duration,
    /// Read Timeout for read next packet (Linux, BPF only)
    pub read_timeout: Duration,
    /// Capture in promiscuous mode
    pub promiscuous: bool,
    /// Receive undefined packets
    pub receive_undefined: bool,
    /// Use TUN interface
    pub tunnel: bool,
    /// Use Loopback interface
    pub loopback: bool,
}

impl Default for PacketCaptureSetting {
    fn default() -> Self {
        let iface: Interface = netdev::get_default_interface().unwrap();
        Self {
            interface_index: iface.index,
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::MAX,
            read_timeout: Duration::from_millis(200),
            promiscuous: false,
            receive_undefined: true,
            tunnel: iface.is_tun(),
            loopback: iface.is_loopback(),
        }
    }
}
