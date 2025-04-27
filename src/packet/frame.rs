use nex::packet::arp::ArpHeader;
use nex::packet::ethernet::EthernetHeader;
use nex::packet::frame::Frame;
use nex::packet::icmp::IcmpHeader;
use nex::packet::icmpv6::Icmpv6Header;
use nex::packet::ipv4::Ipv4Header;
use nex::packet::ipv6::Ipv6Header;
use nex::packet::tcp::TcpHeader;
use nex::packet::udp::UdpHeader;

/// Packet Frame. Contains all the possible packet types
#[derive(Clone, Debug)]
pub struct PacketFrame {
    pub ethernet_header: Option<EthernetHeader>,
    pub arp_header: Option<ArpHeader>,
    pub ipv4_header: Option<Ipv4Header>,
    pub ipv6_header: Option<Ipv6Header>,
    pub icmp_header: Option<IcmpHeader>,
    pub icmpv6_header: Option<Icmpv6Header>,
    pub tcp_header: Option<TcpHeader>,
    pub udp_header: Option<UdpHeader>,
    pub payload: Vec<u8>,
}

impl PacketFrame {
    /// Constructs a new PacketFrame
    pub fn new() -> PacketFrame {
        PacketFrame {
            ethernet_header: None,
            arp_header: None,
            ipv4_header: None,
            ipv6_header: None,
            icmp_header: None,
            icmpv6_header: None,
            tcp_header: None,
            udp_header: None,
            payload: vec![],
        }
    }
    pub fn from_nex_frame(frame: &Frame) -> PacketFrame {
        let mut packet_frame = PacketFrame::new();
        if let Some(datalink) = &frame.datalink {
            packet_frame.ethernet_header = datalink.ethernet.clone();
            packet_frame.arp_header = datalink.arp.clone();
        }
        if let Some(ip) = &frame.ip {
            packet_frame.ipv4_header = ip.ipv4.clone();
            packet_frame.ipv6_header = ip.ipv6.clone();
            packet_frame.icmp_header = ip.icmp.clone();
            packet_frame.icmpv6_header = ip.icmpv6.clone();
        }
        if let Some(transport) = &frame.transport {
            packet_frame.tcp_header = transport.tcp.clone();
            packet_frame.udp_header = transport.udp.clone();
        }
        packet_frame.payload = frame.payload.clone();
        packet_frame
    }
}
