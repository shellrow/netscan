use crate::packet::setting::PacketBuildSetting;
use nex::packet::ethernet::EtherType;
use nex::packet::ip::IpNextLevelProtocol;
use nex::packet::tcp::{TcpFlags, TcpOption};
use nex::util::packet_builder::{
    builder::PacketBuilder, ethernet::EthernetPacketBuilder, ipv4::Ipv4PacketBuilder,
    ipv6::Ipv6PacketBuilder, tcp::TcpPacketBuilder,
};
use std::net::{IpAddr, SocketAddr};

/// Build TCP SYN packet with default options
pub fn build_tcp_syn_packet(setting: PacketBuildSetting) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: setting.src_mac,
        dst_mac: setting.dst_mac,
        ether_type: match setting.dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    match setting.src_ip {
        IpAddr::V4(src_ipv4) => match setting.dst_ip {
            IpAddr::V4(dst_ipv4) => {
                let mut ipv4_packet_builder =
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Tcp);
                ipv4_packet_builder.total_length = Some(64);
                ipv4_packet_builder.ttl = Some(setting.hop_limit);
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(src_ipv6) => match setting.dst_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(dst_ipv6) => {
                let mut ipv6_packet_builder =
                    Ipv6PacketBuilder::new(src_ipv6, dst_ipv6, IpNextLevelProtocol::Tcp);
                ipv6_packet_builder.payload_length = Some(44);
                ipv6_packet_builder.hop_limit = Some(setting.hop_limit);
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    let mut tcp_packet_builder = TcpPacketBuilder::new(
        SocketAddr::new(setting.src_ip, setting.src_port),
        SocketAddr::new(setting.dst_ip, setting.dst_port),
    );
    tcp_packet_builder.flags = TcpFlags::SYN;
    tcp_packet_builder.window = 65535;
    tcp_packet_builder.options = vec![
        TcpOption::mss(1460),
        TcpOption::nop(),
        TcpOption::wscale(6),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::timestamp(u32::MAX, u32::MIN),
        TcpOption::sack_perm(),
    ];
    packet_builder.set_tcp(tcp_packet_builder);

    if setting.ip_packet {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}

pub fn build_ip_next_tcp_syn_packet(setting: PacketBuildSetting) -> Vec<u8> {
    let mut tcp_packet_builder = TcpPacketBuilder::new(
        SocketAddr::new(setting.src_ip, setting.src_port),
        SocketAddr::new(setting.dst_ip, setting.dst_port),
    );
    tcp_packet_builder.flags = TcpFlags::SYN;
    tcp_packet_builder.window = 65535;
    tcp_packet_builder.options = vec![
        TcpOption::mss(1460),
        TcpOption::nop(),
        TcpOption::wscale(6),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::timestamp(u32::MAX, u32::MIN),
        TcpOption::sack_perm(),
    ];
    tcp_packet_builder.build()
}
