use crate::packet::setting::PacketBuildSetting;
use nex::packet::ethernet::EtherType;
use nex::packet::ip::IpNextLevelProtocol;
use nex::util::packet_builder::{
    builder::PacketBuilder, ethernet::EthernetPacketBuilder, ipv4::Ipv4PacketBuilder,
    ipv6::Ipv6PacketBuilder, udp::UdpPacketBuilder,
};
use std::net::{IpAddr, SocketAddr};

/// Build UDP packet
pub fn build_udp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();

    // Ethernet Header
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: setting.src_mac,
        dst_mac: setting.dst_mac,
        ether_type: match setting.dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    // IP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let mut ipv4_packet_builder =
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Udp);
                ipv4_packet_builder.ttl = Some(setting.hop_limit);
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv4) => {
                let mut ipv6_packet_builder =
                    Ipv6PacketBuilder::new(src_ipv4, dst_ipv6, IpNextLevelProtocol::Udp);
                ipv6_packet_builder.hop_limit = Some(setting.hop_limit);
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    // UDP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(IpAddr::V4(src_ipv4), setting.src_port),
                    SocketAddr::new(IpAddr::V4(dst_ipv4), setting.dst_port),
                );
                packet_builder.set_udp(udp_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv6) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(IpAddr::V6(src_ipv6), setting.src_port),
                    SocketAddr::new(IpAddr::V6(dst_ipv6), setting.dst_port),
                );
                packet_builder.set_udp(udp_packet_builder);
            }
        },
    }
    if setting.ip_packet {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}

pub fn build_ip_next_udp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    // UDP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(IpAddr::V4(src_ipv4), setting.src_port),
                    SocketAddr::new(IpAddr::V4(dst_ipv4), setting.dst_port),
                );
                udp_packet_builder.build()
            }
            IpAddr::V6(_) => Vec::new(),
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => Vec::new(),
            IpAddr::V6(src_ipv6) => {
                let udp_packet_builder = UdpPacketBuilder::new(
                    SocketAddr::new(IpAddr::V6(src_ipv6), setting.src_port),
                    SocketAddr::new(IpAddr::V6(dst_ipv6), setting.dst_port),
                );
                udp_packet_builder.build()
            }
        },
    }
}
