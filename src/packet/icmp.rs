use nex::packet::ethernet::EtherType;
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::ip::IpNextLevelProtocol;
use nex::util::packet_builder::builder::PacketBuilder;
use nex::util::packet_builder::ethernet::EthernetPacketBuilder;
use nex::util::packet_builder::icmp::IcmpPacketBuilder;
use nex::util::packet_builder::icmpv6::Icmpv6PacketBuilder;
use nex::util::packet_builder::ipv4::Ipv4PacketBuilder;
use nex::util::packet_builder::ipv6::Ipv6PacketBuilder;
use std::net::IpAddr;

use crate::packet::setting::PacketBuildSetting;

/// Build ICMP packet. Supports both ICMPv4 and ICMPv6
pub fn build_icmp_packet(setting: PacketBuildSetting) -> Vec<u8> {
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
                    Ipv4PacketBuilder::new(src_ipv4, dst_ipv4, IpNextLevelProtocol::Icmp);
                ipv4_packet_builder.ttl = Some(setting.hop_limit);
                packet_builder.set_ipv4(ipv4_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv4) => {
                let mut ipv6_packet_builder =
                    Ipv6PacketBuilder::new(src_ipv4, dst_ipv6, IpNextLevelProtocol::Icmpv6);
                ipv6_packet_builder.hop_limit = Some(setting.hop_limit);
                packet_builder.set_ipv6(ipv6_packet_builder);
            }
        },
    }
    // ICMP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let mut icmp_packet_builder = IcmpPacketBuilder::new(src_ipv4, dst_ipv4);
                icmp_packet_builder.icmp_type = IcmpType::EchoRequest;
                packet_builder.set_icmp(icmp_packet_builder);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(src_ipv6) => {
                let mut icmpv6_packet_builder = Icmpv6PacketBuilder::new(src_ipv6, dst_ipv6);
                icmpv6_packet_builder.icmpv6_type = Icmpv6Type::EchoRequest;
                packet_builder.set_icmpv6(icmpv6_packet_builder);
            }
        },
    }
    if setting.ip_packet {
        packet_builder.ip_packet()
    } else {
        packet_builder.packet()
    }
}

pub fn build_ip_next_icmp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    // ICMP Header
    match setting.dst_ip {
        IpAddr::V4(dst_ipv4) => match setting.src_ip {
            IpAddr::V4(src_ipv4) => {
                let mut icmp_packet_builder = IcmpPacketBuilder::new(src_ipv4, dst_ipv4);
                icmp_packet_builder.icmp_type = IcmpType::EchoRequest;
                icmp_packet_builder.build()
            }
            IpAddr::V6(_) => Vec::new(),
        },
        IpAddr::V6(dst_ipv6) => match setting.src_ip {
            IpAddr::V4(_) => Vec::new(),
            IpAddr::V6(src_ipv6) => {
                let mut icmpv6_packet_builder = Icmpv6PacketBuilder::new(src_ipv6, dst_ipv6);
                icmpv6_packet_builder.icmpv6_type = Icmpv6Type::EchoRequest;
                icmpv6_packet_builder.build()
            }
        },
    }
}
