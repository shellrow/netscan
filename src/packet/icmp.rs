use bytes::Bytes;
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::builder::icmp::IcmpPacketBuilder;
use nex::packet::builder::icmpv6::Icmpv6PacketBuilder;
use nex::packet::builder::ipv4::Ipv4PacketBuilder;
use nex::packet::builder::ipv6::Ipv6PacketBuilder;
use nex::packet::ethernet::EtherType;
use nex::packet::icmp;
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6;
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::ip::IpNextProtocol;
use nex::packet::ipv4::Ipv4Flags;
use std::net::IpAddr;

use crate::packet::setting::PacketBuildSetting;

fn wrap_transport_packet(setting: &PacketBuildSetting, transport_bytes: Bytes) -> Vec<u8> {
    let ip_bytes = match (setting.src_ip, setting.dst_ip) {
        (IpAddr::V4(src_ipv4), IpAddr::V4(dst_ipv4)) => Ipv4PacketBuilder::new()
            .source(src_ipv4)
            .destination(dst_ipv4)
            .ttl(setting.hop_limit)
            .protocol(IpNextProtocol::Icmp)
            .flags(Ipv4Flags::DontFragment)
            .payload(transport_bytes)
            .to_bytes(),
        (IpAddr::V6(src_ipv6), IpAddr::V6(dst_ipv6)) => Ipv6PacketBuilder::new()
            .source(src_ipv6)
            .destination(dst_ipv6)
            .hop_limit(setting.hop_limit)
            .next_header(IpNextProtocol::Icmpv6)
            .payload(transport_bytes)
            .to_bytes(),
        _ => return Vec::new(),
    };

    if setting.ip_packet {
        return ip_bytes.to_vec();
    }

    EthernetPacketBuilder::new()
        .source(setting.src_mac)
        .destination(setting.dst_mac)
        .ethertype(match setting.dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_bytes)
        .to_bytes()
        .to_vec()
}

/// Build ICMP packet. Supports both ICMPv4 and ICMPv6
pub fn build_icmp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    let icmp_bytes = match (setting.src_ip, setting.dst_ip) {
        (IpAddr::V4(src_ipv4), IpAddr::V4(dst_ipv4)) => IcmpPacketBuilder::new(src_ipv4, dst_ipv4)
            .icmp_type(IcmpType::EchoRequest)
            .icmp_code(icmp::echo_request::IcmpCodes::NoCode)
            .echo_fields(0x1234, 0x1)
            .payload(Bytes::from_static(b"hello"))
            .to_bytes(),
        (IpAddr::V6(src_ipv6), IpAddr::V6(dst_ipv6)) => {
            Icmpv6PacketBuilder::new(src_ipv6, dst_ipv6)
                .icmpv6_type(Icmpv6Type::EchoRequest)
                .icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode)
                .echo_fields(0x1234, 0x1)
                .payload(Bytes::from_static(b"hello"))
                .to_bytes()
        }
        _ => return Vec::new(),
    };
    wrap_transport_packet(&setting, icmp_bytes)
}

#[allow(dead_code)]
pub fn build_ip_next_icmp_packet(setting: PacketBuildSetting) -> Vec<u8> {
    match (setting.src_ip, setting.dst_ip) {
        (IpAddr::V4(src_ipv4), IpAddr::V4(dst_ipv4)) => IcmpPacketBuilder::new(src_ipv4, dst_ipv4)
            .icmp_type(IcmpType::EchoRequest)
            .icmp_code(icmp::echo_request::IcmpCodes::NoCode)
            .echo_fields(0x1234, 0x1)
            .payload(Bytes::from_static(b"hello"))
            .to_bytes()
            .to_vec(),
        (IpAddr::V6(src_ipv6), IpAddr::V6(dst_ipv6)) => {
            Icmpv6PacketBuilder::new(src_ipv6, dst_ipv6)
                .icmpv6_type(Icmpv6Type::EchoRequest)
                .icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode)
                .echo_fields(0x1234, 0x1)
                .payload(Bytes::from_static(b"hello"))
                .to_bytes()
                .to_vec()
        }
        _ => Vec::new(),
    }
}
