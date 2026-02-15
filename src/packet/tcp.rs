use crate::packet::setting::PacketBuildSetting;
use bytes::Bytes;
use nex::packet::builder::ethernet::EthernetPacketBuilder;
use nex::packet::builder::ipv4::Ipv4PacketBuilder;
use nex::packet::builder::ipv6::Ipv6PacketBuilder;
use nex::packet::builder::tcp::TcpPacketBuilder;
use nex::packet::ethernet::EtherType;
use nex::packet::ip::IpNextProtocol;
use nex::packet::tcp::{TcpFlags, TcpOptionPacket};
use std::net::IpAddr;

fn wrap_transport_packet(setting: &PacketBuildSetting, transport_bytes: Bytes) -> Vec<u8> {
    let ip_bytes = match (setting.src_ip, setting.dst_ip) {
        (IpAddr::V4(src_ipv4), IpAddr::V4(dst_ipv4)) => Ipv4PacketBuilder::new()
            .source(src_ipv4)
            .destination(dst_ipv4)
            .ttl(setting.hop_limit)
            .protocol(IpNextProtocol::Tcp)
            .payload(transport_bytes)
            .to_bytes(),
        (IpAddr::V6(src_ipv6), IpAddr::V6(dst_ipv6)) => Ipv6PacketBuilder::new()
            .source(src_ipv6)
            .destination(dst_ipv6)
            .hop_limit(setting.hop_limit)
            .next_header(IpNextProtocol::Tcp)
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

/// Build TCP SYN packet with default options
pub fn build_tcp_syn_packet(setting: PacketBuildSetting) -> Vec<u8> {
    let tcp_bytes = TcpPacketBuilder::new(setting.src_ip, setting.dst_ip)
        .source(setting.src_port)
        .destination(setting.dst_port)
        .flags(TcpFlags::SYN)
        .window(65535)
        .options(vec![
            TcpOptionPacket::mss(1460),
            TcpOptionPacket::nop(),
            TcpOptionPacket::wscale(6),
            TcpOptionPacket::nop(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::timestamp(u32::MAX, u32::MIN),
            TcpOptionPacket::sack_perm(),
        ])
        .to_bytes();
    wrap_transport_packet(&setting, tcp_bytes)
}

#[allow(dead_code)]
pub fn build_ip_next_tcp_syn_packet(setting: PacketBuildSetting) -> Vec<u8> {
    TcpPacketBuilder::new(setting.src_ip, setting.dst_ip)
        .source(setting.src_port)
        .destination(setting.dst_port)
        .flags(TcpFlags::SYN)
        .window(65535)
        .options(vec![
            TcpOptionPacket::mss(1460),
            TcpOptionPacket::nop(),
            TcpOptionPacket::wscale(6),
            TcpOptionPacket::nop(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::timestamp(u32::MAX, u32::MIN),
            TcpOptionPacket::sack_perm(),
        ])
        .to_bytes()
        .to_vec()
}
