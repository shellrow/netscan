use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use std::net::Ipv4Addr;

pub const IPV4_HEADER_LEN: usize = pnet::packet::ipv4::MutableIpv4Packet::minimum_packet_size();
pub const IPV4_HEADER_BYTES: usize = 4;

#[cfg(not(target_family = "windows"))]
pub const IPV4_TOTAL_LEN_TCP: u16 = 64;
#[cfg(target_family = "windows")]
pub const IPV4_TOTAL_LEN_TCP: u16 = 52;

pub const IPV4_TOTAL_LEN_UDP: u16 = 28;
pub const IPV4_TOTAL_LEN_ICMP: u16 = 28;
pub const IPV4_DEFAULT_ID: u16 = 4162;
pub const IPV4_DEFAULT_TTL: u8 = 64;

pub fn build_ipv4_packet(
    ipv4_packet: &mut MutableIpv4Packet,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    next_protocol: IpNextHeaderProtocol,
) {
    ipv4_packet.set_header_length((IPV4_HEADER_LEN / IPV4_HEADER_BYTES) as u8);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);
    //ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_identification(IPV4_DEFAULT_ID);
    ipv4_packet.set_ttl(IPV4_DEFAULT_TTL);
    ipv4_packet.set_version(4);
    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
    match next_protocol {
        IpNextHeaderProtocols::Tcp => {
            ipv4_packet.set_total_length(IPV4_TOTAL_LEN_TCP);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        }
        IpNextHeaderProtocols::Udp => {
            ipv4_packet.set_total_length(IPV4_TOTAL_LEN_UDP);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        }
        IpNextHeaderProtocols::Icmp => {
            ipv4_packet.set_total_length(IPV4_TOTAL_LEN_ICMP);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        }
        _ => {}
    }
    let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);
}
