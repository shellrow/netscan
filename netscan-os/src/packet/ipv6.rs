use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;

pub const IPV6_HEADER_LEN: usize = pnet::packet::ipv6::MutableIpv6Packet::minimum_packet_size();
pub const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;
pub const IPV6_TOTAL_LEN_TCP: u16 = 44;
pub const IPV6_TOTAL_LEN_UDP: u16 = 8;
pub const IPV6_TOTAL_LEN_ICMPV6: u16 = 8;

pub fn build_ipv6_packet(
    ipv6_packet: &mut MutableIpv6Packet,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    next_protocol: IpNextHeaderProtocol,
) {
    ipv6_packet.set_source(src_ip);
    ipv6_packet.set_destination(dst_ip);
    ipv6_packet.set_version(6);
    ipv6_packet.set_hop_limit(IPV6_DEFAULT_HOP_LIMIT);
    match next_protocol {
        IpNextHeaderProtocols::Tcp => {
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Tcp);
            ipv6_packet.set_payload_length(IPV6_TOTAL_LEN_TCP);
        }
        IpNextHeaderProtocols::Udp => {
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Udp);
            ipv6_packet.set_payload_length(IPV6_TOTAL_LEN_UDP);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
            ipv6_packet.set_payload_length(IPV6_TOTAL_LEN_ICMPV6);
        }
        _ => {}
    }
}
