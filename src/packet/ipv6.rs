use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;

pub const IPV6_HEADER_LEN: usize = pnet::packet::ipv6::MutableIpv6Packet::minimum_packet_size();

pub fn build_ipv6_packet(
    ipv6_packet: &mut MutableIpv6Packet,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    next_protocol: IpNextHeaderProtocol,
) {
    ipv6_packet.set_source(src_ip);
    ipv6_packet.set_destination(dst_ip);
    ipv6_packet.set_version(6);
    ipv6_packet.set_hop_limit(64);
    match next_protocol {
        IpNextHeaderProtocols::Tcp => {
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Tcp);
            ipv6_packet.set_payload_length(32);
        }
        IpNextHeaderProtocols::Udp => {
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Udp);
            ipv6_packet.set_payload_length(8);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
            ipv6_packet.set_payload_length(8);
        }
        _ => {}
    }
}
