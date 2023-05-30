use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv6::MutableIpv6Packet;
use std::net::Ipv6Addr;

#[allow(dead_code)]
pub const IPV6_HEADER_LEN: usize = 40;

pub const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;

#[allow(dead_code)]
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
        }
        IpNextHeaderProtocols::Udp => {
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Udp);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        }
        _ => {}
    }
}
