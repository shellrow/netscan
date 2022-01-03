use std::net::Ipv4Addr;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::{MutableIpv4Packet, Ipv4Flags};

#[doc(hidden)]
pub const IPV4_HEADER_LEN: usize = 20;
#[doc(hidden)]
pub const IPV4_TOTAL_LEN: u16 = 52;

#[doc(hidden)]
#[cfg(not(target_family="windows"))]
pub const IPV4_TOTAL_LEN_TCP: u16 = 64;

#[doc(hidden)]
#[cfg(target_family="windows")]
pub const IPV4_TOTAL_LEN_TCP: u16 = 52;

pub const IPV4_DEFAULT_ID: u16 = 4162;

pub const IPV4_DEFAULT_TTL: u8 = 64;

#[doc(hidden)]
pub fn build_ipv4_packet(ipv4_packet: &mut MutableIpv4Packet, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, next_protocol: IpNextHeaderProtocol) {
    ipv4_packet.set_header_length(69);
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
        },
        IpNextHeaderProtocols::Udp => {
            ipv4_packet.set_total_length(IPV4_TOTAL_LEN);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        },
        IpNextHeaderProtocols::Icmp => {
            ipv4_packet.set_total_length(IPV4_TOTAL_LEN);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        },
        _ => {},
    }
    let checksum = pnet_packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);
}
