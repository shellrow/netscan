use std::net::Ipv6Addr;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::{Icmpv6Type, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::Packet;

pub const ICMPV6_HEADER_LEN: usize =
    pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::minimum_packet_size();

pub fn build_icmpv6_echo_packet(icmp_packet: &mut MutableEchoRequestPacket, src_ip: Ipv6Addr, dst_ip: Ipv6Addr) {
    icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
    icmp_packet.set_identifier(rand::random::<u16>());
    icmp_packet.set_sequence_number(rand::random::<u16>());
    let icmpv6_packet = pnet::packet::icmpv6::Icmpv6Packet::new(icmp_packet.packet()).unwrap();
    let icmpv6_checksum = pnet::packet::icmpv6::checksum(&icmpv6_packet, &src_ip, &dst_ip);
    //let icmp_check_sum = pnet::packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmpv6_checksum);
}

pub fn build_icmpv6_packet(icmp_packet: &mut MutableIcmpv6Packet, src_ip: Ipv6Addr, dst_ip: Ipv6Addr, icmp_type: Icmpv6Type) {
    icmp_packet.set_icmpv6_type(icmp_type);
    let icmpv6_packet = pnet::packet::icmpv6::Icmpv6Packet::new(icmp_packet.packet()).unwrap();
    let icmpv6_checksum = pnet::packet::icmpv6::checksum(&icmpv6_packet, &src_ip, &dst_ip);
    //let icmp_check_sum = pnet::packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmpv6_checksum);
}
