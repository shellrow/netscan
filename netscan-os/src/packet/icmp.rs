use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpType, MutableIcmpPacket};
use pnet::packet::Packet;

pub const ICMPV4_HEADER_LEN: usize =
    pnet::packet::icmp::echo_request::MutableEchoRequestPacket::minimum_packet_size();

pub fn build_icmp_echo_packet(icmp_packet: &mut MutableEchoRequestPacket, icmp_type: IcmpType) {
    icmp_packet.set_icmp_type(icmp_type);
    icmp_packet.set_sequence_number(rand::random::<u16>());
    icmp_packet.set_identifier(rand::random::<u16>());
    let icmp_check_sum = pnet::packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}

pub fn build_icmp_packet(icmp_packet: &mut MutableIcmpPacket, icmp_type: IcmpType) {
    icmp_packet.set_icmp_type(icmp_type);
    let icmp_check_sum = pnet::packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}
