use pnet_packet::Packet;
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{IcmpType, MutableIcmpPacket};

pub fn build_icmp_echo_packet(icmp_packet:&mut MutableEchoRequestPacket, icmp_type: IcmpType) {
    icmp_packet.set_icmp_type(icmp_type);
    icmp_packet.set_sequence_number(rand::random::<u16>());
    icmp_packet.set_identifier(rand::random::<u16>());
    let icmp_check_sum = pnet_packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}

pub fn build_icmp_packet(icmp_packet:&mut MutableIcmpPacket, icmp_type: IcmpType) {
    icmp_packet.set_icmp_type(icmp_type);
    let icmp_check_sum = pnet_packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}
