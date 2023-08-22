use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::Packet;

pub const ICMPV6_HEADER_SIZE: usize =
    pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::minimum_packet_size();

pub fn build_icmpv6_packet(icmp_packet: &mut MutableEchoRequestPacket) {
    icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
    icmp_packet.set_identifier(rand::random::<u16>());
    icmp_packet.set_sequence_number(rand::random::<u16>());
    let icmp_check_sum = pnet::packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}
