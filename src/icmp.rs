use pnet::packet::Packet;

pub fn build_icmp_packet(icmp_packet:&mut pnet::packet::icmp::echo_request::MutableEchoRequestPacket){
    icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
    icmp_packet.set_sequence_number(rand::random::<u16>());
    icmp_packet.set_identifier(rand::random::<u16>());
    let icmp_check_sum = pnet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}
