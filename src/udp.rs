/* use std::net::Ipv4Addr;
use super::port::PortScanType;

pub fn build_udp_packet(udp_packet:&mut pnet::packet::udp::MutableUdpPacket, src_ip_addr: Ipv4Addr, src_port:u16, dst_ip_addr: Ipv4Addr, dst_port:u16, _scan_type:&PortScanType){
    udp_packet.set_length(8);
    udp_packet.set_source(src_port);
    udp_packet.set_destination(dst_port);
    let checksum = pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip_addr, &dst_ip_addr);
    udp_packet.set_checksum(checksum);
} */
