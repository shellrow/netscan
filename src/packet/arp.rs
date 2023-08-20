use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use std::net::Ipv4Addr;

#[allow(dead_code)]
pub const ARP_HEADER_LEN: usize = 28;

#[allow(dead_code)]
pub fn build_arp_packet(
    arp_packet: &mut MutableArpPacket,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) {
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(dst_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(dst_ip);
}
