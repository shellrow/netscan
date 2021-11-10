use pnet_packet::ethernet::{MutableEthernetPacket, EtherType, EtherTypes};
use pnet_datalink::MacAddr;

pub const ETHERNET_HEADER_LEN: usize = 14;

#[allow(dead_code)]
pub fn build_ethernet_packet(eth_packet: &mut MutableEthernetPacket, src_mac: MacAddr, dst_mac: MacAddr, ether_type: EtherType) {
    eth_packet.set_source(src_mac);
    eth_packet.set_destination(dst_mac);
    match ether_type {
        EtherTypes::Arp => {
            eth_packet.set_ethertype(EtherTypes::Arp);
        },
        EtherTypes::Ipv4 => {
            eth_packet.set_ethertype(EtherTypes::Ipv4);
        },
        EtherTypes::Ipv6 => {
            eth_packet.set_ethertype(EtherTypes::Ipv6);
        },
        _ => {
            //ToDo
        }
    }
}
