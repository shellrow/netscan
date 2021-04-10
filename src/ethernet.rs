pub const ETHERNET_HEADER_LEN: usize = 14;

#[allow(dead_code)]
pub enum EtherType {
    Arp,
    Ipv4,
    Ipv6
}

pub fn build_ethernet_packet(eth_packet: &mut pnet::packet::ethernet::MutableEthernetPacket
    , src_mac_addr: pnet::datalink::MacAddr
    , dst_mac_addr: pnet::datalink::MacAddr
    , ether_type: EtherType){
    eth_packet.set_source(src_mac_addr);
    eth_packet.set_destination(dst_mac_addr);
    match ether_type {
        EtherType::Arp => {
            eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);
        },
        EtherType::Ipv4 => {
            eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);
        },
        EtherType::Ipv6 => {
            eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv6);
        }
    }
}
