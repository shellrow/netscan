use std::net::Ipv4Addr;
pub const IPV4_HEADER_LEN: usize = 20;

#[allow(dead_code)]
pub enum IpNextHeaderProtocol {
    Tcp,
    Udp,
    Icmp
}

pub fn build_ipv4_packet(ipv4_packet: &mut pnet::packet::ipv4::MutableIpv4Packet, src_ip_addr: Ipv4Addr, dst_ip_addr: Ipv4Addr, next_protocol: IpNextHeaderProtocol){
    ipv4_packet.set_header_length(69);
    ipv4_packet.set_total_length(52);
    ipv4_packet.set_source(src_ip_addr);
    ipv4_packet.set_destination(dst_ip_addr);
    ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_version(4);
    ipv4_packet.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
    match next_protocol {
        IpNextHeaderProtocol::Tcp => {
            ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
        },
        IpNextHeaderProtocol::Udp => {
            ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        }
        IpNextHeaderProtocol::Icmp => {
            ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);
        }
    }
    let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);
}
