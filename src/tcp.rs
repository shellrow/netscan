use std::net::Ipv4Addr;
use super::port::PortScanType;

pub fn build_tcp_packet(tcp_packet:&mut pnet::packet::tcp::MutableTcpPacket, src_ip_addr: Ipv4Addr, src_port:u16, dst_ip_addr: Ipv4Addr, dst_port:u16, scan_type:&PortScanType){
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_sequence(0);
    tcp_packet.set_options(&[pnet::packet::tcp::TcpOption::mss(1460)
    , pnet::packet::tcp::TcpOption::sack_perm()
    , pnet::packet::tcp::TcpOption::nop()
    , pnet::packet::tcp::TcpOption::nop()
    , pnet::packet::tcp::TcpOption::wscale(7)]);
    match scan_type {
        PortScanType::SynScan => {
            tcp_packet.set_flags(pnet::packet::tcp::TcpFlags::SYN);
        },
        PortScanType::FinScan => {
            tcp_packet.set_flags(pnet::packet::tcp::TcpFlags::FIN);
        },
        PortScanType::XmasScan => {
            tcp_packet.set_flags(pnet::packet::tcp::TcpFlags::FIN | pnet::packet::tcp::TcpFlags::URG | pnet::packet::tcp::TcpFlags::PSH);
        },
        PortScanType::NullScan => {
            tcp_packet.set_flags(0);
        },
        _ => {
            tcp_packet.set_flags(pnet::packet::tcp::TcpFlags::SYN);
        },
    }
    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip_addr, &dst_ip_addr);
    tcp_packet.set_checksum(checksum);
}
