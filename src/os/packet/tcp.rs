use std::net::IpAddr;
use pnet_packet::tcp::{MutableTcpPacket, TcpOption, TcpFlags};
use crate::os::setting::ProbeType;

#[doc(hidden)]
#[cfg(not(target_family="windows"))]
pub fn build_tcp_packet(tcp_packet:&mut MutableTcpPacket, src_ip: IpAddr, src_port:u16, dst_ip: IpAddr, dst_port:u16, probe_type: ProbeType) {
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_window(65535);
    tcp_packet.set_data_offset(11);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_sequence(0);
    let ts = TcpOption::timestamp(u32::MAX, u32::MIN);
    tcp_packet.set_options(&vec![TcpOption::mss(1460), TcpOption::nop(), TcpOption::wscale(6),TcpOption::nop(), TcpOption::nop(), ts, TcpOption::sack_perm()]);
    match probe_type {
        ProbeType::TcpEcnProbe => {
            tcp_packet.set_flags(TcpFlags::CWR|TcpFlags::ECE|TcpFlags::SYN);
        },
        _ => {
            tcp_packet.set_flags(TcpFlags::SYN);
        },
    }
    match src_ip {
        IpAddr::V4(src_ip) => {
            match dst_ip {
                IpAddr::V4(dst_ip) => {
                    let checksum = pnet_packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                    tcp_packet.set_checksum(checksum);
                },
                IpAddr::V6(_) => {},
            }
        },
        IpAddr::V6(src_ip) => {
            match dst_ip {
                IpAddr::V4(_) => {},
                IpAddr::V6(dst_ip) => {
                    let checksum = pnet_packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                    tcp_packet.set_checksum(checksum);
                },
            }
        },
    }
}

#[doc(hidden)]
#[cfg(target_family="windows")]
pub fn build_tcp_packet(tcp_packet:&mut MutableTcpPacket, src_ip: IpAddr, src_port:u16, dst_ip: IpAddr, dst_port:u16, probe_type: ProbeType) {
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_sequence(0);
    tcp_packet.set_options(&vec![TcpOption::mss(1460), TcpOption::nop(), TcpOption::wscale(8), TcpOption::nop(), TcpOption::nop(), TcpOption::sack_perm()]);
    match probe_type {
        ProbeType::TcpEcnProbe => {
            tcp_packet.set_flags(TcpFlags::CWR|TcpFlags::ECE|TcpFlags::SYN);
        },
        _ => {
            tcp_packet.set_flags(TcpFlags::SYN);
        },
    }
    match src_ip {
        IpAddr::V4(src_ip) => {
            match dst_ip {
                IpAddr::V4(dst_ip) => {
                    let checksum = pnet_packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                    tcp_packet.set_checksum(checksum);
                },
                IpAddr::V6(_) => {},
            }
        },
        IpAddr::V6(src_ip) => {
            match dst_ip {
                IpAddr::V4(_) => {},
                IpAddr::V6(dst_ip) => {
                    let checksum = pnet_packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                    tcp_packet.set_checksum(checksum);
                },
            }
        },
    }
}
