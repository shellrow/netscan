use std::net::IpAddr;
use pnet_packet::tcp::{MutableTcpPacket, TcpOption, TcpFlags};
use crate::setting::ProbeType;

pub enum TcpProbeOption {
    Syn1,
    Syn2,
    Syn3,
    Syn4,
    Syn5,
    Syn6,
    Ecn
}

impl TcpProbeOption {
    pub fn get_tcp_options(&self) -> Vec<TcpOption> {
        match *self {
            TcpProbeOption::Syn1 => vec![TcpOption::wscale(10), TcpOption::nop(), TcpOption::mss(1460), TcpOption::timestamp(u32::MAX, u32::MIN), TcpOption::sack_perm()],
            TcpProbeOption::Syn2 => vec![TcpOption::mss(1400), TcpOption::wscale(0), TcpOption::sack_perm(), TcpOption::timestamp(u32::MAX, u32::MIN)],
            TcpProbeOption::Syn3 => vec![TcpOption::timestamp(u32::MAX, u32::MIN), TcpOption::nop(), TcpOption::nop(), TcpOption::wscale(5),TcpOption::nop(), TcpOption::mss(640)],
            TcpProbeOption::Syn4 => vec![TcpOption::sack_perm(), TcpOption::timestamp(u32::MAX, u32::MIN), TcpOption::wscale(10)],
            TcpProbeOption::Syn5 => vec![TcpOption::mss(536), TcpOption::sack_perm(), TcpOption::timestamp(u32::MAX, u32::MIN), TcpOption::wscale(10)],
            TcpProbeOption::Syn6 => vec![TcpOption::mss(265), TcpOption::sack_perm(), TcpOption::timestamp(u32::MAX, u32::MIN)],
            TcpProbeOption::Ecn => vec![TcpOption::wscale(10), TcpOption::nop(), TcpOption::mss(1460), TcpOption::sack_perm(), TcpOption::nop(), TcpOption::nop()],
        }
    }
}

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
