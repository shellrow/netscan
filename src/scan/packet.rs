use super::setting::HostScanType;
use crate::config::{DEFAULT_HOP_LIMIT, DEFAULT_LOCAL_TCP_PORT, DEFAULT_LOCAL_UDP_PORT};
use crate::host::Host;
use crate::packet::setting::PacketBuildSetting;
use netdev::Interface;
use nex::net::ip::is_global_ipv6;
use std::net::IpAddr;

pub(crate) fn build_hostscan_packet(
    interface: &Interface,
    target_host: &Host,
    scan_type: &HostScanType,
    ip_packet: bool,
) -> Vec<u8> {
    let mut build_setting = PacketBuildSetting::new();
    if let Some(mac_addr) = &interface.mac_addr {
        build_setting.src_mac = *mac_addr;
    }
    if let Some(gateway) = &interface.gateway {
        build_setting.dst_mac = gateway.mac_addr;
    }
    match target_host.ip_addr {
        IpAddr::V4(ipv4_addr) => {
            interface.ipv4.iter().for_each(|ipv4| {
                build_setting.src_ip = IpAddr::V4(ipv4.addr());
            });
            build_setting.dst_ip = IpAddr::V4(ipv4_addr);
        }
        IpAddr::V6(ipv6_addr) => {
            if is_global_ipv6(&ipv6_addr) {
                interface.ipv6.iter().for_each(|ipv6| {
                    if is_global_ipv6(&ipv6.addr()) {
                        build_setting.src_ip = IpAddr::V6(ipv6.addr());
                    }
                });
            } else {
                interface.ipv6.iter().for_each(|ipv6| {
                    build_setting.src_ip = IpAddr::V6(ipv6.addr());
                });
            }
            build_setting.dst_ip = IpAddr::V6(ipv6_addr);
        }
    }
    if target_host.ports.len() > 0 {
        build_setting.dst_port = target_host.ports[0].number;
    }
    build_setting.hop_limit = DEFAULT_HOP_LIMIT;
    if ip_packet || interface.is_tun() || interface.is_loopback() {
        build_setting.ip_packet = true;
    }
    match scan_type {
        HostScanType::IcmpPingScan => crate::packet::icmp::build_icmp_packet(build_setting),
        HostScanType::TcpPingScan => {
            build_setting.src_port = DEFAULT_LOCAL_TCP_PORT;
            crate::packet::tcp::build_tcp_syn_packet(build_setting)
        }
        HostScanType::UdpPingScan => {
            build_setting.src_port = DEFAULT_LOCAL_UDP_PORT;
            crate::packet::udp::build_udp_packet(build_setting)
        }
    }
}

pub(crate) fn build_hostscan_ip_next_packet(
    interface: &Interface,
    target_host: &Host,
    scan_type: &HostScanType,
) -> Vec<u8> {
    let mut build_setting = PacketBuildSetting::new();
    if let Some(mac_addr) = &interface.mac_addr {
        build_setting.src_mac = *mac_addr;
    }
    if let Some(gateway) = &interface.gateway {
        build_setting.dst_mac = gateway.mac_addr;
    }
    match target_host.ip_addr {
        IpAddr::V4(ipv4_addr) => {
            interface.ipv4.iter().for_each(|ipv4| {
                build_setting.src_ip = IpAddr::V4(ipv4.addr());
            });
            build_setting.dst_ip = IpAddr::V4(ipv4_addr);
        }
        IpAddr::V6(ipv6_addr) => {
            if is_global_ipv6(&ipv6_addr) {
                interface.ipv6.iter().for_each(|ipv6| {
                    if is_global_ipv6(&ipv6.addr()) {
                        build_setting.src_ip = IpAddr::V6(ipv6.addr());
                    }
                });
            } else {
                interface.ipv6.iter().for_each(|ipv6| {
                    build_setting.src_ip = IpAddr::V6(ipv6.addr());
                });
            }
            build_setting.dst_ip = IpAddr::V6(ipv6_addr);
        }
    }
    if target_host.ports.len() > 0 {
        build_setting.dst_port = target_host.ports[0].number;
    }
    build_setting.hop_limit = DEFAULT_HOP_LIMIT;
    if interface.is_tun() || interface.is_loopback() {
        build_setting.ip_packet = true;
    }
    match scan_type {
        HostScanType::IcmpPingScan => crate::packet::icmp::build_ip_next_icmp_packet(build_setting),
        HostScanType::TcpPingScan => {
            build_setting.src_port = DEFAULT_LOCAL_TCP_PORT;
            crate::packet::tcp::build_ip_next_tcp_syn_packet(build_setting)
        }
        HostScanType::UdpPingScan => {
            build_setting.src_port = DEFAULT_LOCAL_UDP_PORT;
            crate::packet::udp::build_ip_next_udp_packet(build_setting)
        }
    }
}

pub(crate) fn build_portscan_packet(
    interface: &Interface,
    target_ip_addr: IpAddr,
    target_port: u16,
    ip_packet: bool,
) -> Vec<u8> {
    let mut build_setting = PacketBuildSetting::new();
    if let Some(mac_addr) = &interface.mac_addr {
        build_setting.src_mac = *mac_addr;
    }
    if let Some(gateway) = &interface.gateway {
        build_setting.dst_mac = gateway.mac_addr;
    }
    match target_ip_addr {
        IpAddr::V4(ipv4_addr) => {
            interface.ipv4.iter().for_each(|ipv4| {
                build_setting.src_ip = IpAddr::V4(ipv4.addr());
            });
            build_setting.dst_ip = IpAddr::V4(ipv4_addr);
        }
        IpAddr::V6(ipv6_addr) => {
            if is_global_ipv6(&ipv6_addr) {
                interface.ipv6.iter().for_each(|ipv6| {
                    if is_global_ipv6(&ipv6.addr()) {
                        build_setting.src_ip = IpAddr::V6(ipv6.addr());
                    }
                });
            } else {
                interface.ipv6.iter().for_each(|ipv6| {
                    build_setting.src_ip = IpAddr::V6(ipv6.addr());
                });
            }
            build_setting.dst_ip = IpAddr::V6(ipv6_addr);
        }
    }
    build_setting.dst_port = target_port;
    build_setting.hop_limit = DEFAULT_HOP_LIMIT;
    if ip_packet || interface.is_tun() || interface.is_loopback() {
        build_setting.ip_packet = true;
    }
    build_setting.src_port = DEFAULT_LOCAL_TCP_PORT;
    crate::packet::tcp::build_tcp_syn_packet(build_setting)
}

pub(crate) fn build_portscan_ip_next_packet(
    interface: &Interface,
    target_ip_addr: IpAddr,
    target_port: u16,
) -> Vec<u8> {
    let mut build_setting = PacketBuildSetting::new();
    if let Some(mac_addr) = &interface.mac_addr {
        build_setting.src_mac = *mac_addr;
    }
    if let Some(gateway) = &interface.gateway {
        build_setting.dst_mac = gateway.mac_addr;
    }
    match target_ip_addr {
        IpAddr::V4(ipv4_addr) => {
            interface.ipv4.iter().for_each(|ipv4| {
                build_setting.src_ip = IpAddr::V4(ipv4.addr());
            });
            build_setting.dst_ip = IpAddr::V4(ipv4_addr);
        }
        IpAddr::V6(ipv6_addr) => {
            if is_global_ipv6(&ipv6_addr) {
                interface.ipv6.iter().for_each(|ipv6| {
                    if is_global_ipv6(&ipv6.addr()) {
                        build_setting.src_ip = IpAddr::V6(ipv6.addr());
                    }
                });
            } else {
                interface.ipv6.iter().for_each(|ipv6| {
                    build_setting.src_ip = IpAddr::V6(ipv6.addr());
                });
            }
            build_setting.dst_ip = IpAddr::V6(ipv6_addr);
        }
    }
    build_setting.dst_port = target_port;
    build_setting.hop_limit = DEFAULT_HOP_LIMIT;
    if interface.is_tun() || interface.is_loopback() {
        build_setting.ip_packet = true;
    }
    build_setting.src_port = DEFAULT_LOCAL_TCP_PORT;
    crate::packet::tcp::build_ip_next_tcp_syn_packet(build_setting)
}
