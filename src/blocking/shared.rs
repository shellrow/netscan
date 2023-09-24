use std::{net::{SocketAddr, IpAddr}, sync::{mpsc::Sender, Mutex, Arc}, thread, time::{Instant, Duration}};
use rayon::prelude::*;
use cross_socket::{socket::{Socket, DataLinkSocket}, packet::{builder::PacketBuilder, ethernet::{EthernetPacketBuilder, EtherType}, ipv4::Ipv4PacketBuilder, ip::IpNextLevelProtocol, tcp::{TcpPacketBuilder, TcpFlag, TcpOption}, ipv6::Ipv6PacketBuilder, icmp::IcmpPacketBuilder, icmpv6::Icmpv6PacketBuilder}};
use cross_socket::datalink::MacAddr;
use cross_socket::packet::udp::UDP_BASE_DST_PORT;

use crate::setting::{ScanSetting, ScanType};

pub(crate) fn send_tcp_syn_packets(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    for target in &scan_setting.targets {
        for port in &target.ports {
            let dst_socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, port.port);
            let mut tcp_packet_builder = TcpPacketBuilder::new(
                SocketAddr::new(scan_setting.src_ip, scan_setting.src_port),
                dst_socket_addr,
            );
            tcp_packet_builder.flags = vec![TcpFlag::Syn];
            tcp_packet_builder.options = vec![
                TcpOption::mss(1460),
                TcpOption::sack_perm(),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ];
            let packet_bytes: Vec<u8> = tcp_packet_builder.build();
            
            match socket.send_to(&packet_bytes, dst_socket_addr) {
                Ok(_) => {}
                Err(_) => {}
            }
            match ptx.lock() {
                Ok(lr) => match lr.send(dst_socket_addr) {
                    Ok(_) => {}
                    Err(_) => {}
                },
                Err(_) => {}
            }
            thread::sleep(scan_setting.send_rate);
        }
    }
}

pub(crate) fn send_icmp_echo_packets(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    for target in &scan_setting.targets {
        let dst_socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, 0);
        match scan_setting.src_ip {
            IpAddr::V4(src_ipv4) => match target.ip_addr {
                IpAddr::V4(dst_ipv4) => {
                    let mut icmp_packet_builder = IcmpPacketBuilder::new(
                        src_ipv4,
                        dst_ipv4,
                    );
                    icmp_packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::EchoRequest;
                    let packet_bytes: Vec<u8> = icmp_packet_builder.build();
                    
                    match socket.send_to(&packet_bytes, dst_socket_addr) {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                },
                IpAddr::V6(_) => {},
            },
            IpAddr::V6(src_ipv6) => match target.ip_addr {
                IpAddr::V4(_) => {},
                IpAddr::V6(dst_ipv6) => {
                    let icmpv6_packet_builder = Icmpv6PacketBuilder{
                        src_ip: src_ipv6,
                        dst_ip: dst_ipv6,
                        icmpv6_type: cross_socket::packet::icmpv6::Icmpv6Type::EchoRequest,
                        sequence_number: None,
                        identifier: None,
                    };
                    let packet_bytes: Vec<u8> = icmpv6_packet_builder.build();
                    match socket.send_to(&packet_bytes, dst_socket_addr) {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                },
            },
        }
        match ptx.lock() {
            Ok(lr) => match lr.send(dst_socket_addr) {
                Ok(_) => {}
                Err(_) => {}
            },
            Err(_) => {}
        }
        thread::sleep(scan_setting.send_rate);
    }
}

pub(crate) fn send_udp_ping_packets(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    for target in &scan_setting.targets {
        let dst_socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, UDP_BASE_DST_PORT);
        let udp_packet_builder = cross_socket::packet::udp::UdpPacketBuilder::new(
            SocketAddr::new(scan_setting.src_ip, scan_setting.src_port),
            dst_socket_addr,
        );
        let packet_bytes: Vec<u8> = udp_packet_builder.build();
        
        match socket.send_to(&packet_bytes, dst_socket_addr) {
            Ok(_) => {}
            Err(_) => {}
        }
        match ptx.lock() {
            Ok(lr) => match lr.send(dst_socket_addr) {
                Ok(_) => {}
                Err(_) => {}
            },
            Err(_) => {}
        }
        thread::sleep(scan_setting.send_rate);
    }
}

pub(crate) fn send_tcp_syn_packets_datalink(socket: &mut DataLinkSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: MacAddr::new(scan_setting.src_mac.clone()),
        dst_mac: MacAddr::new(scan_setting.dst_mac.clone()),
        ether_type: if scan_setting.src_ip.is_ipv4() {
            EtherType::Ipv4
        } else {
            EtherType::Ipv6
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);

    for target in &scan_setting.targets {
        match scan_setting.src_ip {
            IpAddr::V4(src_ipv4) => match target.ip_addr {
                IpAddr::V4(dst_ipv4) => {
                    let ipv4_packet_builder = Ipv4PacketBuilder::new(
                        src_ipv4,
                        dst_ipv4,
                        IpNextLevelProtocol::Tcp,
                    );
                    packet_builder.set_ipv4(ipv4_packet_builder);
                },
                IpAddr::V6(_) => {},
            },
            IpAddr::V6(src_ipv6) => match target.ip_addr {
                IpAddr::V4(_) => {},
                IpAddr::V6(dst_ipv6) => {
                    let ipv6_packet_builder = Ipv6PacketBuilder::new(
                        src_ipv6,
                        dst_ipv6,
                        IpNextLevelProtocol::Tcp,
                    );
                    packet_builder.set_ipv6(ipv6_packet_builder);
                },
            },
        }
        for port in &target.ports {
            let mut tcp_packet_builder = TcpPacketBuilder::new(
                SocketAddr::new(scan_setting.src_ip, scan_setting.src_port),
                SocketAddr::new(target.ip_addr, port.port),
            );
            tcp_packet_builder.flags = vec![TcpFlag::Syn];
            tcp_packet_builder.options = vec![
                TcpOption::mss(1460),
                TcpOption::sack_perm(),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ];
            packet_builder.set_tcp(tcp_packet_builder);

            let packet_bytes: Vec<u8> = packet_builder.packet();

            match socket.send_to(&packet_bytes) {
                Ok(_) => {}
                Err(_) => {}
            }
            let socket_addr = SocketAddr::new(target.ip_addr, port.port);
            match ptx.lock() {
                Ok(lr) => match lr.send(socket_addr) {
                    Ok(_) => {}
                    Err(_) => {}
                },
                Err(_) => {}
            }
            thread::sleep(scan_setting.send_rate);
        }
    }
}

pub(crate) fn send_icmp_echo_packets_datalink(socket: &mut DataLinkSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: socket.interface.mac_addr.clone().unwrap(),
        dst_mac: socket.interface.gateway.clone().unwrap().mac_addr,
        ether_type: if scan_setting.src_ip.is_ipv4() {
            EtherType::Ipv4
        } else {
            EtherType::Ipv6
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    for target in &scan_setting.targets {
        match scan_setting.src_ip {
            IpAddr::V4(src_ipv4) => match target.ip_addr {
                IpAddr::V4(dst_ipv4) => {
                    let ipv4_packet_builder = Ipv4PacketBuilder::new(
                        src_ipv4,
                        dst_ipv4,
                        IpNextLevelProtocol::Icmp,
                    );
                    packet_builder.set_ipv4(ipv4_packet_builder);
                    let mut icmp_packet_builder = IcmpPacketBuilder::new(
                        src_ipv4,
                        dst_ipv4,
                    );
                    icmp_packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::EchoRequest;
                    packet_builder.set_icmp(icmp_packet_builder);
                },
                IpAddr::V6(_) => {},
            },
            IpAddr::V6(src_ipv6) => match target.ip_addr {
                IpAddr::V4(_) => {},
                IpAddr::V6(dst_ipv6) => {
                    let ipv6_packet_builder = Ipv6PacketBuilder::new(
                        src_ipv6,
                        dst_ipv6,
                        IpNextLevelProtocol::Icmpv6,
                    );
                    packet_builder.set_ipv6(ipv6_packet_builder);
                    let icmpv6_packet_builder = Icmpv6PacketBuilder{
                        src_ip: src_ipv6,
                        dst_ip: dst_ipv6,
                        icmpv6_type: cross_socket::packet::icmpv6::Icmpv6Type::EchoRequest,
                        sequence_number: None,
                        identifier: None,
                    };
                    packet_builder.set_icmpv6(icmpv6_packet_builder);
                },
            },
        }

        let packet_bytes: Vec<u8> = packet_builder.packet();

        match socket.send_to(&packet_bytes) {
            Ok(_) => {}
            Err(_) => {}
        }
        let socket_addr = SocketAddr::new(target.ip_addr, 0);
        match ptx.lock() {
            Ok(lr) => match lr.send(socket_addr) {
                Ok(_) => {}
                Err(_) => {}
            },
            Err(_) => {}
        }
        thread::sleep(scan_setting.send_rate);
    }
}

pub(crate) fn send_udp_ping_packets_datalink(socket: &mut DataLinkSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: socket.interface.mac_addr.clone().unwrap(),
        dst_mac: socket.interface.gateway.clone().unwrap().mac_addr,
        ether_type: EtherType::Ipv4,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    for target in &scan_setting.targets {
        match scan_setting.src_ip {
            IpAddr::V4(src_ipv4) => match target.ip_addr {
                IpAddr::V4(dst_ipv4) => {
                    let ipv4_packet_builder = Ipv4PacketBuilder::new(
                        src_ipv4,
                        dst_ipv4,
                        IpNextLevelProtocol::Udp,
                    );
                    packet_builder.set_ipv4(ipv4_packet_builder);
                },
                IpAddr::V6(_) => {},
            },
            IpAddr::V6(src_ipv6) => match target.ip_addr {
                IpAddr::V4(_) => {},
                IpAddr::V6(dst_ipv6) => {
                    let ipv6_packet_builder = Ipv6PacketBuilder::new(
                        src_ipv6,
                        dst_ipv6,
                        IpNextLevelProtocol::Udp,
                    );
                    packet_builder.set_ipv6(ipv6_packet_builder);
                },
            },
        }
        let udp_packet_builder = cross_socket::packet::udp::UdpPacketBuilder::new(
            SocketAddr::new(scan_setting.src_ip, scan_setting.src_port),
            SocketAddr::new(target.ip_addr, UDP_BASE_DST_PORT),
        );
        packet_builder.set_udp(udp_packet_builder);

        let packet_bytes: Vec<u8> = packet_builder.packet();

        match socket.send_to(&packet_bytes) {
            Ok(_) => {}
            Err(_) => {}
        }
        let socket_addr = SocketAddr::new(target.ip_addr, 0);
        match ptx.lock() {
            Ok(lr) => match lr.send(socket_addr) {
                Ok(_) => {}
                Err(_) => {}
            },
            Err(_) => {}
        }
        thread::sleep(scan_setting.send_rate);
    }
}

pub(crate) fn send_ping_packets(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            send_icmp_echo_packets(socket, scan_setting, ptx);
        }
        ScanType::TcpPingScan => {
            send_tcp_syn_packets(socket, scan_setting, ptx);
        }
        ScanType::UdpPingScan => {
            send_udp_ping_packets(socket, scan_setting, ptx);
        }
        _ => {
            return;
        }
    }
}

pub(crate) fn send_ping_packets_datalink(socket: &mut DataLinkSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            send_icmp_echo_packets_datalink(socket, scan_setting, ptx);
        }
        ScanType::TcpPingScan => {
            send_tcp_syn_packets_datalink(socket, scan_setting, ptx);
        }
        ScanType::UdpPingScan => {
            send_udp_ping_packets_datalink(socket, scan_setting, ptx);
        }
        _ => {
            return;
        }
    }
}

pub(crate) fn send_tcp_connect_requests(scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let start_time = Instant::now();
    let conn_timeout = Duration::from_millis(200);
    for dst in scan_setting.targets.clone() {
        let ip_addr: IpAddr = dst.ip_addr;
        dst.get_ports().into_par_iter().for_each(|port| {
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).unwrap();
            let socket_addr: SocketAddr = SocketAddr::new(ip_addr, port);
            let sock_addr = socket2::SockAddr::from(socket_addr);
            match socket.connect_timeout(&sock_addr, conn_timeout) {
                Ok(_) => {},
                Err(_) => {}
            }
            match ptx.lock() {
                Ok(lr) => match lr.send(socket_addr) {
                    Ok(_) => {}
                    Err(_) => {}
                },
                Err(_) => {}
            }
            // Cancel scan if timeout
            if Instant::now().duration_since(start_time) > scan_setting.timeout {
                return;
            }
        });
    }
}