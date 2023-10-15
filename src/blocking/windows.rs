use crate::host::{HostInfo, PortInfo, PortStatus};
use crate::result::ScanResult;
use crate::setting::ScanSetting;
use crate::setting::ScanType;
use crate::setting::LISTENER_WAIT_TIME_MILLIS;
use cross_socket::packet::PacketFrame;
use cross_socket::pcap::PacketCaptureOptions;
use cross_socket::pcap::listener::Listner;
use rayon::prelude::*;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use cross_socket::{socket::DataLinkSocket, packet::{builder::PacketBuilder, ethernet::{EthernetPacketBuilder, EtherType}, ipv4::Ipv4PacketBuilder, ip::IpNextLevelProtocol, tcp::{TcpPacketBuilder, TcpFlag, TcpOption}, ipv6::Ipv6PacketBuilder, icmp::IcmpPacketBuilder, icmpv6::Icmpv6PacketBuilder}};
use cross_socket::packet::udp::UDP_BASE_DST_PORT;

fn send_tcp_syn_packets_datalink(socket: &mut DataLinkSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: scan_setting.src_mac.clone(),
        dst_mac: scan_setting.dst_mac.clone(),
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

fn send_icmp_echo_packets_datalink(socket: &mut DataLinkSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
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

fn send_udp_ping_packets_datalink(socket: &mut DataLinkSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
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

fn send_ping_packets_datalink(socket: &mut DataLinkSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
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

fn send_tcp_connect_requests(scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let start_time = Instant::now();
    let conn_timeout = Duration::from_millis(200);
    for dst in scan_setting.targets.clone() {
        let ip_addr: IpAddr = dst.ip_addr;
        dst.get_ports().into_par_iter().for_each(|port| {
            let socket = if ip_addr.is_ipv4() {
                socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).unwrap()
            }else {
                socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).unwrap()
            };
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

pub(crate) fn scan_hosts(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(interface) => interface,
        None => return ScanResult::new(),
    };
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();

    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: scan_setting.if_index,
        interface_name: scan_setting.if_name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        duration: scan_setting.timeout,
        promiscuous: false,
        store: true,
        store_limit: u32::MAX,
        receive_undefined: false,
        use_tun: scan_setting.use_tun,
        loopback: scan_setting.loopback,
    };
    for target in scan_setting.targets.clone() {
        capture_options.src_ips.insert(target.ip_addr);
    }
    match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Icmp);
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Icmpv6);
        }
        ScanType::TcpPingScan => {
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Tcp);
            for target in scan_setting.targets.clone() {
                for port in target.get_ports() {
                    capture_options.src_ports.insert(port);
                }
            }
        }
        ScanType::UdpPingScan => {
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Udp);
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Icmp);
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Icmpv6);
        }
        _ => {}
    }
    let listener: Listner = Listner::new(capture_options);
    let stop_handle = listener.get_stop_handle();
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&packets);

    let handler = thread::spawn(move || {
        listener.start();
        for p in listener.get_packets() {
            receive_packets.lock().unwrap().push(p);
        }
    });

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(LISTENER_WAIT_TIME_MILLIS));

    // Send probe packets
    send_ping_packets_datalink(&mut socket, &scan_setting, ptx);
    thread::sleep(scan_setting.wait_time);
    *stop_handle.lock().unwrap() = true;

    // Wait for listener to stop
    handler.join().unwrap();

    // Parse packets and store results
    let mut result: ScanResult = ScanResult::new();
    for p in packets.lock().unwrap().iter() {
        let mut ports: Vec<PortInfo> = vec![];
        match scan_setting.scan_type {
            ScanType::IcmpPingScan => {
                if p.icmp_packet.is_none() && p.icmpv6_packet.is_none() {
                    continue;
                }
            }
            ScanType::TcpPingScan => {
                if p.tcp_packet.is_none() {
                    continue;
                }
                if let Some(tcp_packet) = &p.tcp_packet {
                    if tcp_packet.flags.contains(&TcpFlag::Syn) && tcp_packet.flags.contains(&TcpFlag::Ack) {
                        let port_info: PortInfo = PortInfo {
                            port: tcp_packet.source,
                            status: PortStatus::Open,
                        };
                        ports.push(port_info);
                    }else if tcp_packet.flags.contains(&TcpFlag::Rst) && tcp_packet.flags.contains(&TcpFlag::Ack) {
                        let port_info: PortInfo = PortInfo {
                            port: tcp_packet.source,
                            status: PortStatus::Closed,
                        };
                        ports.push(port_info);
                    }else {
                        continue;
                    }
                }else{
                    continue;
                }
            }
            ScanType::UdpPingScan => {
                if p.icmp_packet.is_none() && p.icmpv6_packet.is_none() {
                    continue;
                }
            }
            _ => {}
        }
        let host_info: HostInfo = if let Some(ipv4_packet) = &p.ipv4_packet {
            HostInfo {
                ip_addr: IpAddr::V4(ipv4_packet.source),
                host_name: scan_setting.ip_map.get(&IpAddr::V4(ipv4_packet.source)).unwrap_or(&String::new()).clone(),
                ttl: ipv4_packet.ttl,
                ports: ports,
            }
        }else if let Some(ipv6_packet) = &p.ipv6_packet {
            HostInfo {
                ip_addr: IpAddr::V6(ipv6_packet.source),
                host_name: scan_setting.ip_map.get(&IpAddr::V6(ipv6_packet.source)).unwrap_or(&String::new()).clone(),
                ttl: ipv6_packet.hop_limit,
                ports: ports,
            }
        }else{
            continue;
        };
        if !result.hosts.contains(&host_info) {
            result.hosts.push(host_info);
            result.fingerprints.push(p.clone());
        }
    }
    return result;
}

pub(crate) fn scan_ports(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(interface) => interface,
        None => return ScanResult::new(),
    };
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();

    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: scan_setting.if_index,
        interface_name: scan_setting.if_name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        duration: scan_setting.timeout,
        promiscuous: false,
        store: true,
        store_limit: u32::MAX,
        receive_undefined: false,
        use_tun: scan_setting.use_tun,
        loopback: scan_setting.loopback,
    };
    for target in scan_setting.targets.clone() {
        capture_options.src_ips.insert(target.ip_addr);
        capture_options.src_ports.extend(target.get_ports());
    }
    match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Tcp);
        }
        ScanType::TcpConnectScan => {
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Tcp);
        }
        _ => {}
    }
    let listener: Listner = Listner::new(capture_options);
    let stop_handle = listener.get_stop_handle();
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&packets);

    let handler = thread::spawn(move || {
        listener.start();
        for p in listener.get_packets() {
            receive_packets.lock().unwrap().push(p);
        }
    });

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(LISTENER_WAIT_TIME_MILLIS));

    match scan_setting.scan_type {
        ScanType::TcpConnectScan => {
            send_tcp_connect_requests(&scan_setting, ptx);
        }
        _ => {
            send_tcp_syn_packets_datalink(&mut socket, &scan_setting, ptx);
        }
    }
    thread::sleep(scan_setting.wait_time);
    *stop_handle.lock().unwrap() = true;

    // Wait for listener to stop
    handler.join().unwrap();

    // Parse packets and store results
    let mut result: ScanResult = ScanResult::new();
    let mut socket_set: HashSet<SocketAddr> = HashSet::new();
    for p in packets.lock().unwrap().iter() {
        if p.ipv4_packet.is_none() && p.ipv6_packet.is_none() {
            continue;
        }
        let ip_addr: IpAddr = {
            if let Some(ipv4_packet) = &p.ipv4_packet {
                if let Some(tcp_packet) = &p.tcp_packet {
                    if socket_set.contains(&SocketAddr::new(IpAddr::V4(ipv4_packet.source), tcp_packet.source)) {
                        continue;
                    }
                }else{
                    continue;
                }
                IpAddr::V4(ipv4_packet.source) 
            }else if let Some(ipv6_packet) = &p.ipv6_packet {
                if let Some(tcp_packet) = &p.tcp_packet {
                    if socket_set.contains(&SocketAddr::new(IpAddr::V6(ipv6_packet.source), tcp_packet.source)) {
                        continue;
                    }
                }else {
                    continue;
                }
                IpAddr::V6(ipv6_packet.source)
            }else {
                continue;
            }
        };
        let port_info: PortInfo = if let Some(tcp_packet) = &p.tcp_packet {
            if tcp_packet.flags.contains(&TcpFlag::Syn) && tcp_packet.flags.contains(&TcpFlag::Ack) {
                PortInfo {
                    port: tcp_packet.source,
                    status: PortStatus::Open,
                }
            }else if tcp_packet.flags.contains(&TcpFlag::Rst) && tcp_packet.flags.contains(&TcpFlag::Ack) {
                PortInfo {
                    port: tcp_packet.source,
                    status: PortStatus::Closed,
                }
            }else {
                continue;
            }
        }else{
            continue;
        };
        let mut exists: bool = false;
        for host in result.hosts.iter_mut()
        {
            if host.ip_addr == ip_addr {
                host.ports.push(port_info);
                exists = true;     
            }
        }
        if !exists {
            let host_info: HostInfo = HostInfo {
                ip_addr: ip_addr,
                host_name: scan_setting.ip_map.get(&ip_addr).unwrap_or(&String::new()).clone(),
                ttl: if let Some(ipv4_packet) = &p.ipv4_packet {
                    ipv4_packet.ttl
                }else if let Some(ipv6_packet) = &p.ipv6_packet {
                    ipv6_packet.hop_limit
                }else{
                    0
                },
                ports: vec![port_info],
            };
            result.hosts.push(host_info);
        }
        result.fingerprints.push(p.clone());
        socket_set.insert(SocketAddr::new(ip_addr, port_info.port));
    }
    return result;
}
