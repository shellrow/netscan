use crate::host::{HostInfo, PortInfo, PortStatus};
use crate::packet;
use crate::result::ScanResult;
use crate::setting::ScanSetting;
use crate::setting::ScanType;
use np_listener::listener::Listner;
use np_listener::option::PacketCaptureOptions;
use np_listener::packet::TcpIpFingerprint;
use np_listener::packet::ip::IpNextLevelProtocol;
use np_listener::packet::tcp::TcpFlagKind;
use pnet_packet::Packet;
use rayon::prelude::*;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn build_icmpv4_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; 16];
    let mut icmp_packet =
        pnet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    packet::icmp::build_icmp_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

fn build_tcp_syn_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut tcp_packet = pnet_packet::tcp::MutableTcpPacket::new(
        &mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
    packet::tcp::build_tcp_packet(&mut tcp_packet, src_ip, src_port, dst_ip, dst_port);
    tcp_packet.packet().to_vec()
}

fn build_udp_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut udp_packet = pnet_packet::udp::MutableUdpPacket::new(
        &mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
    packet::udp::build_udp_packet(&mut udp_packet, src_ip, src_port, dst_ip, dst_port);
    udp_packet.packet().to_vec()
}

fn send_icmp_echo_packets(
    socket: &Socket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    for dst in scan_setting.targets.clone() {
        let socket_addr = SocketAddr::new(dst.ip_addr, 0);
        let sock_addr = SockAddr::from(socket_addr);
        let mut icmp_packet: Vec<u8> = build_icmpv4_echo_packet();
        match socket.send_to(&mut icmp_packet, &sock_addr) {
            Ok(_) => {}
            Err(_) => {}
        }
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

fn send_tcp_syn_packets(
    socket: &Socket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    for dst in scan_setting.targets.clone() {
        for port in dst.get_ports() {
            let socket_addr = SocketAddr::new(dst.ip_addr, port);
            let sock_addr = SockAddr::from(socket_addr);
            let mut tcp_packet: Vec<u8> = build_tcp_syn_packet(
                scan_setting.src_ip,
                scan_setting.src_port,
                dst.ip_addr,
                port,
            );
            match socket.send_to(&mut tcp_packet, &sock_addr) {
                Ok(_) => {}
                Err(_) => {}
            }
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

fn send_udp_packets(
    socket: &Socket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    for dst in scan_setting.targets.clone() {
        for port in dst.get_ports() {
            let socket_addr = SocketAddr::new(dst.ip_addr, port);
            let sock_addr = SockAddr::from(socket_addr);
            let mut udp_packet: Vec<u8> = build_udp_packet(
                scan_setting.src_ip,
                scan_setting.src_port,
                dst.ip_addr,
                port,
            );
            match socket.send_to(&mut udp_packet, &sock_addr) {
                Ok(_) => {}
                Err(_) => {}
            }
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

fn run_connect_scan(
    scan_setting: ScanSetting
) -> ScanResult {
    let port_scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let start_time = Instant::now();
    let conn_timeout = Duration::from_millis(200);
    for dst in scan_setting.targets.clone() {
        let ip_addr: IpAddr = dst.ip_addr;
        dst.get_ports().into_par_iter().for_each(|port| {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
            let socket_addr: SocketAddr = SocketAddr::new(ip_addr, port);
            let sock_addr = SockAddr::from(socket_addr);
            match socket.connect_timeout(&sock_addr, conn_timeout) {
                Ok(_) => {
                    let port_info = PortInfo {
                        port: socket_addr.port(),
                        status: PortStatus::Open,
                    };
                    // Avoid deadlock.
                    let mut exists: bool = false;
                    for host in port_scan_result
                        .lock()
                        .unwrap()
                        .hosts
                        .iter_mut()
                    {
                        if host.ip_addr == socket_addr.ip() {
                            host.ports.push(port_info);
                            exists = true;
                        }
                    }
                    if !exists {
                        let mut host_info = HostInfo::new();
                        host_info.ip_addr = socket_addr.ip();
                        host_info.host_name = scan_setting
                            .ip_map
                            .get(&socket_addr.ip())
                            .unwrap_or(&String::new())
                            .to_string();
                        host_info.ttl = socket.ttl().unwrap_or(0) as u8;
                        host_info.ports.push(port_info);
                        port_scan_result
                            .lock()
                            .unwrap()
                            .hosts
                            .push(host_info);
                    }
                }
                Err(_) => {}
            }
            // Cancel scan if timeout
            if Instant::now().duration_since(start_time) > scan_setting.timeout {
                return;
            }
        });
    }
    let mut result: ScanResult = port_scan_result.lock().unwrap().clone();
    result.scan_time = Instant::now().duration_since(start_time);
    return result;
}

fn send_ping_packet(
    socket: &Socket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            send_icmp_echo_packets(socket, scan_setting, ptx);
        }
        ScanType::TcpPingScan => {
            send_tcp_syn_packets(socket, scan_setting, ptx);
        }
        ScanType::UdpPingScan => {
            send_udp_packets(socket, scan_setting, ptx);
        }
        _ => {
            return;
        }
    }
}

fn send_tcp_packets(
    socket: &Socket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            send_tcp_syn_packets(socket, scan_setting, ptx);
        }
        _ => {
            return;
        }
    }
}

pub(crate) fn scan_hosts(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let socket = match scan_setting.src_ip {
        IpAddr::V4(_) => match scan_setting.scan_type {
            ScanType::IcmpPingScan => {
                Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap()
            }
            ScanType::TcpPingScan => {
                Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).unwrap()
            }
            ScanType::UdpPingScan => {
                Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)).unwrap()
            }
            _ => return ScanResult::new(),
        },
        IpAddr::V6(_) => match scan_setting.scan_type {
            ScanType::IcmpPingScan => {
                Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap()
            }
            ScanType::TcpPingScan => {
                Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP)).unwrap()
            }
            ScanType::UdpPingScan => {
                Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP)).unwrap()
            }
            _ => return ScanResult::new(),
        },
    };
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
    };
    for target in scan_setting.targets.clone() {
        capture_options.src_ips.insert(target.ip_addr);
    }
    match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            capture_options.ip_protocols.insert(IpNextLevelProtocol::Icmp);
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
        }
        _ => {}
    }
    let listener: Listner = Listner::new(capture_options);
    let stop_handle = listener.get_stop_handle();
    let fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>> = Arc::new(Mutex::new(vec![]));
    let receive_fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>> = Arc::clone(&fingerprints);

    let handler = thread::spawn(move || {
        listener.start();
        for f in listener.get_fingerprints() {
            receive_fingerprints.lock().unwrap().push(f);
        }
    });
    
    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(1));

    // Send probe packets
    send_ping_packet(&socket, &scan_setting, ptx);
    thread::sleep(scan_setting.wait_time);
    *stop_handle.lock().unwrap() = true;

    // Wait for listener to stop
    handler.join().unwrap();

    // Parse fingerprints and store results
    let mut result: ScanResult = ScanResult::new();
    for f in fingerprints.lock().unwrap().iter() {
        let mut ports: Vec<PortInfo> = vec![];
        match scan_setting.scan_type {
            ScanType::IcmpPingScan => {
                if f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Icmp {
                    continue;
                }
            }
            ScanType::TcpPingScan => {
                if f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Tcp {
                    continue;
                }
                if let Some(tcp_fingerprint) = &f.tcp_fingerprint {
                    if tcp_fingerprint.flags.contains(&TcpFlagKind::Syn) && tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) {
                        let port_info: PortInfo = PortInfo {
                            port: tcp_fingerprint.source_port,
                            status: PortStatus::Open,
                        };
                        ports.push(port_info);
                    }else if tcp_fingerprint.flags.contains(&TcpFlagKind::Rst) || tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) {
                        let port_info: PortInfo = PortInfo {
                            port: tcp_fingerprint.source_port,
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
                if f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Udp {
                    continue;
                }
            }
            _ => {}
        }
        let host_info: HostInfo = HostInfo {
            ip_addr: f.ip_fingerprint.source_ip,
            host_name: scan_setting.ip_map.get(&f.ip_fingerprint.source_ip).unwrap_or(&String::new()).clone(),
            ttl: f.ip_fingerprint.ttl,
            ports: ports,
        };
        if !result.hosts.contains(&host_info) {
            result.hosts.push(host_info);
        }
    }
    return result;
}

pub(crate) fn scan_ports(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    match scan_setting.scan_type {
        ScanType::TcpConnectScan => {
            return run_connect_scan(scan_setting);
        }
        _ => {}
    }
    let socket = match scan_setting.src_ip {
        IpAddr::V4(_) => match scan_setting.scan_type {
            ScanType::TcpSynScan => {
                Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).unwrap()
            }
            ScanType::TcpConnectScan => {
                Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap()
            }
            _ => return ScanResult::new(),
        },
        IpAddr::V6(_) => match scan_setting.scan_type {
            ScanType::TcpSynScan => {
                Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP)).unwrap()
            }
            ScanType::TcpConnectScan => {
                Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).unwrap()
            }
            _ => return ScanResult::new(),
        },
    };
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
    let fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>> = Arc::new(Mutex::new(vec![]));
    let receive_fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>> = Arc::clone(&fingerprints);

    let handler = thread::spawn(move || {
        listener.start();
        for f in listener.get_fingerprints() {
            receive_fingerprints.lock().unwrap().push(f);
        }
    });

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(1));

    send_tcp_packets(&socket, &scan_setting, ptx);
    thread::sleep(scan_setting.wait_time);
    *stop_handle.lock().unwrap() = true;

    // Wait for listener to stop
    handler.join().unwrap();

    // Parse fingerprints and store results
    let mut result: ScanResult = ScanResult::new();
    let mut socket_set: HashSet<SocketAddr> = HashSet::new();
    for f in fingerprints.lock().unwrap().iter() {
        match scan_setting.scan_type {
            ScanType::TcpSynScan => {
                if f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Tcp {
                    continue;
                }
            }
            ScanType::TcpConnectScan => {
                if f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Tcp {
                    continue;
                }
            }
            _ => {}
        }
        if socket_set.contains(&f.source) {
            continue;
        }
        let port_info: PortInfo = if let Some(tcp_fingerprint) = &f.tcp_fingerprint {
            if tcp_fingerprint.flags.contains(&TcpFlagKind::Syn) && tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) {
                let port_info: PortInfo = PortInfo {
                    port: tcp_fingerprint.source_port,
                    status: PortStatus::Open,
                };
                port_info
            }else if tcp_fingerprint.flags.contains(&TcpFlagKind::Rst) || tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) {
                let port_info: PortInfo = PortInfo {
                    port: tcp_fingerprint.source_port,
                    status: PortStatus::Closed,
                };
                port_info
            }else {
                continue;
            }
        }else{
            continue;
        };
        let mut exists: bool = false;
        for host in result.hosts.iter_mut()
        {
            if host.ip_addr == f.ip_fingerprint.source_ip {
                host.ports.push(port_info);
                exists = true;     
            }
        }
        if !exists {
            let host_info: HostInfo = HostInfo {
                ip_addr: f.ip_fingerprint.source_ip,
                host_name: scan_setting.ip_map.get(&f.ip_fingerprint.source_ip).unwrap_or(&String::new()).clone(),
                ttl: f.ip_fingerprint.ttl,
                ports: vec![port_info],
            };
            result.hosts.push(host_info);
        }
        socket_set.insert(f.source);
    }
    return result;
}
