use super::socket::AsyncSocket;
use crate::host::{HostInfo, PortInfo, PortStatus};
use crate::packet;
use crate::result::ScanResult;
use crate::setting::{ScanSetting, ScanType};
use async_io::{Async, Timer};
use futures::executor::ThreadPool;
use futures::stream::{self, StreamExt};
use futures::task::SpawnExt;
use futures_lite::{future::FutureExt, io};
use np_listener::packet::TcpIpFingerprint;
use np_listener::packet::tcp::TcpFlagKind;
use pnet::packet::Packet;
use socket2::{Protocol, SockAddr, Type};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use np_listener::option::PacketCaptureOptions;
use np_listener::listener::Listner;
use np_listener::packet::ip::IpNextLevelProtocol;

async fn build_icmpv4_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; packet::icmp::ICMPV4_HEADER_SIZE];
    let mut icmp_packet =
        pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    packet::icmp::build_icmp_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

async fn build_icmpv6_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; packet::icmpv6::ICMPV6_HEADER_SIZE];
    let mut icmp_packet =
        pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    packet::icmpv6::build_icmpv6_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

async fn build_tcp_syn_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Vec<u8> {
    let mut vec: Vec<u8> = if src_ip.is_ipv4() { vec![0; 66] } else { vec![0; 86] };
    let mut tcp_packet = if src_ip.is_ipv4() {
        pnet::packet::tcp::MutableTcpPacket::new(
            &mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
        )
        .unwrap()
    }else{
        pnet::packet::tcp::MutableTcpPacket::new(
            &mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)..],
        )
        .unwrap()
    };
    packet::tcp::build_tcp_packet(&mut tcp_packet, src_ip, src_port, dst_ip, dst_port);
    tcp_packet.packet().to_vec()
}

async fn build_udp_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = if src_ip.is_ipv4() { vec![0; 42] } else { vec![0; 62] };
    let mut udp_packet = if src_ip.is_ipv4() {
        pnet::packet::udp::MutableUdpPacket::new(
            &mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
        )
        .unwrap()
    } else {
        pnet::packet::udp::MutableUdpPacket::new(
            &mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)..],
        )
        .unwrap()
    };
    packet::udp::build_udp_packet(&mut udp_packet, src_ip, src_port, dst_ip, dst_port);
    udp_packet.packet().to_vec()
}

async fn send_icmp_echo_packets(
    socket: &AsyncSocket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.hosts_concurrency,
        |dst| {
            let socket_addr = SocketAddr::new(dst.ip_addr, 0);
            let sock_addr = SockAddr::from(socket_addr);
            async move {
                let mut icmp_packet: Vec<u8> = if scan_setting.src_ip.is_ipv4() {
                    build_icmpv4_echo_packet().await
                }
                else {
                    build_icmpv6_echo_packet().await
                };
                match socket.send_to(&mut icmp_packet, &sock_addr).await {
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
            }
        },
    );
    fut_host.await;
}

async fn send_tcp_syn_packets(
    socket: &AsyncSocket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.hosts_concurrency,
        |dst| async move {
            let fut_port = stream::iter(dst.get_ports()).for_each_concurrent(
                scan_setting.ports_concurrency,
                |port| {
                    let dst = dst.clone();
                    let socket_addr = SocketAddr::new(dst.ip_addr, port);
                    let sock_addr = SockAddr::from(socket_addr);
                    async move {
                        let mut tcp_packet: Vec<u8> = build_tcp_syn_packet(
                            scan_setting.src_ip,
                            scan_setting.src_port,
                            dst.ip_addr,
                            port,
                        )
                        .await;
                        match socket.send_to(&mut tcp_packet, &sock_addr).await {
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
                    }
                },
            );
            fut_port.await;
        },
    );
    fut_host.await;
}

#[allow(dead_code)]
async fn send_udp_packets(
    socket: &AsyncSocket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.hosts_concurrency,
        |dst| async move {
            let fut_port = stream::iter(dst.get_ports()).for_each_concurrent(
                scan_setting.ports_concurrency,
                |port| {
                    let dst = dst.clone();
                    let socket_addr = SocketAddr::new(dst.ip_addr, port);
                    let sock_addr = SockAddr::from(socket_addr);
                    async move {
                        let mut udp_packet: Vec<u8> = build_udp_packet(
                            scan_setting.src_ip,
                            scan_setting.src_port,
                            dst.ip_addr,
                            port,
                        )
                        .await;
                        match socket.send_to(&mut udp_packet, &sock_addr).await {
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
                    }
                },
            );
            fut_port.await;
        },
    );
    fut_host.await;
}

async fn send_udp_ping_packets(
    socket: &AsyncSocket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.hosts_concurrency,
        |dst| async move {
            let socket_addr = SocketAddr::new(dst.ip_addr, packet::udp::UDP_BASE_DST_PORT);
            let sock_addr = SockAddr::from(socket_addr);
            let mut udp_packet: Vec<u8> = build_udp_packet(
                scan_setting.src_ip,
                scan_setting.src_port,
                dst.ip_addr,
                packet::udp::UDP_BASE_DST_PORT,
            )
            .await;
            match socket.send_to(&mut udp_packet, &sock_addr).await {
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
        },
    );
    fut_host.await;
}

async fn try_connect_ports(
    concurrency: usize,
    dst: HostInfo,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> HostInfo {
    let (channel_tx, channel_rx) = mpsc::channel();
    let conn_timeout = Duration::from_millis(200);
    let fut = stream::iter(dst.get_ports()).for_each_concurrent(concurrency, |port| {
        let dst = dst.clone();
        let channel_tx = channel_tx.clone();
        async move {
            let socket_addr = SocketAddr::new(dst.ip_addr, port);
            let stream = Async::<TcpStream>::connect(socket_addr)
                .or(async {
                    Timer::after(conn_timeout).await;
                    Err(io::ErrorKind::TimedOut.into())
                })
                .await;
            match stream {
                Ok(_) => {
                    let _ = channel_tx.send(port);
                }
                _ => {}
            }
            match ptx.lock() {
                Ok(lr) => match lr.send(socket_addr) {
                    Ok(_) => {}
                    Err(_) => {}
                },
                Err(_) => {}
            }
        }
    });
    fut.await;
    drop(channel_tx);
    let mut open_ports: Vec<PortInfo> = vec![];
    loop {
        match channel_rx.recv() {
            Ok(port) => {
                open_ports.push(PortInfo {
                    port: port,
                    status: PortStatus::Open,
                });
            }
            Err(_) => {
                break;
            }
        }
    }
    HostInfo {
        ip_addr: dst.ip_addr,
        host_name: dst.host_name,
        ttl: dst.ttl,
        ports: open_ports,
    }
}

async fn send_connect_requests(
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    let _results: Vec<HostInfo> = stream::iter(scan_setting.targets.clone().into_iter())
        .map(|dst| try_connect_ports(scan_setting.ports_concurrency, dst, ptx))
        .buffer_unordered(scan_setting.hosts_concurrency)
        .collect()
        .await;
}

async fn send_ping_packet(
    socket: &AsyncSocket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            send_icmp_echo_packets(socket, scan_setting, ptx).await;
        }
        ScanType::TcpPingScan => {
            send_tcp_syn_packets(socket, scan_setting, ptx).await;
        }
        ScanType::UdpPingScan => {
            send_udp_ping_packets(socket, scan_setting, ptx).await;
        }
        _ => {
            return;
        }
    }
}

async fn send_tcp_packets(
    socket: &AsyncSocket,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            send_tcp_syn_packets(socket, scan_setting, ptx).await;
        }
        _ => {
            return;
        }
    }
}

pub(crate) async fn scan_hosts(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let socket = match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            match scan_setting.src_ip {
                IpAddr::V4(_) => {
                    AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::ICMPV4).unwrap()
                }
                IpAddr::V6(_) => {
                    AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::ICMPV6).unwrap()
                }
            }
        }
        ScanType::TcpPingScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::TCP).unwrap()
        }
        ScanType::UdpPingScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::UDP).unwrap()
        }
        _ => return ScanResult::new(),
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
    let fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>> = Arc::new(Mutex::new(vec![]));
    let receive_fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>> = Arc::clone(&fingerprints);

    let executor = ThreadPool::new().unwrap();
    let future = async move {
        listener.start();
        for f in listener.get_fingerprints() {
            receive_fingerprints.lock().unwrap().push(f);
        }
    };
    let lisner_handle: futures::future::RemoteHandle<()> = executor.spawn_with_handle(future).unwrap();
    
    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(1));

    // Send probe packets
    send_ping_packet(&socket, &scan_setting, ptx).await;
    thread::sleep(scan_setting.wait_time);
    *stop_handle.lock().unwrap() = true;

    // Wait for listener to complete task
    lisner_handle.await;

    // Parse fingerprints and store results
    let mut result: ScanResult = ScanResult::new();
    for f in fingerprints.lock().unwrap().iter() {
        let mut ports: Vec<PortInfo> = vec![];
        match scan_setting.scan_type {
            ScanType::IcmpPingScan => {
                if f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Icmp && f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Icmpv6 {
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
                    }else if tcp_fingerprint.flags.contains(&TcpFlagKind::Rst) && tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) {
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
                if f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Icmp && f.ip_fingerprint.next_level_protocol != IpNextLevelProtocol::Icmpv6 {
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
            result.fingerprints.push(f.clone());
        }
    }
    return result;
}

pub(crate) async fn scan_ports(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let socket = match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::TCP).unwrap()
        }
        ScanType::TcpConnectScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::STREAM, Protocol::TCP).unwrap()
        }
        _ => return ScanResult::new(),
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

    let executor = ThreadPool::new().unwrap();
    let future = async move {
        listener.start();
        for f in listener.get_fingerprints() {
            receive_fingerprints.lock().unwrap().push(f);
        }
    };
    let lisner_handle: futures::future::RemoteHandle<()> = executor.spawn_with_handle(future).unwrap();

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(1));

    match scan_setting.scan_type {
        ScanType::TcpConnectScan => {
            send_connect_requests(&scan_setting, ptx).await;
        }
        _ => {
            send_tcp_packets(&socket, &scan_setting, ptx).await;
        }
    }
    
    thread::sleep(scan_setting.wait_time);
    *stop_handle.lock().unwrap() = true;

    // Wait for listener to complete task
    lisner_handle.await;

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
            }else if tcp_fingerprint.flags.contains(&TcpFlagKind::Rst) && tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) {
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
        result.fingerprints.push(f.clone());
        socket_set.insert(f.source);
    }
    return result;
}
