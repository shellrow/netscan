use super::socket::AsyncSocket;
use crate::async_io::receiver;
use crate::host::{HostInfo, PortInfo, PortStatus};
use crate::packet;
use crate::result::{HostScanResult, PortScanResult, ScanResult, ScanStatus};
use crate::setting::{ScanSetting, ScanType};
use async_io::{Async, Timer};
use futures::executor::ThreadPool;
use futures::stream::{self, StreamExt};
use futures::task::SpawnExt;
use futures_lite::{future::FutureExt, io};
use np_listener::packet::TcpIpFingerprint;
use np_listener::packet::tcp::TcpFlagKind;
use pnet_packet::Packet;
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
    let mut buf = vec![0; 16];
    let mut icmp_packet =
        pnet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    packet::icmp::build_icmp_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

async fn build_tcp_syn_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut tcp_packet = pnet_packet::tcp::MutableTcpPacket::new(
        &mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
    packet::tcp::build_tcp_packet(&mut tcp_packet, src_ip, src_port, dst_ip, dst_port);
    tcp_packet.packet().to_vec()
}

async fn build_udp_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut udp_packet = pnet_packet::udp::MutableUdpPacket::new(
        &mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
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
                let mut icmp_packet: Vec<u8> = build_icmpv4_echo_packet().await;
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

async fn run_connect_scan(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> PortScanResult {
    let results: Vec<HostInfo> = stream::iter(scan_setting.targets.clone().into_iter())
        .map(|dst| try_connect_ports(scan_setting.ports_concurrency, dst, ptx))
        .buffer_unordered(scan_setting.hosts_concurrency)
        .collect()
        .await;
    PortScanResult {
        results: results,
        scan_time: Duration::from_millis(0),
        scan_status: ScanStatus::Ready,
    }
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
            send_udp_packets(socket, scan_setting, ptx).await;
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
) -> HostScanResult {
    let socket = match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::ICMPV4).unwrap()
        }
        ScanType::TcpPingScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::TCP).unwrap()
        }
        ScanType::UdpPingScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::UDP).unwrap()
        }
        _ => return HostScanResult::new(),
    };

    let executor = ThreadPool::new().unwrap();

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
    let mut result: HostScanResult = HostScanResult::new();
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

pub(crate) async fn scan_ports(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> PortScanResult {
    match scan_setting.scan_type {
        ScanType::TcpConnectScan => {
            let scan_result = run_connect_scan(scan_setting, ptx).await;
            return scan_result;
        }
        _ => {}
    }
    let socket = match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::TCP).unwrap()
        }
        ScanType::TcpConnectScan => {
            AsyncSocket::new(scan_setting.src_ip, Type::STREAM, Protocol::TCP).unwrap()
        }
        _ => return PortScanResult::new(),
    };
    let interfaces = pnet_datalink::interfaces();
    let interface = match interfaces
        .into_iter()
        .filter(|interface: &pnet_datalink::NetworkInterface| {
            interface.index == scan_setting.if_index
        })
        .next()
    {
        Some(interface) => interface,
        None => return PortScanResult::new(),
    };
    let config = pnet_datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet_datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut _tx, mut rx) = match pnet_datalink::channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let receive_result: Arc<Mutex<ScanResult>> = Arc::clone(&scan_result);
    let receive_stop: Arc<Mutex<bool>> = Arc::clone(&stop);
    let receive_setting: ScanSetting = scan_setting.clone();
    let executor = ThreadPool::new().unwrap();
    let future = async move {
        receiver::receive_packets(&mut rx, receive_setting, &receive_result, &receive_stop).await;
    };
    executor.spawn(future).unwrap();
    send_tcp_packets(&socket, &scan_setting, ptx).await;
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
    let result: PortScanResult = scan_result.lock().unwrap().port_scan_result.clone();
    return result;
}
