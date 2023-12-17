use crate::host::{HostInfo, PortInfo, PortStatus};
use crate::result::ScanResult;
use crate::setting::{ScanSetting, ScanType};
use crate::setting::LISTENER_WAIT_TIME_MILLIS;
use async_io::{Async, Timer};
use crate::pcap::PacketFrame;
use crate::pcap::PacketCaptureOptions;
use crate::pcap::listener::Listner;
use xenet::socket::{AsyncSocket, SocketOption, IpVersion, SocketType};
use futures::executor::ThreadPool;
use futures::stream::{self, StreamExt};
use futures::task::SpawnExt;
use futures_lite::{future::FutureExt, io};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::packet::tcp::{TcpFlags, TcpOption};
use xenet::util::packet_builder::{tcp::TcpPacketBuilder, icmp::IcmpPacketBuilder, icmpv6::Icmpv6PacketBuilder};

const UDP_BASE_DST_PORT: u16 = 33435;

async fn send_tcp_syn_packets(socket: &AsyncSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.hosts_concurrency,
        |dst| async move {
            let fut_port = stream::iter(dst.get_ports()).for_each_concurrent(
                scan_setting.ports_concurrency,
                |port| {
                    let target = dst.clone();
                    let dst_socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, port);
                    async move {
                        let mut tcp_packet_builder = TcpPacketBuilder::new(
                            SocketAddr::new(scan_setting.src_ip, scan_setting.src_port),
                            dst_socket_addr,
                        );
                        tcp_packet_builder.flags = TcpFlags::SYN;
                        if scan_setting.minimize_packet {
                            tcp_packet_builder.options = vec![
                                TcpOption::mss(1460),
                                TcpOption::sack_perm(),
                                TcpOption::nop(),
                                TcpOption::nop(),
                                TcpOption::wscale(7),
                            ];
                        }else{
                            tcp_packet_builder.window = 65535;
                            tcp_packet_builder.options = vec![
                                        TcpOption::mss(1460),
                                        TcpOption::nop(),
                                        TcpOption::wscale(6),
                                        TcpOption::nop(),
                                        TcpOption::nop(),
                                        TcpOption::timestamp(u32::MAX, u32::MIN),
                                        TcpOption::sack_perm(),
                                    ];
                        }
                        
                        let packet_bytes: Vec<u8> = tcp_packet_builder.build();
                        
                        match socket.send_to(&packet_bytes, dst_socket_addr).await {
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
                        //thread::sleep(scan_setting.send_rate);
                    }
                },
            );
            fut_port.await;
        },
    );
    fut_host.await;
}

async fn send_icmp_echo_packets(socket: &AsyncSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.hosts_concurrency,
        |target| {
            let dst_socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, 0);
            async move {
                match scan_setting.src_ip {
                    IpAddr::V4(src_ipv4) => match target.ip_addr {
                        IpAddr::V4(dst_ipv4) => {
                            let mut icmp_packet_builder = IcmpPacketBuilder::new(
                                src_ipv4,
                                dst_ipv4,
                            );
                            icmp_packet_builder.icmp_type = xenet::packet::icmp::IcmpType::EchoRequest;
                            let packet_bytes: Vec<u8> = icmp_packet_builder.build();
                            
                            match socket.send_to(&packet_bytes, dst_socket_addr).await {
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
                                icmpv6_type: xenet::packet::icmpv6::Icmpv6Type::EchoRequest,
                                sequence_number: None,
                                identifier: None,
                            };
                            let packet_bytes: Vec<u8> = icmpv6_packet_builder.build();
                            match socket.send_to(&packet_bytes, dst_socket_addr).await {
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
                //thread::sleep(scan_setting.send_rate);
            }
        },
    );
    fut_host.await;
}

async fn send_udp_ping_packets(socket: &AsyncSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.hosts_concurrency,
        |target| async move {
            let dst_socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, UDP_BASE_DST_PORT);
            let udp_packet_builder = xenet::util::packet_builder::udp::UdpPacketBuilder::new(
                SocketAddr::new(scan_setting.src_ip, scan_setting.src_port),
                dst_socket_addr,
            );
            let packet_bytes: Vec<u8> = udp_packet_builder.build();
            
            match socket.send_to(&packet_bytes, dst_socket_addr).await {
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
            //thread::sleep(scan_setting.send_rate);
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

async fn send_tcp_connect_requests(
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    let _results: Vec<HostInfo> = stream::iter(scan_setting.targets.clone().into_iter())
        .map(|dst| try_connect_ports(scan_setting.ports_concurrency, dst, ptx))
        .buffer_unordered(scan_setting.hosts_concurrency)
        .collect()
        .await;
}

async fn send_ping_packets(socket: &AsyncSocket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
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

pub(crate) async fn scan_hosts(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let socket = match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            match scan_setting.src_ip {
                IpAddr::V4(_) => {
                    let socket_option = SocketOption {
                        ip_version: IpVersion::V4,
                        socket_type: SocketType::Raw,
                        protocol: Some(IpNextLevelProtocol::Icmp),
                        timeout: None,
                        ttl: None,
                        non_blocking: true,
                    };
                    AsyncSocket::new(socket_option).unwrap()
                }
                IpAddr::V6(_) => {
                    let socket_option = SocketOption {
                        ip_version: IpVersion::V6,
                        socket_type: SocketType::Raw,
                        protocol: Some(IpNextLevelProtocol::Icmpv6),
                        timeout: None,
                        ttl: None,
                        non_blocking: true,
                    };
                    AsyncSocket::new(socket_option).unwrap()
                }
            }
        }
        ScanType::TcpPingScan => {
            let socket_option = SocketOption {
                ip_version: if scan_setting.src_ip.is_ipv4() {
                    IpVersion::V4
                } else {
                    IpVersion::V6
                },
                socket_type: SocketType::Raw,
                protocol: Some(IpNextLevelProtocol::Tcp),
                timeout: None,
                ttl: None,
                non_blocking: true,
            };
            AsyncSocket::new(socket_option).unwrap()
        }
        ScanType::UdpPingScan => {
            let socket_option = SocketOption {
                ip_version: if scan_setting.src_ip.is_ipv4() {
                    IpVersion::V4
                } else {
                    IpVersion::V6
                },
                socket_type: SocketType::Raw,
                protocol: Some(IpNextLevelProtocol::Udp),
                timeout: None,
                ttl: None,
                non_blocking: true,
            };
            AsyncSocket::new(socket_option).unwrap()
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
        read_timeout: scan_setting.wait_time,
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

    let executor = ThreadPool::new().unwrap();
    let future = async move {
        let packets: Vec<PacketFrame> = listener.start();
        for p in packets {
            receive_packets.lock().unwrap().push(p);
        }
    };
    let lisner_handle: futures::future::RemoteHandle<()> = executor.spawn_with_handle(future).unwrap();
    
    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(LISTENER_WAIT_TIME_MILLIS));

    // Send probe packets
    send_ping_packets(&socket, &scan_setting, ptx).await;
    thread::sleep(scan_setting.wait_time);
    // Stop listener
    match stop_handle.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }

    // Wait for listener to complete task
    lisner_handle.await;

    // Parse packets and store results
    let mut result: ScanResult = ScanResult::new();
    for p in packets.lock().unwrap().iter() {
        let mut ports: Vec<PortInfo> = vec![];
        match scan_setting.scan_type {
            ScanType::IcmpPingScan => {
                if p.icmp_header.is_none() && p.icmpv6_header.is_none() {
                    continue;
                }
            }
            ScanType::TcpPingScan => {
                if p.tcp_header.is_none() {
                    continue;
                }
                if let Some(tcp_packet) = &p.tcp_header {
                    if tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK {
                        let port_info: PortInfo = PortInfo {
                            port: tcp_packet.source,
                            status: PortStatus::Open,
                        };
                        ports.push(port_info);
                    }else if tcp_packet.flags == TcpFlags::RST | TcpFlags::ACK {
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
                if p.icmp_header.is_none() && p.icmpv6_header.is_none() {
                    continue;
                }
            }
            _ => {}
        }
        let host_info: HostInfo = if let Some(ipv4_packet) = &p.ipv4_header {
            HostInfo {
                ip_addr: IpAddr::V4(ipv4_packet.source),
                host_name: scan_setting.ip_map.get(&IpAddr::V4(ipv4_packet.source)).unwrap_or(&String::new()).clone(),
                ttl: ipv4_packet.ttl,
                ports: ports,
            }
        }else if let Some(ipv6_packet) = &p.ipv6_header {
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

pub(crate) async fn scan_ports(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let socket = match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            let socket_option = SocketOption {
                ip_version: if scan_setting.src_ip.is_ipv4() {
                    IpVersion::V4
                } else {
                    IpVersion::V6
                },
                socket_type: SocketType::Raw,
                protocol: Some(IpNextLevelProtocol::Tcp),
                timeout: None,
                ttl: None,
                non_blocking: true,
            };
            AsyncSocket::new(socket_option).unwrap()
        }
        ScanType::TcpConnectScan => {
            let socket_option = SocketOption {
                ip_version: if scan_setting.src_ip.is_ipv4() {
                    IpVersion::V4
                } else {
                    IpVersion::V6
                },
                socket_type: SocketType::Stream,
                protocol: Some(IpNextLevelProtocol::Tcp),
                timeout: None,
                ttl: None,
                non_blocking: true,
            };
            AsyncSocket::new(socket_option).unwrap()
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
        read_timeout: scan_setting.wait_time,
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

    let executor = ThreadPool::new().unwrap();
    let future = async move {
        let packets: Vec<PacketFrame> = listener.start();
        for p in packets {
            receive_packets.lock().unwrap().push(p);
        }
    };
    let lisner_handle: futures::future::RemoteHandle<()> = executor.spawn_with_handle(future).unwrap();

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(LISTENER_WAIT_TIME_MILLIS));

    match scan_setting.scan_type {
        ScanType::TcpConnectScan => {
            send_tcp_connect_requests(&scan_setting, ptx).await;
        }
        _ => {
            send_tcp_syn_packets(&socket, &scan_setting, ptx).await;
        }
    }

    thread::sleep(scan_setting.wait_time);
    // Stop listener
    match stop_handle.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }

    // Wait for listener to complete task
    lisner_handle.await;

    // Parse packets and store results
    let mut result: ScanResult = ScanResult::new();
    let mut socket_set: HashSet<SocketAddr> = HashSet::new();
    for p in packets.lock().unwrap().iter() {
        if p.ipv4_header.is_none() && p.ipv6_header.is_none() {
            continue;
        }
        let ip_addr: IpAddr = {
            if let Some(ipv4_packet) = &p.ipv4_header {
                if let Some(tcp_packet) = &p.tcp_header {
                    if socket_set.contains(&SocketAddr::new(IpAddr::V4(ipv4_packet.source), tcp_packet.source)) {
                        continue;
                    }
                }else{
                    continue;
                }
                IpAddr::V4(ipv4_packet.source) 
            }else if let Some(ipv6_packet) = &p.ipv6_header {
                if let Some(tcp_packet) = &p.tcp_header {
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
        let port_info: PortInfo = if let Some(tcp_packet) = &p.tcp_header {
            if tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK {
                PortInfo {
                    port: tcp_packet.source,
                    status: PortStatus::Open,
                }
            }else if tcp_packet.flags == TcpFlags::RST | TcpFlags::ACK {
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
                ttl: if let Some(ipv4_packet) = &p.ipv4_header {
                    ipv4_packet.ttl
                }else if let Some(ipv6_packet) = &p.ipv6_header {
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
