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
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use rayon::prelude::*;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn build_tcp_syn_packet(
    scan_setting: &ScanSetting,
    tmp_packet: &mut [u8],
    dst_ip: IpAddr,
    dst_port: u16,
) {
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    packet::ethernet::build_ethernet_packet(
        &mut eth_header,
        pnet::datalink::MacAddr::from(scan_setting.src_mac),
        pnet::datalink::MacAddr::from(scan_setting.dst_mac),
        EtherTypes::Ipv4,
    );
    // Setup IP header
    let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(
        &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
            ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)],
    )
    .unwrap();
    match scan_setting.src_ip {
        IpAddr::V4(src_ip) => match dst_ip {
            IpAddr::V4(dst_ip) => {
                packet::ipv4::build_ipv4_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Tcp,
                );
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(_ip) => {}
    }
    // Setup TCP header
    let mut tcp_header = pnet::packet::tcp::MutableTcpPacket::new(
        &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
    packet::tcp::build_tcp_packet(
        &mut tcp_header,
        scan_setting.src_ip,
        scan_setting.src_port,
        dst_ip,
        dst_port,
    );
}

fn build_udp_packet(
    scan_setting: &ScanSetting,
    tmp_packet: &mut [u8],
    dst_ip: IpAddr,
    dst_port: u16,
) {
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    packet::ethernet::build_ethernet_packet(
        &mut eth_header,
        pnet::datalink::MacAddr::from(scan_setting.src_mac),
        pnet::datalink::MacAddr::from(scan_setting.dst_mac),
        EtherTypes::Ipv4,
    );
    // Setup IP header
    let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(
        &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
            ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)],
    )
    .unwrap();
    match scan_setting.src_ip {
        IpAddr::V4(src_ip) => match dst_ip {
            IpAddr::V4(dst_ip) => {
                packet::ipv4::build_ipv4_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Tcp,
                );
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(_ip) => {}
    }
    // Setup UDP header
    let mut udp_header = pnet::packet::udp::MutableUdpPacket::new(
        &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
    packet::udp::build_udp_packet(
        &mut udp_header,
        scan_setting.src_ip,
        scan_setting.src_port,
        dst_ip,
        dst_port,
    );
}

fn build_icmp_echo_packet(scan_setting: &ScanSetting, tmp_packet: &mut [u8], dst_ip: IpAddr) {
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    packet::ethernet::build_ethernet_packet(
        &mut eth_header,
        pnet::datalink::MacAddr::from(scan_setting.src_mac),
        pnet::datalink::MacAddr::from(scan_setting.dst_mac),
        EtherTypes::Ipv4,
    );
    // Setup IP header
    let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(
        &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
            ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)],
    )
    .unwrap();
    match scan_setting.src_ip {
        IpAddr::V4(src_ip) => match dst_ip {
            IpAddr::V4(dst_ip) => {
                packet::ipv4::build_ipv4_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Icmp,
                );
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(_ip) => {}
    }
    // Setup ICMP header
    let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(
        &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
    packet::icmp::build_icmp_packet(&mut icmp_packet);
}

fn send_packets(
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    match scan_setting.scan_type {
        ScanType::TcpSynScan | ScanType::TcpPingScan => {
            for dst in scan_setting.targets.clone() {
                let dst_ip: IpAddr = dst.ip_addr;
                for port in dst.get_ports() {
                    tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                        build_tcp_syn_packet(scan_setting, packet, dst_ip, port);
                    });
                    let socket_addr = SocketAddr::new(dst.ip_addr, port);
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
        ScanType::UdpPingScan => {
            for dst in scan_setting.targets.clone() {
                let dst_ip: IpAddr = dst.ip_addr;
                for port in dst.get_ports() {
                    tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                        build_udp_packet(scan_setting, packet, dst_ip, port);
                    });
                    let socket_addr = SocketAddr::new(dst.ip_addr, port);
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
        ScanType::IcmpPingScan => {
            for dst in scan_setting.targets.clone() {
                tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                    build_icmp_echo_packet(scan_setting, packet, dst.ip_addr);
                });
                let socket_addr = SocketAddr::new(dst.ip_addr, 0);
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
        _ => {}
    }
}

fn send_connect_requests(
    scan_setting: &ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>
) {
    let start_time = Instant::now();
    let conn_timeout = Duration::from_millis(200);
    for dst in scan_setting.targets.clone() {
        let ip_addr: IpAddr = dst.ip_addr;
        dst.get_ports().into_par_iter().for_each(|port| {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
            let socket_addr: SocketAddr = SocketAddr::new(ip_addr, port);
            let sock_addr = SockAddr::from(socket_addr);
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
    let interfaces = pnet::datalink::interfaces();
    let interface = match interfaces
        .into_iter()
        .filter(|interface: &pnet::datalink::NetworkInterface| {
            interface.index == scan_setting.if_index
        })
        .next()
    {
        Some(interface) => interface,
        None => return ScanResult::new(),
    };
    let config = pnet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut tx, mut _rx) = match pnet::datalink::channel(&interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
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
    send_packets(&mut tx, &scan_setting, ptx);
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
            result.fingerprints.push(f.clone());
        }
    }
    return result;
}

pub(crate) fn scan_ports(
    scan_setting: ScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let interfaces = pnet::datalink::interfaces();
    let interface = match interfaces
        .into_iter()
        .filter(|interface: &pnet::datalink::NetworkInterface| {
            interface.index == scan_setting.if_index
        })
        .next()
    {
        Some(interface) => interface,
        None => return ScanResult::new(),
    };
    let config = pnet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut tx, mut _rx) = match pnet::datalink::channel(&interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
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

    match scan_setting.scan_type {
        ScanType::TcpConnectScan => {
            send_connect_requests(&scan_setting, ptx);
        }
        _ => {
            send_packets(&mut tx, &scan_setting, ptx);
        }
    }
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
