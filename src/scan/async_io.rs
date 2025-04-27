use futures::stream::{self, StreamExt};
use netdev::Interface;
use nex::socket::{AsyncSocket, IpVersion, SocketOption, SocketType};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::host::{Host, Port, PortStatus};

use super::packet::{build_hostscan_ip_next_packet, build_portscan_ip_next_packet};
use super::result::ScanResult;
use super::setting::{HostScanSetting, PortScanSetting};

use crate::config::PCAP_WAIT_TIME_MILLIS;
use crate::packet::frame::PacketFrame;
use crate::pcap::PacketCaptureOptions;
use nex::packet::ip::IpNextLevelProtocol;
use std::collections::HashSet;
use std::thread;

use super::result::{parse_hostscan_result, parse_portscan_result, ScanStatus};
use super::setting::{HostScanType, PortScanType};

pub(crate) async fn send_portscan_packets(
    interface: &Interface,
    socket: &AsyncSocket,
    scan_setting: &PortScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.concurrency,
        |dst| async move {
            let fut_port = stream::iter(dst.get_ports()).for_each_concurrent(
                scan_setting.concurrency,
                |port| {
                    let target = dst.clone();
                    let dst_socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, port);
                    async move {
                        let packet_bytes: Vec<u8> =
                            build_portscan_ip_next_packet(&interface, target.ip_addr, port);
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

pub(crate) async fn send_hostscan_packets(
    interface: &Interface,
    scan_setting: &HostScanSetting,
    ptx: &Arc<Mutex<Sender<Host>>>,
) {
    let fut_host = stream::iter(scan_setting.targets.clone()).for_each_concurrent(
        scan_setting.concurrency,
        |dst| async move {
            let socket: AsyncSocket = match scan_setting.scan_type {
                HostScanType::IcmpPingScan => match dst.ip_addr {
                    IpAddr::V4(_) => {
                        let socket_option = SocketOption {
                            ip_version: IpVersion::V4,
                            socket_type: SocketType::Raw,
                            protocol: Some(IpNextLevelProtocol::Icmp),
                            non_blocking: true,
                        };
                        AsyncSocket::new(socket_option).unwrap()
                    }
                    IpAddr::V6(_) => {
                        let socket_option = SocketOption {
                            ip_version: IpVersion::V6,
                            socket_type: SocketType::Raw,
                            protocol: Some(IpNextLevelProtocol::Icmpv6),
                            non_blocking: true,
                        };
                        AsyncSocket::new(socket_option).unwrap()
                    }
                },
                HostScanType::TcpPingScan => {
                    let socket_option = SocketOption {
                        ip_version: if dst.ip_addr.is_ipv4() {
                            IpVersion::V4
                        } else {
                            IpVersion::V6
                        },
                        socket_type: SocketType::Raw,
                        protocol: Some(IpNextLevelProtocol::Tcp),
                        non_blocking: true,
                    };
                    AsyncSocket::new(socket_option).unwrap()
                }
                HostScanType::UdpPingScan => {
                    let socket_option = SocketOption {
                        ip_version: if dst.ip_addr.is_ipv4() {
                            IpVersion::V4
                        } else {
                            IpVersion::V6
                        },
                        socket_type: SocketType::Raw,
                        protocol: Some(IpNextLevelProtocol::Udp),
                        non_blocking: true,
                    };
                    AsyncSocket::new(socket_option).unwrap()
                }
            };
            let dst_socket_addr: SocketAddr = SocketAddr::new(dst.ip_addr, 0);
            let packet_bytes =
                build_hostscan_ip_next_packet(&interface, &dst, &scan_setting.scan_type);
            match socket.send_to(&packet_bytes, dst_socket_addr).await {
                Ok(_) => {}
                Err(_) => {}
            }
            match ptx.lock() {
                Ok(lr) => match lr.send(dst) {
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

pub async fn try_connect_ports(
    target: Host,
    concurrency: usize,
    timeout: Duration,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> Host {
    let (channel_tx, channel_rx) = mpsc::channel();
    let fut = stream::iter(target.get_ports()).for_each_concurrent(concurrency, |port| {
        let channel_tx = channel_tx.clone();
        async move {
            let socket_addr: SocketAddr = SocketAddr::new(target.ip_addr, port);
            match AsyncSocket::new_with_async_connect_timeout(&socket_addr, timeout).await {
                Ok(async_socket) => {
                    let _ = channel_tx.send(port);
                    match async_socket.shutdown(std::net::Shutdown::Both).await {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
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
    });
    fut.await;
    drop(channel_tx);
    let mut open_ports: Vec<Port> = vec![];
    loop {
        match channel_rx.recv() {
            Ok(port) => {
                open_ports.push(Port {
                    number: port,
                    status: PortStatus::Open,
                    service_name: String::new(),
                    service_version: String::new(),
                });
            }
            Err(_) => {
                break;
            }
        }
    }
    Host {
        ip_addr: target.ip_addr,
        hostname: target.hostname,
        ports: open_ports,
        mac_addr: target.mac_addr,
        ttl: target.ttl,
    }
}

pub fn run_connect_scan(
    scan_setting: PortScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        let start_time = std::time::Instant::now();
        let mut tasks = vec![];
        for target in scan_setting.targets {
            let ptx = ptx.clone();
            tasks.push(tokio::spawn(async move {
                let host =
                    try_connect_ports(target, scan_setting.concurrency, scan_setting.timeout, &ptx)
                        .await;
                host
            }));
        }
        let mut hosts: Vec<Host> = vec![];
        for task in tasks {
            match task.await {
                Ok(host) => {
                    hosts.push(host);
                }
                Err(e) => {
                    println!("error: {}", e);
                }
            }
        }
        let mut result = ScanResult::new();
        result.hosts = hosts;
        result.scan_time = start_time.elapsed();
        result.scan_status = crate::scan::result::ScanStatus::Done;
        result
    });
    result
}

pub(crate) async fn scan_hosts(
    scan_setting: HostScanSetting,
    ptx: &Arc<Mutex<Sender<Host>>>,
) -> ScanResult {
    let interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(interface) => interface,
        None => return ScanResult::new(),
    };
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(scan_setting.wait_time),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut _tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return ScanResult::error("Unhandled channel type".to_string()),
        Err(e) => return ScanResult::error(format!("Failed to create channel: {}", e)),
    };
    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        capture_timeout: scan_setting.timeout,
        tunnel: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    for target in scan_setting.targets.clone() {
        capture_options.src_ips.insert(target.ip_addr);
    }
    match scan_setting.scan_type {
        HostScanType::IcmpPingScan => {
            capture_options
                .ip_protocols
                .insert(IpNextLevelProtocol::Icmp);
            capture_options
                .ip_protocols
                .insert(IpNextLevelProtocol::Icmpv6);
        }
        HostScanType::TcpPingScan => {
            capture_options
                .ip_protocols
                .insert(IpNextLevelProtocol::Tcp);
            for target in scan_setting.targets.clone() {
                for port in target.get_ports() {
                    capture_options.src_ports.insert(port);
                }
            }
        }
        HostScanType::UdpPingScan => {
            capture_options
                .ip_protocols
                .insert(IpNextLevelProtocol::Udp);
            capture_options
                .ip_protocols
                .insert(IpNextLevelProtocol::Icmp);
            capture_options
                .ip_protocols
                .insert(IpNextLevelProtocol::Icmpv6);
        }
    }
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let stop_handle = Arc::clone(&stop);
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&packets);
    // Spawn pcap thread
    let pcap_handler = thread::spawn(move || {
        let packets: Vec<PacketFrame> =
            crate::pcap::start_capture(&mut rx, capture_options, &stop_handle);
        match receive_packets.lock() {
            Ok(mut receive_packets) => {
                for p in packets {
                    receive_packets.push(p);
                }
            }
            Err(e) => {
                eprintln!("Failed to lock receive_packets: {}", e);
            }
        }
    });

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(PCAP_WAIT_TIME_MILLIS));
    let start_time = std::time::Instant::now();
    // Send probe packets
    send_hostscan_packets(&interface, &scan_setting, ptx).await;
    thread::sleep(scan_setting.wait_time);
    // Stop pcap
    match stop.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Failed to lock stop: {}", e);
        }
    }
    // Wait for listener to stop
    match pcap_handler.join() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Failed to join pcap_handler: {:?}", e);
        }
    }

    let mut scan_result: ScanResult = ScanResult::new();
    match packets.lock() {
        Ok(packets) => {
            scan_result = parse_hostscan_result(packets.clone(), scan_setting);
        }
        Err(e) => {
            eprintln!("Failed to lock packets: {}", e);
        }
    }
    scan_result.scan_time = start_time.elapsed();
    scan_result.scan_status = ScanStatus::Done;
    scan_result
}

pub(crate) async fn scan_ports(
    scan_setting: PortScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(interface) => interface,
        None => return ScanResult::new(),
    };
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(scan_setting.wait_time),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut _tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return ScanResult::error("Unhandled channel type".to_string()),
        Err(e) => return ScanResult::error(format!("Failed to create channel: {}", e)),
    };
    let socket_option = SocketOption {
        ip_version: if scan_setting.targets.len() > 0 {
            if scan_setting.targets[0].ip_addr.is_ipv4() {
                IpVersion::V4
            } else {
                IpVersion::V6
            }
        } else {
            IpVersion::V4
        },
        socket_type: SocketType::Raw,
        protocol: Some(IpNextLevelProtocol::Tcp),
        non_blocking: true,
    };
    let socket: AsyncSocket = AsyncSocket::new(socket_option).unwrap();
    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        capture_timeout: scan_setting.timeout,
        tunnel: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    for target in scan_setting.targets.clone() {
        capture_options.src_ips.insert(target.ip_addr);
        capture_options.src_ports.extend(target.get_ports());
    }
    match scan_setting.scan_type {
        PortScanType::TcpSynScan => {
            capture_options
                .ip_protocols
                .insert(IpNextLevelProtocol::Tcp);
        }
        PortScanType::TcpConnectScan => {
            capture_options
                .ip_protocols
                .insert(IpNextLevelProtocol::Tcp);
        }
    }
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let stop_handle = Arc::clone(&stop);
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&packets);
    // Spawn pcap thread
    let pcap_handler = thread::spawn(move || {
        let packets: Vec<PacketFrame> =
            crate::pcap::start_capture(&mut rx, capture_options, &stop_handle);
        match receive_packets.lock() {
            Ok(mut receive_packets) => {
                for p in packets {
                    receive_packets.push(p);
                }
            }
            Err(e) => {
                eprintln!("Failed to lock receive_packets: {}", e);
            }
        }
    });
    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(PCAP_WAIT_TIME_MILLIS));
    let start_time = std::time::Instant::now();
    // Send probe packets
    send_portscan_packets(&interface, &socket, &scan_setting, ptx).await;
    thread::sleep(scan_setting.wait_time);
    // Stop pcap
    match stop.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Failed to lock stop: {}", e);
        }
    }
    // Wait for listener to stop
    match pcap_handler.join() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Failed to join pcap_handler: {:?}", e);
        }
    }
    let mut scan_result: ScanResult = ScanResult::new();
    match packets.lock() {
        Ok(packets) => {
            scan_result = parse_portscan_result(packets.clone(), scan_setting);
        }
        Err(e) => {
            eprintln!("Failed to lock packets: {}", e);
        }
    }
    scan_result.scan_time = start_time.elapsed();
    scan_result.scan_status = ScanStatus::Done;
    scan_result
}
