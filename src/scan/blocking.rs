use crate::config::PCAP_WAIT_TIME_MILLIS;
use crate::host::Host;
use crate::packet::frame::PacketFrame;
use crate::pcap::PacketCaptureOptions;
use crate::scan::setting::{HostScanSetting, PortScanSetting};
use netdev::Interface;
use nex::datalink::RawSender;
use nex::packet::ip::IpNextProtocol;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::packet::{build_hostscan_packet, build_portscan_packet};
use super::result::{
    ScanError, ScanResult, ScanStatus, parse_hostscan_result, parse_portscan_result,
};
use super::setting::{HostScanType, PortScanType};

pub(crate) fn send_hostscan_packets(
    tx: &mut Box<dyn RawSender>,
    interface: &Interface,
    targets: &[Host],
    ptx: &Arc<Mutex<Sender<Host>>>,
    scan_type: HostScanType,
    send_rate: Duration,
) {
    for target in targets {
        let packet = build_hostscan_packet(interface, target, &scan_type, false);
        match tx.send(&packet) {
            Some(_) => {
                // Notify packet sent
                if let Ok(lock) = ptx.lock() {
                    if let Err(e) = lock.send(target.clone()) {
                        eprintln!("Failed to send message: {}", e);
                    }
                }
            }
            None => {
                eprintln!("Failed to send packet");
            }
        }
        if !send_rate.is_zero() {
            thread::sleep(send_rate);
        }
    }
}

pub(crate) fn send_portscan_packets(
    tx: &mut Box<dyn RawSender>,
    interface: &Interface,
    targets: &[Host],
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
    scan_type: PortScanType,
    send_rate: Duration,
) {
    for target in targets {
        match scan_type {
            PortScanType::TcpSynScan => {
                for port in &target.ports {
                    let packet =
                        build_portscan_packet(interface, target.ip_addr, port.number, false);
                    match tx.send(&packet) {
                        Some(_) => {
                            // Notify packet sent
                            if let Ok(lock) = ptx.lock() {
                                if let Err(e) =
                                    lock.send(SocketAddr::new(target.ip_addr, port.number))
                                {
                                    eprintln!("Failed to send message: {}", e);
                                }
                            }
                        }
                        None => {
                            eprintln!("Failed to send packet");
                        }
                    }
                    if !send_rate.is_zero() {
                        thread::sleep(send_rate);
                    }
                }
            }
            PortScanType::TcpConnectScan => {
                // TODO
            }
        }
    }
}

pub(crate) fn scan_hosts(
    scan_setting: HostScanSetting,
    ptx: &Arc<Mutex<Sender<Host>>>,
) -> ScanResult {
    let interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(interface) => interface,
        None => return ScanResult::error(ScanError::InterfaceNotFound),
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
    let (mut tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return ScanResult::error(ScanError::UnhandledChannelType),
        Err(e) => return ScanResult::error(ScanError::ChannelCreationFailed(e.to_string())),
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
            capture_options.ip_protocols.insert(IpNextProtocol::Icmp);
            capture_options.ip_protocols.insert(IpNextProtocol::Icmpv6);
        }
        HostScanType::TcpPingScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Tcp);
            for target in scan_setting.targets.clone() {
                for port in target.ports {
                    capture_options.src_ports.insert(port.number);
                }
            }
        }
        HostScanType::UdpPingScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Udp);
            capture_options.ip_protocols.insert(IpNextProtocol::Icmp);
            capture_options.ip_protocols.insert(IpNextProtocol::Icmpv6);
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
    send_hostscan_packets(
        &mut tx,
        &interface,
        &scan_setting.targets,
        ptx,
        scan_setting.scan_type,
        scan_setting.send_rate,
    );
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

pub(crate) fn scan_ports(
    scan_setting: PortScanSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> ScanResult {
    let interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(interface) => interface,
        None => return ScanResult::error(ScanError::InterfaceNotFound),
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
    let (mut tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return ScanResult::error(ScanError::UnhandledChannelType),
        Err(e) => return ScanResult::error(ScanError::ChannelCreationFailed(e.to_string())),
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
        capture_options.src_ports.extend(target.get_ports());
    }
    match scan_setting.scan_type {
        PortScanType::TcpSynScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Tcp);
        }
        PortScanType::TcpConnectScan => {
            capture_options.ip_protocols.insert(IpNextProtocol::Tcp);
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
    send_portscan_packets(
        &mut tx,
        &interface,
        &scan_setting.targets,
        ptx,
        scan_setting.scan_type,
        scan_setting.send_rate,
    );
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
