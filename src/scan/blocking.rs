use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use netdev::Interface;
use nex::datalink::FrameSender;
use nex::packet::ip::IpNextLevelProtocol;
use crate::config::PCAP_WAIT_TIME_MILLIS;
use crate::packet::frame::PacketFrame;
use crate::pcap::PacketCaptureOptions;
use crate::scan::setting::{PortScanSetting, HostScanSetting};
use crate::host::Host;

use super::result::{ScanResult, ScanStatus, parse_hostscan_result, parse_portscan_result};
use super::setting::{HostScanType, PortScanType};
use super::packet::{build_hostscan_packet, build_portscan_packet};

pub (crate) fn send_hostscan_packets(tx: &mut Box<dyn FrameSender>, interface: &Interface, targets: Vec<Host>, ptx: &Arc<Mutex<Sender<Host>>>, scan_type: HostScanType) {
    // Acquire message sender lock
    let ptx_lock = match ptx.lock() {
        Ok(ptx) => ptx,
        Err(e) => {
            eprintln!("Failed to lock ptx: {}", e);
            return;
        }
    };
    for target in targets {
        let packet = build_hostscan_packet(&interface, &target, &scan_type, false);
        match tx.send(&packet) {
            Some(_) => {
                // Notify packet sent
                match ptx_lock.send(target) {
                    Ok(_) => {},
                    Err(e) => {
                        eprintln!("Failed to send message: {}", e);
                    }
                }
            },
            None => {
                eprintln!("Failed to send packet");
            }
        }
    }
    // Drop message sender lock
    drop(ptx_lock);
}

pub (crate) fn send_portscan_packets(tx: &mut Box<dyn FrameSender>, interface: &Interface, targets: Vec<Host>, ptx: &Arc<Mutex<Sender<SocketAddr>>>, scan_type: PortScanType) {
    // Acquire message sender lock
    let ptx_lock = match ptx.lock() {
        Ok(ptx) => ptx,
        Err(e) => {
            eprintln!("Failed to lock ptx: {}", e);
            return;
        }
    };
    for target in targets {
        match scan_type {
            PortScanType::TcpSynScan => {
                for port in target.ports {
                    let packet = build_portscan_packet(&interface, target.ip_addr, port.number, false);
                    match tx.send(&packet) {
                        Some(_) => {
                            // Notify packet sent
                            match ptx_lock.send(SocketAddr::new(target.ip_addr, port.number)) {
                                Ok(_) => {},
                                Err(e) => {
                                    eprintln!("Failed to send message: {}", e);
                                }
                            }
                        },
                        None => {
                            eprintln!("Failed to send packet");
                        }
                    }
                }
            },
            PortScanType::TcpConnectScan => {
                // TODO
            },
        }
    }
    // Drop message sender lock
    drop(ptx_lock);
}

pub (crate) fn scan_hosts(scan_setting: HostScanSetting, ptx: &Arc<Mutex<Sender<Host>>>) -> ScanResult {
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
    let (mut tx, mut rx) = match nex::datalink::channel(&interface, config) {
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
        read_timeout: scan_setting.wait_time,
        promiscuous: false,
        receive_undefined: false,
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
                for port in target.ports {
                    capture_options.src_ports.insert(port.number);
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
        let packets: Vec<PacketFrame> = crate::pcap::start_capture(&mut rx, capture_options, &stop_handle);
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
    send_hostscan_packets(&mut tx, &interface, scan_setting.targets.clone(), ptx, scan_setting.scan_type.clone());
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
        Ok(_) => {},
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

pub (crate) fn scan_ports(scan_setting: PortScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) -> ScanResult {
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
    let (mut tx, mut rx) = match nex::datalink::channel(&interface, config) {
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
        read_timeout: scan_setting.wait_time,
        promiscuous: false,
        receive_undefined: false,
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
        let packets: Vec<PacketFrame> = crate::pcap::start_capture(&mut rx, capture_options, &stop_handle);
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
    send_portscan_packets(&mut tx, &interface, scan_setting.targets.clone(), ptx, scan_setting.scan_type.clone());
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
        Ok(_) => {},
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
