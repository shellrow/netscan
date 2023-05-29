use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Instant, Duration};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use pnet_packet::Packet;
use crate::host::{HostInfo, PortInfo, PortStatus};
use crate::result::{HostScanResult, PortScanResult, ScanResult};
use crate::setting::{ScanSetting};
use crate::setting::{ScanType};
use crate::packet;
use crate::blocking::receiver;
use rayon::prelude::*;

fn build_icmpv4_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; 16];
    let mut icmp_packet = pnet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    packet::icmp::build_icmp_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

fn build_tcp_syn_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut tcp_packet = pnet_packet::tcp::MutableTcpPacket::new(&mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..]).unwrap();
    packet::tcp::build_tcp_packet(&mut tcp_packet, src_ip, src_port, dst_ip, dst_port);
    tcp_packet.packet().to_vec()
}

fn build_udp_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut udp_packet = pnet_packet::udp::MutableUdpPacket::new(&mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..]).unwrap();
    packet::udp::build_udp_packet(&mut udp_packet, src_ip, src_port, dst_ip, dst_port);
    udp_packet.packet().to_vec()
}

fn send_icmp_echo_packets(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    for dst in scan_setting.targets.clone() {
        let socket_addr = SocketAddr::new(dst.ip_addr, 0);
        let sock_addr = SockAddr::from(socket_addr);
        let mut icmp_packet: Vec<u8> = build_icmpv4_echo_packet();
        match socket.send_to(&mut icmp_packet, &sock_addr) {
            Ok(_) => {},
            Err(_) => {},
        }
        match ptx.lock() {
            Ok(lr) => {
                match lr.send(socket_addr) {
                    Ok(_) => {},
                    Err(_) => {},
                }
            },
            Err(_) => {},
        }
        thread::sleep(scan_setting.send_rate);
    }
}

fn send_tcp_syn_packets(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>){
    for dst in scan_setting.targets.clone() {
        for port in dst.get_ports() {
            let socket_addr = SocketAddr::new(dst.ip_addr, port);
            let sock_addr = SockAddr::from(socket_addr);
            let mut tcp_packet: Vec<u8> = build_tcp_syn_packet(scan_setting.src_ip, scan_setting.src_port, dst.ip_addr, port);
            match socket.send_to(&mut tcp_packet, &sock_addr) {
                Ok(_) => {},
                Err(_) => {},
            }
            match ptx.lock() {
                Ok(lr) => {
                    match lr.send(socket_addr) {
                        Ok(_) => {},
                        Err(_) => {},
                    }
                },
                Err(_) => {},
            }
            thread::sleep(scan_setting.send_rate);
        }
    }
}

fn send_udp_packets(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    for dst in scan_setting.targets.clone() {
        for port in dst.get_ports() {
            let socket_addr = SocketAddr::new(dst.ip_addr, port);
            let sock_addr = SockAddr::from(socket_addr);
            let mut udp_packet: Vec<u8> = build_udp_packet(scan_setting.src_ip, scan_setting.src_port, dst.ip_addr, port);
            match socket.send_to(&mut udp_packet, &sock_addr) {
                Ok(_) => {},
                Err(_) => {},
            }
            match ptx.lock() {
                Ok(lr) => {
                    match lr.send(socket_addr) {
                        Ok(_) => {},
                        Err(_) => {},
                    }
                },
                Err(_) => {},
            }
            thread::sleep(scan_setting.send_rate);
        }
    }
}

fn run_connect_scan(scan_setting: ScanSetting, scan_result: &Arc<Mutex<ScanResult>>, stop: &Arc<Mutex<bool>>) {
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
                    let port_info = PortInfo{
                        port: socket_addr.port(),
                        status: PortStatus::Open,
                    };
                    // Avoid deadlock.
                    let mut exists: bool = false;
                    for host in scan_result.lock().unwrap().port_scan_result.results.iter_mut() {
                        if host.ip_addr == socket_addr.ip() {
                            host.ports.push(port_info);
                            exists = true;
                        }
                    }
                    if !exists {
                        let mut host_info = HostInfo::new();
                        host_info.ip_addr = socket_addr.ip();
                        host_info.host_name = scan_setting.ip_map.get(&socket_addr.ip()).unwrap_or(&String::new()).to_string();
                        host_info.ttl = socket.ttl().unwrap_or(0) as u8;
                        host_info.ports.push(port_info);
                        scan_result.lock().unwrap().port_scan_result.results.push(host_info);
                    }
                },
                Err(_) => {},
            }
            if Instant::now().duration_since(start_time) > scan_setting.timeout {
                *stop.lock().unwrap() = true;
                return;
            }
        });
    }
}

fn send_ping_packet(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            send_icmp_echo_packets(socket, scan_setting, ptx);
        },
        ScanType::TcpPingScan => {
            send_tcp_syn_packets(socket, scan_setting, ptx);
        },
        ScanType::UdpPingScan => {
            send_udp_packets(socket, scan_setting, ptx);
        },
        _ => {
            return;
        },
    }
}

fn send_tcp_packets(socket: &Socket, scan_setting: &ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
    match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            send_tcp_syn_packets(socket, scan_setting, ptx);
        },
        _ => {
            return;
        },
    }
}

pub(crate) fn scan_hosts(scan_setting: ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) -> HostScanResult {
    let socket = match scan_setting.src_ip {
        IpAddr::V4(_) => {
            match scan_setting.scan_type {
                ScanType::IcmpPingScan => Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap(),
                ScanType::TcpPingScan => Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).unwrap(),
                ScanType::UdpPingScan => Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)).unwrap(),
                _ => {
                    return HostScanResult::new()
                },
            }
        },
        IpAddr::V6(_) => {
            match scan_setting.scan_type {
                ScanType::IcmpPingScan => Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap(),
                ScanType::TcpPingScan => Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP)).unwrap(),
                ScanType::UdpPingScan => Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP)).unwrap(),
                _ => {
                    return HostScanResult::new()
                },
            }
        },
    };
    let interfaces = pnet_datalink::interfaces();
    let interface = match interfaces.into_iter().filter(|interface: &pnet_datalink::NetworkInterface| interface.index == scan_setting.if_index).next() {
        Some(interface) => interface,
        None => return HostScanResult::new(),
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
    let receive_result: Arc<Mutex<ScanResult>>  = Arc::clone(&scan_result);
    let receive_stop: Arc<Mutex<bool>> = Arc::clone(&stop);
    let receive_setting: ScanSetting = scan_setting.clone();
    thread::spawn(move || {
        receiver::receive_packets(&mut rx, receive_setting, &receive_result, &receive_stop);    
    });
    send_ping_packet(&socket, &scan_setting, ptx);
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
    let result: HostScanResult = scan_result.lock().unwrap().host_scan_result.clone(); 
    return result;
}

pub(crate) fn scan_ports(scan_setting: ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) -> PortScanResult {
    let socket = match scan_setting.src_ip {
        IpAddr::V4(_) => {
            match scan_setting.scan_type {
                ScanType::TcpSynScan => Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).unwrap(),
                ScanType::TcpConnectScan => Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap(),
                _ => {
                    return PortScanResult::new()
                },
            }
        },
        IpAddr::V6(_) => {
            match scan_setting.scan_type {
                ScanType::TcpSynScan => Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP)).unwrap(),
                ScanType::TcpConnectScan => Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).unwrap(),
                _ => {
                    return PortScanResult::new()
                },
            }
        },
    };
    let interfaces = pnet_datalink::interfaces();
    let interface = match interfaces.into_iter().filter(|interface: &pnet_datalink::NetworkInterface| interface.index == scan_setting.if_index).next() {
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
    let receive_result: Arc<Mutex<ScanResult>>  = Arc::clone(&scan_result);
    let receive_stop: Arc<Mutex<bool>> = Arc::clone(&stop);
    let receive_setting: ScanSetting = scan_setting.clone();
    match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            thread::spawn(move || {
                receiver::receive_packets(&mut rx, receive_setting, &receive_result, &receive_stop);    
            });
            send_tcp_packets(&socket, &scan_setting, ptx);
            thread::sleep(scan_setting.wait_time);
            *stop.lock().unwrap() = true;
        },
        ScanType::TcpConnectScan => {
            run_connect_scan(scan_setting, &receive_result, &receive_stop);
        },
        _ => {},
    }
    let result: PortScanResult = scan_result.lock().unwrap().port_scan_result.clone(); 
    return result;
}
