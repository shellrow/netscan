use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Instant, Duration};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use pnet_packet::ethernet::EtherTypes;
use pnet_packet::ip::IpNextHeaderProtocols;
use rayon::prelude::*;
use crate::host::{HostInfo, PortInfo, PortStatus};
use crate::result::{HostScanResult, PortScanResult, ScanResult};
use crate::setting::{ScanSetting};
use crate::setting::{ScanType};
use crate::packet;
use crate::blocking::receiver;

fn build_tcp_syn_packet(scan_setting: &ScanSetting, tmp_packet: &mut [u8], dst_ip: IpAddr, dst_port: u16){
    // Setup Ethernet header
    let mut eth_header = pnet_packet::ethernet::MutableEthernetPacket::new(&mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN]).unwrap();
    packet::ethernet::build_ethernet_packet(&mut eth_header, scan_setting.src_mac, scan_setting.dst_mac, EtherTypes::Ipv4);
    // Setup IP header
    let mut ip_header = pnet_packet::ipv4::MutableIpv4Packet::new(&mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)]).unwrap();
    match scan_setting.src_ip {
        IpAddr::V4(src_ip) => {
            match dst_ip {
                IpAddr::V4(dst_ip) => {
                    packet::ipv4::build_ipv4_packet(&mut ip_header, src_ip, dst_ip, IpNextHeaderProtocols::Tcp);
                },
                IpAddr::V6(_ip) => {},
            }
        },
        IpAddr::V6(_ip) => {},
    }
    // Setup TCP header
    let mut tcp_header = pnet_packet::tcp::MutableTcpPacket::new(&mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..]).unwrap();
    packet::tcp::build_tcp_packet(&mut tcp_header, scan_setting.src_ip, scan_setting.src_port, dst_ip, dst_port);
}

fn build_udp_packet(scan_setting: &ScanSetting, tmp_packet: &mut [u8], dst_ip: IpAddr, dst_port: u16){
    // Setup Ethernet header
    let mut eth_header = pnet_packet::ethernet::MutableEthernetPacket::new(&mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN]).unwrap();
    packet::ethernet::build_ethernet_packet(&mut eth_header, scan_setting.src_mac, scan_setting.dst_mac, EtherTypes::Ipv4);
    // Setup IP header
    let mut ip_header = pnet_packet::ipv4::MutableIpv4Packet::new(&mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)]).unwrap();
    match scan_setting.src_ip {
        IpAddr::V4(src_ip) => {
            match dst_ip {
                IpAddr::V4(dst_ip) => {
                    packet::ipv4::build_ipv4_packet(&mut ip_header, src_ip, dst_ip, IpNextHeaderProtocols::Tcp);
                },
                IpAddr::V6(_ip) => {},
            }
        },
        IpAddr::V6(_ip) => {},
    }
    // Setup UDP header
    let mut udp_header = pnet_packet::udp::MutableUdpPacket::new(&mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..]).unwrap();
    packet::udp::build_udp_packet(&mut udp_header, scan_setting.src_ip, scan_setting.src_port, dst_ip, dst_port);
}

fn build_icmp_echo_packet(scan_setting: &ScanSetting, tmp_packet: &mut [u8], dst_ip: IpAddr) {
    // Setup Ethernet header
    let mut eth_header = pnet_packet::ethernet::MutableEthernetPacket::new(&mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN]).unwrap();
    packet::ethernet::build_ethernet_packet(&mut eth_header, scan_setting.src_mac, scan_setting.dst_mac, EtherTypes::Ipv4);
    // Setup IP header
    let mut ip_header = pnet_packet::ipv4::MutableIpv4Packet::new(&mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)]).unwrap();
    match scan_setting.src_ip {
        IpAddr::V4(src_ip) => {
            match dst_ip {
                IpAddr::V4(dst_ip) => {
                    packet::ipv4::build_ipv4_packet(&mut ip_header, src_ip, dst_ip, IpNextHeaderProtocols::Icmp);
                },
                IpAddr::V6(_ip) => {},
            }
        },
        IpAddr::V6(_ip) => {},
    }
    // Setup ICMP header
    let mut icmp_packet = pnet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..]).unwrap();
    packet::icmp::build_icmp_packet(&mut icmp_packet);
}

fn send_packets(tx: &mut Box<dyn pnet_datalink::DataLinkSender>, scan_setting: &ScanSetting, stop: &Arc<Mutex<bool>>, ptx: &Arc<Mutex<Sender<SocketAddr>>>) {
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
        },
        ScanType::UdpPingScan => {
            for dst in scan_setting.targets.clone() {
                let dst_ip: IpAddr = dst.ip_addr;
                for port in dst.get_ports() {
                    tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                        build_udp_packet(scan_setting, packet, dst_ip, port);
                    });
                    let socket_addr = SocketAddr::new(dst.ip_addr, port);
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
        },
        ScanType::IcmpPingScan => {
            for dst in scan_setting.targets.clone() {
                tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                    build_icmp_echo_packet(scan_setting, packet, dst.ip_addr);
                });
                let socket_addr = SocketAddr::new(dst.ip_addr, 0);
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
        },
        _ => {},
    }
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
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

pub(crate) fn scan_hosts(scan_setting: ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) -> HostScanResult {
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
    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let receive_setting: ScanSetting = scan_setting.clone();
    rayon::join(|| send_packets(&mut tx, &scan_setting, &stop, ptx),
                || receiver::receive_packets(&mut rx, receive_setting, &scan_result, &stop)
    );
    let result: HostScanResult = scan_result.lock().unwrap().host_scan_result.clone(); 
    return result;
}

pub(crate) fn scan_ports(scan_setting: ScanSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) -> PortScanResult {
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
    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let receive_setting: ScanSetting = scan_setting.clone();
    match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            rayon::join(|| send_packets(&mut tx, &scan_setting, &stop, ptx),
                || receiver::receive_packets(&mut rx, receive_setting, &scan_result, &stop)
            );
        },
        ScanType::TcpConnectScan => {
            run_connect_scan(scan_setting, &scan_result, &stop);
        },
        _ => {},
    }
    let result: PortScanResult = scan_result.lock().unwrap().port_scan_result.clone(); 
    return result;
}
