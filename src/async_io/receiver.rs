use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::net::{IpAddr, SocketAddr};
use pnet_packet::Packet;
use crate::host::{HostInfo, PortInfo, PortStatus};
use crate::result::ScanResult;
use crate::setting::{ScanSetting, ScanType};

pub(crate) async fn receive_packets(rx: &mut Box<dyn pnet_datalink::DataLinkReceiver>, scan_setting: ScanSetting, scan_result: &Arc<Mutex<ScanResult>>, stop: &Arc<Mutex<bool>>) {
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = pnet_packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet_packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, &scan_setting, &scan_result);
                    },
                    pnet_packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, &scan_setting, &scan_result);
                    },
                    _ => {},
                }
            },
            Err(_) => {},
        }
        if *stop.lock().unwrap(){
            break;
        }
        if Instant::now().duration_since(start_time) > scan_setting.timeout {
            break;
        }
    }
}

fn ipv4_handler(ethernet: &pnet_packet::ethernet::EthernetPacket, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(ethernet.payload()){
        match packet.get_next_level_protocol() {
            pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler_v4(&packet, scan_setting, scan_result);
            },
            pnet_packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler_v4(&packet, scan_setting, scan_result);
            },
            pnet_packet::ip::IpNextHeaderProtocols::Icmp => {
                icmp_handler_v4(&packet, scan_setting, scan_result);
            }
            _ => {}
        }
    }
}

fn ipv6_handler(ethernet: &pnet_packet::ethernet::EthernetPacket, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    if let Some(packet) = pnet_packet::ipv6::Ipv6Packet::new(ethernet.payload()){
        match packet.get_next_header() {
            pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler_v6(&packet, scan_setting, scan_result);
            },
            pnet_packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler_v6(&packet, scan_setting, scan_result);
            },
            pnet_packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                icmp_handler_v6(&packet, scan_setting, scan_result);
            },
            _ => {}
        }
    }
}

fn tcp_handler_v4(packet: &pnet_packet::ipv4::Ipv4Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let tcp_packet = pnet_packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp_packet) = tcp_packet {
        let host_info: HostInfo = HostInfo {
            ip_addr: IpAddr::V4(packet.get_source()),
            host_name: scan_setting.ip_map.get(&IpAddr::V4(packet.get_source())).unwrap_or(&String::new()).to_string(),
            ttl: packet.get_ttl(),
            ports: vec![],
        };
        handle_tcp_packet(tcp_packet, host_info, &scan_setting, scan_result);
    }
}

fn tcp_handler_v6(packet: &pnet_packet::ipv6::Ipv6Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let tcp_packet = pnet_packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp_packet) = tcp_packet {
        let host_info: HostInfo = HostInfo {
            ip_addr: IpAddr::V6(packet.get_source()),
            host_name: scan_setting.ip_map.get(&IpAddr::V6(packet.get_source())).unwrap_or(&String::new()).to_string(),
            ttl: packet.get_hop_limit(),
            ports: vec![],
        };
        handle_tcp_packet(tcp_packet, host_info, &scan_setting, scan_result);
    }
}

fn udp_handler_v4(packet: &pnet_packet::ipv4::Ipv4Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let udp = pnet_packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        handle_udp_packet(udp, &scan_setting, scan_result);
    }
}

fn udp_handler_v6(packet: &pnet_packet::ipv6::Ipv6Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let udp = pnet_packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        handle_udp_packet(udp, &scan_setting, scan_result);
    }
}

fn icmp_handler_v4(packet: &pnet_packet::ipv4::Ipv4Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
    if let Some(_icmp) = icmp_packet {
        if scan_setting.ip_map.contains_key(&IpAddr::V4(packet.get_source())) && !scan_result.lock().unwrap().ip_set.contains(&IpAddr::V4(packet.get_source())) {
            scan_result.lock().unwrap().host_scan_result.hosts.push(
                HostInfo {
                    ip_addr: IpAddr::V4(packet.get_source()),
                    host_name: scan_setting.ip_map.get(&IpAddr::V4(packet.get_source())).unwrap_or(&String::new()).to_string(),
                    ttl: packet.get_ttl(),
                    ports: vec![],
                }
            );
            scan_result.lock().unwrap().ip_set.insert(IpAddr::V4(packet.get_source()));
        }
    }
}

fn icmp_handler_v6(packet: &pnet_packet::ipv6::Ipv6Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
    if let Some(_icmp) = icmp_packet {
        if scan_setting.ip_map.contains_key(&IpAddr::V6(packet.get_source())) && !scan_result.lock().unwrap().ip_set.contains(&IpAddr::V6(packet.get_source())) {
            scan_result.lock().unwrap().host_scan_result.hosts.push(
                HostInfo {
                    ip_addr: IpAddr::V6(packet.get_source()),
                    host_name: scan_setting.ip_map.get(&IpAddr::V6(packet.get_source())).unwrap_or(&String::new()).to_string(),
                    ttl: packet.get_hop_limit(),
                    ports: vec![],
                }
            );
            scan_result.lock().unwrap().ip_set.insert(IpAddr::V6(packet.get_source()));
        }
    }
}

fn handle_tcp_packet(tcp_packet: pnet_packet::tcp::TcpPacket, mut host_info: HostInfo, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let socket_addr: SocketAddr = SocketAddr::new(host_info.ip_addr, tcp_packet.get_source());
    if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK {
        let port_info = PortInfo{
            port: socket_addr.port(),
            status: PortStatus::Open,
        };
        match scan_setting.scan_type {
            ScanType::TcpSynScan => {
                if !scan_result.lock().unwrap().socket_set.contains(&socket_addr) {
                    // Avoid deadlock.
                    let mut exists: bool = false;
                    for host in scan_result.lock().unwrap().port_scan_result.results.iter_mut() {
                        if host.ip_addr == socket_addr.ip() {
                            host.ports.push(port_info);
                            exists = true;
                        }
                    }
                    if !exists {
                        let mut host = HostInfo::new();
                        host.ip_addr = socket_addr.ip();
                        host.host_name = host_info.host_name;
                        host.ttl = host_info.ttl;
                        host.ports.push(port_info);
                        scan_result.lock().unwrap().port_scan_result.results.push(host);
                    }
                    scan_result.lock().unwrap().socket_set.insert(socket_addr);
                }
            },
            _ => {
                host_info.ports.push(port_info);
                scan_result.lock().unwrap().host_scan_result.hosts.push(host_info.clone());
                match host_info.ip_addr {
                    IpAddr::V4(ip) => {
                        scan_result.lock().unwrap().ip_set.insert(IpAddr::V4(ip));
                    },
                    IpAddr::V6(ip) => {
                        scan_result.lock().unwrap().ip_set.insert(IpAddr::V6(ip));
                    },
                }
            },
        }
    }else if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::RST | pnet_packet::tcp::TcpFlags::ACK {
        let port_info = PortInfo{
            port: socket_addr.port(),
            status: PortStatus::Closed,
        };
        match scan_setting.scan_type {
            ScanType::TcpSynScan => {
                if !scan_result.lock().unwrap().socket_set.contains(&socket_addr) {
                    // Avoid deadlock.
                    let mut exists: bool = false;
                    for host in scan_result.lock().unwrap().port_scan_result.results.iter_mut() {
                        if host.ip_addr == socket_addr.ip() {
                            host.ports.push(port_info);
                            exists = true;
                        }
                    }
                    if !exists {
                        let mut host = HostInfo::new();
                        host.ip_addr = socket_addr.ip();
                        host.host_name = host_info.host_name;
                        host.ttl = host_info.ttl;
                        host.ports.push(port_info);
                        scan_result.lock().unwrap().port_scan_result.results.push(host);
                    }
                    scan_result.lock().unwrap().socket_set.insert(socket_addr);    
                }
            },
            _ => {
                host_info.ports.push(port_info);
                scan_result.lock().unwrap().host_scan_result.hosts.push(host_info.clone());
                match host_info.ip_addr {
                    IpAddr::V4(ip) => {
                        scan_result.lock().unwrap().ip_set.insert(IpAddr::V4(ip));
                    },
                    IpAddr::V6(ip) => {
                        scan_result.lock().unwrap().ip_set.insert(IpAddr::V6(ip));
                    },
                }
            },
        }
    }
}

fn handle_udp_packet(_udp_packet: pnet_packet::udp::UdpPacket, _scan_setting: &ScanSetting, _scan_result: &Arc<Mutex<ScanResult>>) {

}
