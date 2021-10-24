use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::net::IpAddr;
use pnet::packet::Packet;
use tokio::sync::Mutex as TokioMutex;
use crate::base_type::{ScanStatus, PortInfo, PortStatus, ScanSetting, ScanResult};

pub fn receive_packets(
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>, 
    scan_setting: &ScanSetting, 
    scan_result: &Arc<Mutex<ScanResult>>,  
    stop: &Arc<Mutex<bool>>, 
    scan_status: &Arc<Mutex<ScanStatus>>) {
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = pnet::packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet::packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, scan_setting, &scan_result);
                    },
                    pnet::packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, scan_setting, &scan_result);
                    },
                    _ => {},
                }
            },
            Err(e) => {
                panic!("Failed to read: {}", e);
            }
        }
        if *stop.lock().unwrap(){
            *scan_status.lock().unwrap() = ScanStatus::Done;
            break;
        }
        if Instant::now().duration_since(start_time) > scan_setting.timeout {
            *scan_status.lock().unwrap() = ScanStatus::Timeout;
            break;
        }
    }
}

pub async fn receive_packets_async(rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>, stop: &Arc<TokioMutex<bool>>, scan_status: &Arc<TokioMutex<ScanStatus>>) {
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = pnet::packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet::packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, scan_setting, &scan_result);
                    },
                    pnet::packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, scan_setting, &scan_result);
                    },
                    _ => {},
                }
            },
            Err(e) => {
                panic!("Failed to read: {}", e);
            }
        }
        if *stop.lock().await {
            *scan_status.lock().await = ScanStatus::Done;
            break;
        }
        if Instant::now().duration_since(start_time) > scan_setting.timeout {
            *scan_status.lock().await = ScanStatus::Timeout;
            break;
        }
    }
}

fn ipv4_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    if let Some(packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()){
        match packet.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler_v4(&packet, scan_setting, scan_result);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler_v4(&packet, scan_setting, scan_result);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                icmp_handler_v4(&packet, scan_setting, scan_result);
            }
            _ => {}
        }
    }
}

fn ipv6_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    if let Some(packet) = pnet::packet::ipv6::Ipv6Packet::new(ethernet.payload()){
        match packet.get_next_header() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler_v6(&packet, scan_setting, scan_result);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler_v6(&packet, scan_setting, scan_result);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                icmp_handler_v6(&packet, scan_setting, scan_result);
            },
            _ => {}
        }
    }
}

fn tcp_handler_v4(packet: &pnet::packet::ipv4::Ipv4Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let tcp_packet = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp_packet) = tcp_packet {
        handle_tcp_packet(tcp_packet, scan_setting, scan_result);
    }
}

fn tcp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let tcp_packet = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp_packet) = tcp_packet {
        handle_tcp_packet(tcp_packet, scan_setting, scan_result);
    }
}

fn udp_handler_v4(packet: &pnet::packet::ipv4::Ipv4Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        handle_udp_packet(udp, scan_setting, scan_result);
    }
}

fn udp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        handle_udp_packet(udp, scan_setting, scan_result);
    }
}

fn icmp_handler_v4(packet: &pnet::packet::ipv4::Ipv4Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let icmp_packet = pnet::packet::icmp::IcmpPacket::new(packet.payload());
    if let Some(_icmp) = icmp_packet {
        if scan_setting.dst_ips.contains(&IpAddr::V4(packet.get_source())) && !scan_result.lock().unwrap().hosts.contains(&IpAddr::V4(packet.get_source())) {
            scan_result.lock().unwrap().hosts.push(IpAddr::V4(packet.get_source()));
        }
    }
}

fn icmp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    let icmp_packet = pnet::packet::icmp::IcmpPacket::new(packet.payload());
    if let Some(_icmp) = icmp_packet {
        if scan_setting.dst_ips.contains(&IpAddr::V6(packet.get_source())) && !scan_result.lock().unwrap().hosts.contains(&IpAddr::V6(packet.get_source())) {
            scan_result.lock().unwrap().hosts.push(IpAddr::V6(packet.get_source()));
        }
    }
}

fn handle_tcp_packet(tcp_packet: pnet::packet::tcp::TcpPacket, _scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>) {
    if tcp_packet.get_flags() == pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK {
        scan_result.lock().unwrap().ports.push(
            PortInfo{
                port: tcp_packet.get_source(),
                status: PortStatus::Open,
            }
        );
    }else if tcp_packet.get_flags() == pnet::packet::tcp::TcpFlags::RST | pnet::packet::tcp::TcpFlags::ACK {
        scan_result.lock().unwrap().ports.push(
            PortInfo{
                port: tcp_packet.get_source(),
                status: PortStatus::Closed,
            }
        );
    }
}

fn handle_udp_packet(_udp_packet: pnet::packet::udp::UdpPacket, _scan_setting: &ScanSetting, _scan_result: &Arc<Mutex<ScanResult>>) {

}
