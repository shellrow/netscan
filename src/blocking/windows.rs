use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use pnet_packet::ethernet::EtherTypes;
use pnet_packet::ip::IpNextHeaderProtocols;
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

fn send_packets(tx: &mut Box<dyn pnet_datalink::DataLinkSender>, scan_setting: &ScanSetting, stop: &Arc<Mutex<bool>>) {
    match scan_setting.scan_type {
        ScanType::TcpSynScan | ScanType::TcpPingScan => {
            for dst in scan_setting.destinations.clone() {
                let dst_ip: IpAddr = dst.dst_ip;
                for port in dst.dst_ports {
                    tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                        build_tcp_syn_packet(scan_setting, packet, dst_ip, port);
                    });
                    thread::sleep(scan_setting.send_rate);
                }
            }
        },
        ScanType::UdpPingScan => {
            for dst in scan_setting.destinations.clone() {
                let dst_ip: IpAddr = dst.dst_ip;
                for port in dst.dst_ports {
                    tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                        build_udp_packet(scan_setting, packet, dst_ip, port);
                    });
                    thread::sleep(scan_setting.send_rate);
                }
            }
        },
        ScanType::IcmpPingScan => {
            for dst in scan_setting.destinations.clone() {
                tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                    build_icmp_echo_packet(scan_setting, packet, dst.dst_ip);
                });
                thread::sleep(scan_setting.send_rate);
            }
        },
        _ => {},
    }
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
}

pub fn scan_hosts(scan_setting: ScanSetting) -> HostScanResult {
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
    rayon::join(|| send_packets(&mut tx, &scan_setting, &stop),
                || receiver::receive_packets(&mut rx, receive_setting, &scan_result, &stop)
    );
    let result: HostScanResult = scan_result.lock().unwrap().host_scan_result.clone(); 
    return result;
}

pub fn scan_ports(scan_setting: ScanSetting) -> PortScanResult {
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
    rayon::join(|| send_packets(&mut tx, &scan_setting, &stop),
                || receiver::receive_packets(&mut rx, receive_setting, &scan_result, &stop)
    );
    let result: PortScanResult = scan_result.lock().unwrap().port_scan_result.clone(); 
    return result;
}
