use std::thread;
use std::sync::{Arc, Mutex};
use pnet::packet::Packet;
use std::time::{Duration, Instant};
use rayon::prelude::*;
use std::net::{IpAddr, ToSocketAddrs, TcpStream};
use crate::{tcp, ipv4, ethernet};
use crate::packet::EndPoints;
use crate::scanner::shared::{PortScanType, ScanStatus, PortInfo, PortStatus};
use crate::PortScanner;

pub fn scan_ports(interface: &pnet::datalink::NetworkInterface, scanner: &PortScanner) -> (Vec<PortInfo>, ScanStatus)
{
    let mut result = vec![];
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let open_ports: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(vec![]));
    let scan_status: Arc<Mutex<ScanStatus>> = Arc::new(Mutex::new(ScanStatus::Ready));
    // run port scan
    match scanner.scan_type {
        PortScanType::ConnectScan => {
            run_connect_scan(scanner, &open_ports, &stop, &scan_status);
        },
        PortScanType::SynScan => {
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
            let (mut tx, mut rx) = match pnet::datalink::channel(&interface, config) {
                Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unknown channel type"),
                Err(e) => panic!("Error happened {}", e),
            };
            rayon::join(|| send_packets(&mut tx, scanner, &stop),
                        || receive_packets(&mut rx, scanner, &open_ports, &stop, &scan_status)
            );
        }
    }
    open_ports.lock().unwrap().sort();
    for port in open_ports.lock().unwrap().iter() {
        let port_info = PortInfo {
            port: port.clone(),
            status: PortStatus::Open,
        };
        result.push(port_info);
    }
    return (result, *scan_status.lock().unwrap());
}

fn build_packet(scanner: &PortScanner, tmp_packet: &mut [u8], target_port: u16){
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(&mut tmp_packet[..ethernet::ETHERNET_HEADER_LEN]).unwrap();
    ethernet::build_ethernet_packet(&mut eth_header, scanner.src_mac, scanner.dst_mac, ethernet::EtherType::Ipv4);
    // Setup IP header
    let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(&mut tmp_packet[ethernet::ETHERNET_HEADER_LEN..(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)]).unwrap();
    match scanner.src_ip {
        IpAddr::V4(src_ip) => {
            match scanner.dst_ip {
                IpAddr::V4(dst_ip) => {
                    ipv4::build_ipv4_packet(&mut ip_header, src_ip, dst_ip, ipv4::IpNextHeaderProtocol::Tcp);
                    // Setup TCP header
                    let mut tcp_header = pnet::packet::tcp::MutableTcpPacket::new(&mut tmp_packet[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..]).unwrap();
                    tcp::build_tcp_packet(&mut tcp_header, src_ip, scanner.src_port, dst_ip, target_port);
                },
                IpAddr::V6(_ip) => {},
            }
        },
        IpAddr::V6(_ip) => {},
    }
}

fn send_packets(tx: &mut Box<dyn pnet::datalink::DataLinkSender>, scanner: &PortScanner, stop: &Arc<Mutex<bool>>) {
    for port in scanner.dst_ports.clone() {
        tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
            build_packet(scanner, packet, port);
        });
        thread::sleep(scanner.send_rate);
    }
    thread::sleep(scanner.wait_time);
    *stop.lock().unwrap() = true;
}

fn receive_packets(
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>, 
    scanner: &PortScanner, 
    open_ports: &Arc<Mutex<Vec<u16>>>,  
    stop: &Arc<Mutex<bool>>, 
    scan_status: &Arc<Mutex<ScanStatus>>) {
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = pnet::packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet::packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, scanner, &open_ports);
                    },
                    pnet::packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, scanner, &open_ports);
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
        if Instant::now().duration_since(start_time) > scanner.timeout {
            *scan_status.lock().unwrap() = ScanStatus::Timeout;
            break;
        }
    }
}

fn ipv4_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, scanner: &PortScanner, open_ports: &Arc<Mutex<Vec<u16>>>) {
    if let Some(packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()){
        match packet.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet, scanner, &open_ports);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler(&packet, scanner, &open_ports);
            },
            _ => {}
        }
    }
}

fn ipv6_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, scanner: &PortScanner, open_ports: &Arc<Mutex<Vec<u16>>>) {
    if let Some(packet) = pnet::packet::ipv6::Ipv6Packet::new(ethernet.payload()){
        match packet.get_next_header() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet, scanner, &open_ports);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler(&packet, scanner, &open_ports);
            },
            _ => {}
        }
    }
}

fn tcp_handler(packet: &dyn EndPoints, scanner: &PortScanner, open_ports: &Arc<Mutex<Vec<u16>>>) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.get_payload());
    if let Some(tcp) = tcp {
        match scanner.scan_type {
            PortScanType::SynScan => {
                if tcp.get_flags() == pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK {
                    append_packet_info(packet, &tcp, scanner, &open_ports);
                }
            },
            _ => {
                if tcp.get_flags() == pnet::packet::tcp::TcpFlags::RST {
                    append_packet_info(packet, &tcp, scanner, &open_ports);
                }
            },
        }
    }
}

fn udp_handler(packet: &dyn EndPoints, scanner: &PortScanner, open_ports: &Arc<Mutex<Vec<u16>>>) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.get_payload());
    if let Some(udp) = udp {
        append_packet_info(packet, &udp, scanner, &open_ports);
    }
}

fn append_packet_info(_l3: &dyn EndPoints, l4: &dyn EndPoints, scanner: &PortScanner, open_ports: &Arc<Mutex<Vec<u16>>>) {
    if l4.get_destination() == scanner.src_port.to_string() {
        if !open_ports.lock().unwrap().contains(&l4.get_source().parse::<u16>().unwrap()){
            open_ports.lock().unwrap().push(l4.get_source().parse::<u16>().unwrap());
        }
    }
}

fn run_connect_scan(scanner: &PortScanner, open_ports: &Arc<Mutex<Vec<u16>>>, stop: &Arc<Mutex<bool>>, scan_status: &Arc<Mutex<ScanStatus>>){
    let ip_addr = scanner.dst_ip.clone();
    let ports = scanner.dst_ports.clone();
    let timeout = scanner.timeout.clone();
    let conn_timeout = Duration::from_millis(50);
    let start_time = Instant::now();
    ports.into_par_iter().for_each(|port| 
        {
            let socket_addr_str = format!("{}:{}", ip_addr, port);
            let mut addrs = socket_addr_str.to_socket_addrs().unwrap();
            if let Some(addr) = addrs.find(|x| (*x).is_ipv4()) {
                match TcpStream::connect_timeout(&addr, conn_timeout) {
                    Ok(_) => {
                        open_ports.lock().unwrap().push(port);
                    },
                    Err(_) => {},
                }
            }
            if Instant::now().duration_since(start_time) > timeout {
                *scan_status.lock().unwrap() = ScanStatus::Timeout;
                *stop.lock().unwrap() = true;
                return;
            }
        }
    );
    *scan_status.lock().unwrap() = ScanStatus::Done;
    *stop.lock().unwrap() = true;
}
