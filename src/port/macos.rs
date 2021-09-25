use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{TransportSender, transport_channel};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::sync::{Arc, Mutex};
use pnet::packet::Packet;
use std::time::{Duration, Instant};
use rayon::prelude::*;
use std::net::{ToSocketAddrs,TcpStream};
use crate::packet::EndPoints;
use crate::status::ScanStatus;
use crate::PortScanner;

/// Type of port scan 
/// 
/// Supports SynScan, ConnectScan
#[derive(Clone, Copy)]
pub enum PortScanType {
    SynScan = pnet::packet::tcp::TcpFlags::SYN as isize,
    ConnectScan = 401,
}

pub fn scan_ports(interface: &pnet::datalink::NetworkInterface, scanner: &PortScanner) -> (Vec<u16>, ScanStatus)
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
            let (mut _tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
                Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unknown channel type"),
                Err(e) => panic!("Error happened {}", e),
            };
            let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
            let (mut tx, mut _rx) = match transport_channel(4096, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => panic!(
                    "An error occurred when creating the transport channel: {}",
                    e
                ),
            };
            rayon::join(|| send_packets(&mut tx, scanner, &stop),
                        || receive_packets(&mut rx, scanner, &open_ports, &stop, &scan_status)
            );
        }
    }
    for port in open_ports.lock().unwrap().iter(){
        result.push(port.clone());
    }
    result.sort();
    return (result, *scan_status.lock().unwrap());
}

fn send_packets(tx: &mut TransportSender, scanner: &PortScanner, stop: &Arc<Mutex<bool>>) {
    for port in scanner.dst_ports.clone() {
        let src_ip_addr: Ipv4Addr = scanner.src_ipaddr;
        let dst_ip_addr: Ipv4Addr = scanner.dst_ipaddr;
        let mut vec: Vec<u8> = vec![0; 1024];
        let mut tcp_packet = MutableTcpPacket::new(&mut vec[..]).unwrap();
        tcp_packet.set_source(scanner.src_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(8);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_sequence(0);
        tcp_packet.set_options(&[pnet::packet::tcp::TcpOption::mss(1460)
        , pnet::packet::tcp::TcpOption::sack_perm()
        , pnet::packet::tcp::TcpOption::nop()
        , pnet::packet::tcp::TcpOption::nop()
        , pnet::packet::tcp::TcpOption::wscale(7)]);
        tcp_packet.set_flags(pnet::packet::tcp::TcpFlags::SYN);
        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip_addr, &dst_ip_addr);
        tcp_packet.set_checksum(checksum);

        match tx.send_to(tcp_packet, IpAddr::V4(dst_ip_addr)) {
            Ok(_) => {},
            Err(_) => {},
        }
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
        if tcp.get_flags() == pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK {
            append_packet_info(packet, &tcp, scanner, &open_ports);
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
    let ip_addr = scanner.dst_ipaddr.clone();
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
