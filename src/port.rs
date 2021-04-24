use crate::{tcp, ipv4, ethernet};
use crate::packet::EndPoints;
use crate::status::ScanStatus;
use std::{thread, time};
use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;
use pnet::datalink::MacAddr;
use pnet::packet::Packet;
use std::time::{Duration, Instant};

/// Type of port scan 
/// 
/// Supports SynScan, FinScan, XmasScan, NullScan, UdpScan.
#[derive(Clone, Copy)]
pub enum PortScanType {
    SynScan = pnet::packet::tcp::TcpFlags::SYN as isize,
    FinScan = pnet::packet::tcp::TcpFlags::FIN as isize,
    XmasScan = pnet::packet::tcp::TcpFlags::FIN as isize | pnet::packet::tcp::TcpFlags::URG as isize | pnet::packet::tcp::TcpFlags::PSH as isize,
    NullScan = 0,
}

pub struct PortScanOptions {
    pub sender_mac: MacAddr,
    pub target_mac: MacAddr,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,    
    pub src_port: u16,
    pub target_ports: Vec<u16>,
    pub scan_type: PortScanType,
    pub timeout: Duration,
    pub wait_time: Duration,
}

pub fn scan_ports(interface: &pnet::datalink::NetworkInterface, scan_options: &PortScanOptions) -> (Vec<String>, ScanStatus)
{
    let mut result = vec![];
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let open_ports: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let close_ports: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let scan_status: Arc<Mutex<ScanStatus>> = Arc::new(Mutex::new(ScanStatus::Ready));
    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    rayon::join(|| send_packets(&mut tx, &scan_options, &stop),
                || receive_packets(&mut rx, &scan_options, &open_ports, &close_ports, &stop, &scan_status)
    );
    match scan_options.scan_type {
        PortScanType::SynScan | PortScanType::FinScan => {
            for port in open_ports.lock().unwrap().iter(){
                result.push(port.to_string());
            }
        },
        PortScanType::XmasScan | PortScanType::NullScan => {
            if close_ports.lock().unwrap().len() > 0 {
                for port in &scan_options.target_ports {
                    if !close_ports.lock().unwrap().contains(&port.to_string()){
                        result.push(port.to_string());
                    }
                }
            }
        },
    }
    return (result, *scan_status.lock().unwrap());
}

fn build_packet(scan_options: &PortScanOptions, tmp_packet: &mut [u8], target_port: u16){
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(&mut tmp_packet[..ethernet::ETHERNET_HEADER_LEN]).unwrap();
    ethernet::build_ethernet_packet(&mut eth_header, scan_options.sender_mac, scan_options.target_mac, ethernet::EtherType::Ipv4);
    // Setup IP header
    let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(&mut tmp_packet[ethernet::ETHERNET_HEADER_LEN..(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)]).unwrap();
    match scan_options.scan_type {
        _ => {
            ipv4::build_ipv4_packet(&mut ip_header, scan_options.src_ip, scan_options.dst_ip, ipv4::IpNextHeaderProtocol::Tcp);
            // Setup TCP header
            let mut tcp_header = pnet::packet::tcp::MutableTcpPacket::new(&mut tmp_packet[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..]).unwrap();
            tcp::build_tcp_packet(&mut tcp_header, scan_options.src_ip, scan_options.src_port, scan_options.dst_ip, target_port, &scan_options.scan_type);
        },
    }
}

fn send_packets(tx: &mut Box<dyn pnet::datalink::DataLinkSender>, scan_options: &PortScanOptions, stop: &Arc<Mutex<bool>>) {
    for port in &scan_options.target_ports {
        thread::sleep(time::Duration::from_millis(1));
        tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
            build_packet(&scan_options, packet, *port);
        });
    }
    thread::sleep(scan_options.wait_time);
    *stop.lock().unwrap() = true;
}

fn receive_packets(
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>, 
    scan_options: &PortScanOptions, 
    open_ports: &Arc<Mutex<Vec<String>>>, 
    close_ports: &Arc<Mutex<Vec<String>>>, 
    stop: &Arc<Mutex<bool>>, 
    scan_status: &Arc<Mutex<ScanStatus>>) {
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = pnet::packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet::packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, &scan_options, &open_ports, &close_ports);
                    },
                    pnet::packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, &scan_options, &open_ports, &close_ports);
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
        if Instant::now().duration_since(start_time) > scan_options.timeout {
            *scan_status.lock().unwrap() = ScanStatus::Timeout;
            break;
        }
    }
}

fn ipv4_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, scan_options: &PortScanOptions, open_ports: &Arc<Mutex<Vec<String>>>, close_ports: &Arc<Mutex<Vec<String>>>) {
    if let Some(packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()){
        match packet.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet, &scan_options, &open_ports, &close_ports);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler(&packet, &scan_options, &open_ports, &close_ports);
            },
            _ => {}
        }
    }
}

fn ipv6_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, scan_options: &PortScanOptions, open_ports: &Arc<Mutex<Vec<String>>>, close_ports: &Arc<Mutex<Vec<String>>>) {
    if let Some(packet) = pnet::packet::ipv6::Ipv6Packet::new(ethernet.payload()){
        match packet.get_next_header() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler(&packet, &scan_options, &open_ports, &close_ports);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler(&packet, &scan_options, &open_ports, &close_ports);
            },
            _ => {}
        }
    }
}

fn tcp_handler(packet: &dyn EndPoints, scan_options: &PortScanOptions, open_ports: &Arc<Mutex<Vec<String>>>, close_ports: &Arc<Mutex<Vec<String>>>) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.get_payload());
    if let Some(tcp) = tcp {
        append_packet_info(packet, &tcp, &scan_options, &open_ports, &close_ports);
    }
}

fn udp_handler(packet: &dyn EndPoints, scan_options: &PortScanOptions, open_ports: &Arc<Mutex<Vec<String>>>, close_ports: &Arc<Mutex<Vec<String>>>) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.get_payload());
    if let Some(udp) = udp {
        append_packet_info(packet, &udp, &scan_options, &open_ports, &close_ports);
    }
}

fn append_packet_info(_l3: &dyn EndPoints, l4: &dyn EndPoints, scan_options: &PortScanOptions, open_ports: &Arc<Mutex<Vec<String>>>, close_ports: &Arc<Mutex<Vec<String>>>) {
    match scan_options.scan_type {
        PortScanType::SynScan | PortScanType::FinScan => {
            if l4.get_destination() == scan_options.src_port.to_string() {
                if !open_ports.lock().unwrap().contains(&l4.get_source()){
                    open_ports.lock().unwrap().push(l4.get_source());
                }
            }
        },
        PortScanType::XmasScan | PortScanType::NullScan => {
            if l4.get_destination() == scan_options.src_port.to_string() {
                if !close_ports.lock().unwrap().contains(&l4.get_source()){
                    close_ports.lock().unwrap().push(l4.get_source());
                }
            }
        },
    }
}
