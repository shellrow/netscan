use crate::packet::icmp;
use crate::scanner::shared::HostScanner;
use std::{thread, time};
use std::time::{Duration, Instant};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::icmp_packet_iter;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::transport::{TransportSender, transport_channel};
use pnet::packet::Packet;
use rayon::prelude::*;
use std::net::{ToSocketAddrs,TcpStream};
use crate::packet::endpoint::EndPoints;
use crate::PortScanner;
use crate::base_type::{PortScanType, PortStatus, PortInfo, ScanStatus};
use crate::packet::ethernet;
use crate::packet::ipv4;

pub fn scan_hosts(scanner: &HostScanner) ->(Vec<String>, ScanStatus)
{
    let mut result = vec![];
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let up_hosts:Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(vec![]));
    let scan_status: Arc<Mutex<ScanStatus>> = Arc::new(Mutex::new(ScanStatus::Ready));
    let protocol = Layer4(Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match pnet::transport::transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("Error happened {}", e),
    };
    rayon::join(|| send_icmp_packet(&mut tx, &stop, scanner),
                || receive_icmp_packets(&mut rx, scanner, &stop, &up_hosts, &scan_status)
    );
    up_hosts.lock().unwrap().sort();
    for host in up_hosts.lock().unwrap().iter(){
        result.push(host.to_string());
    }
    return (result, *scan_status.lock().unwrap());
}

fn send_icmp_packet(tx: &mut pnet::transport::TransportSender, stop: &Arc<Mutex<bool>>, scanner: &HostScanner){
    for host in &scanner.dst_ips {
        thread::sleep(time::Duration::from_millis(1));
        let mut buf = vec![0; 16];
        let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
        icmp::build_icmp_packet(&mut icmp_packet);
        let _result = tx.send_to(icmp_packet, *host);
    }
    thread::sleep(scanner.wait_time);
    *stop.lock().unwrap() = true;
}

fn receive_icmp_packets(
    rx: &mut pnet::transport::TransportReceiver, 
    scanner: &HostScanner,
    stop: &Arc<Mutex<bool>>, 
    up_hosts: &Arc<Mutex<Vec<IpAddr>>>, 
    scan_status: &Arc<Mutex<ScanStatus>>){
    let mut iter = icmp_packet_iter(rx);
    let start_time = Instant::now();
    loop {
        match iter.next_with_timeout(time::Duration::from_millis(100)) {
            Ok(r) => {
                if let Some((_packet, addr)) = r {
                    if scanner.dst_ips.contains(&addr) && !up_hosts.lock().unwrap().contains(&addr) {
                        up_hosts.lock().unwrap().push(addr);
                    }
                }else{
                    error!("Failed to read packet");
                }
            },
            Err(e) => {
                error!("An error occurred while reading: {}", e);
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
            run_syn_scan(interface, scanner, &open_ports, &stop, &scan_status);
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

fn run_syn_scan(interface: &pnet::datalink::NetworkInterface, scanner: &PortScanner,open_ports: &Arc<Mutex<Vec<u16>>>, stop: &Arc<Mutex<bool>>, scan_status: &Arc<Mutex<ScanStatus>>) {
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
    let (mut _tx, mut rx) = match pnet::datalink::channel(&interface, config) {
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
    rayon::join(|| send_tcp_packets(&mut tx, scanner, &stop),
                || receive_tcp_packets(&mut rx, scanner, &open_ports, &stop, &scan_status)
    );
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

fn send_tcp_packets(tx: &mut TransportSender, scanner: &PortScanner, stop: &Arc<Mutex<bool>>) {
    for port in scanner.dst_ports.clone() {
        let src_ip: IpAddr = scanner.src_ip;
        let dst_ip: IpAddr = scanner.dst_ip;
        let mut vec: Vec<u8> = vec![0; 66];
        let mut tcp_packet = MutableTcpPacket::new(&mut vec[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..]).unwrap();
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
        let checksum: u16 = match src_ip {
            IpAddr::V4(src_ipv4) => {
                match dst_ip {
                    IpAddr::V4(dst_ipv4) => {
                        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ipv4, &dst_ipv4)
                    },
                    IpAddr::V6(_) => 0,
                }
            },
            IpAddr::V6(src_ipv6) => {
                match dst_ip {
                    IpAddr::V4(_) => 0,
                    IpAddr::V6(dst_ipv6) => {
                        pnet::packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_ipv6, &dst_ipv6)
                    },
                }
            },
        };
        tcp_packet.set_checksum(checksum);

        match tx.send_to(tcp_packet, dst_ip) {
            Ok(_) => {},
            Err(_) => {},
        }
        thread::sleep(scanner.send_rate);
    }
    thread::sleep(scanner.wait_time);
    *stop.lock().unwrap() = true;
}

fn receive_tcp_packets(
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
