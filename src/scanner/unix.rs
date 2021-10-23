use crate::packet::icmp;
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
use rayon::prelude::*;
use std::net::{ToSocketAddrs,TcpStream};
use crate::base_type::{PortScanType, PortStatus, PortInfo, ScanStatus, ScanSetting, ScanResult};
use crate::packet::ethernet;
use crate::packet::ipv4;
use crate::scan;

pub fn scan_hosts(_interface: &pnet::datalink::NetworkInterface, scan_setting: &ScanSetting) ->(Vec<IpAddr>, ScanStatus)
{
    let mut result = vec![];
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let scan_status: Arc<Mutex<ScanStatus>> = Arc::new(Mutex::new(ScanStatus::Ready));
    let protocol = Layer4(Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match pnet::transport::transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("Error happened {}", e),
    };
    rayon::join(|| send_icmp_packet(&mut tx, &stop, scan_setting),
                || receive_icmp_packets(&mut rx, scan_setting, &stop, &scan_result, &scan_status)
    );
    scan_result.lock().unwrap().hosts.sort();
    for host in scan_result.lock().unwrap().hosts.iter(){
        result.push(host.clone());
    }
    return (result, *scan_status.lock().unwrap());
}

fn send_icmp_packet(tx: &mut pnet::transport::TransportSender, stop: &Arc<Mutex<bool>>, scan_setting: &ScanSetting){
    for host in &scan_setting.dst_ips {
        let mut buf = vec![0; 16];
        let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
        icmp::build_icmp_packet(&mut icmp_packet);
        let _result = tx.send_to(icmp_packet, *host);
        thread::sleep(scan_setting.send_rate);
    }
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
}

fn receive_icmp_packets(
    rx: &mut pnet::transport::TransportReceiver, 
    scan_setting: &ScanSetting,
    stop: &Arc<Mutex<bool>>, 
    scan_result: &Arc<Mutex<ScanResult>>, 
    scan_status: &Arc<Mutex<ScanStatus>>){
    let mut iter = icmp_packet_iter(rx);
    let start_time = Instant::now();
    loop {
        match iter.next_with_timeout(time::Duration::from_millis(100)) {
            Ok(r) => {
                if let Some((_packet, addr)) = r {
                    if scan_setting.dst_ips.contains(&addr) && !scan_result.lock().unwrap().hosts.contains(&addr) {
                        scan_result.lock().unwrap().hosts.push(addr);
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
        if Instant::now().duration_since(start_time) > scan_setting.timeout {
            *scan_status.lock().unwrap() = ScanStatus::Timeout;
            break;
        }
    }
}

pub fn scan_ports(interface: &pnet::datalink::NetworkInterface, scan_setting: &ScanSetting) -> (Vec<PortInfo>, ScanStatus)
{
    let mut result = vec![];
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let scan_status: Arc<Mutex<ScanStatus>> = Arc::new(Mutex::new(ScanStatus::Ready));
    let scan_status_receive = Arc::clone(&scan_status);
    // run port scan
    match scan_setting.scan_type.unwrap() {
        PortScanType::ConnectScan => {
            run_connect_scan(scan_setting, &scan_result, &stop, &scan_status_receive);
        },
        PortScanType::SynScan => {
            run_syn_scan(interface, scan_setting, &scan_result, &stop, &scan_status_receive);
        }
    }
    for port_info in scan_result.lock().unwrap().ports.iter() {
        result.push(port_info.clone());
    }
    let scan_status = *scan_status.lock().unwrap();
    (result, scan_status)
}

fn run_syn_scan(interface: &pnet::datalink::NetworkInterface, scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>, stop: &Arc<Mutex<bool>>, scan_status: &Arc<Mutex<ScanStatus>>) {
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
    rayon::join(|| send_tcp_packets(&mut tx, scan_setting, &stop),
                || scan::receive::receive_packets(&mut rx, scan_setting, &scan_result, &stop, &scan_status)
    );
}

fn run_connect_scan(scan_setting: &ScanSetting, scan_result: &Arc<Mutex<ScanResult>>, stop: &Arc<Mutex<bool>>, scan_status: &Arc<Mutex<ScanStatus>>){
    let ip_addr = scan_setting.dst_ip.clone();
    let ports = scan_setting.dst_ports.clone();
    let timeout = scan_setting.timeout.clone();
    let conn_timeout = Duration::from_millis(50);
    let start_time = Instant::now();
    ports.into_par_iter().for_each(|port| 
        {
            let socket_addr_str = format!("{}:{}", ip_addr, port);
            let mut addrs = socket_addr_str.to_socket_addrs().unwrap();
            if let Some(addr) = addrs.find(|x| (*x).is_ipv4()) {
                match TcpStream::connect_timeout(&addr, conn_timeout) {
                    Ok(_) => {
                        scan_result.lock().unwrap().ports.push(
                            PortInfo{
                                port: port,
                                status: PortStatus::Open,
                            }
                        );
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

fn send_tcp_packets(tx: &mut TransportSender, scan_setting: &ScanSetting, stop: &Arc<Mutex<bool>>) {
    for port in scan_setting.dst_ports.clone() {
        let src_ip: IpAddr = scan_setting.src_ip;
        let dst_ip: IpAddr = scan_setting.dst_ip;
        let mut vec: Vec<u8> = vec![0; 66];
        let mut tcp_packet = MutableTcpPacket::new(&mut vec[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..]).unwrap();
        tcp_packet.set_source(scan_setting.src_port);
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
        thread::sleep(scan_setting.send_rate);
    }
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
}

