use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use std::thread;
use std::sync::Mutex;
use tokio::sync::Mutex as TokioMutex;
use pnet::packet::{tcp, Packet};
use crate::base_type::{PortStatus, PortInfo, ScanStatus};
use crate::packet::endpoint::EndPoints;
use crate::packet::ethernet;
use crate::packet::ipv4;
use crate::async_scanner::AsyncPortScanner;

#[derive(Clone, Debug)]
pub struct AsyncSocket {
    inner: Arc<AsyncFd<Socket>>,
}

impl AsyncSocket {
    pub fn new(addr: IpAddr, protocol: Protocol) -> io::Result<AsyncSocket> {
        let socket = match addr {
            IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::RAW, Some(protocol))?,
            IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::RAW, Some(protocol))?,
        };
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(AsyncFd::new(socket)?),
        })
    }
    pub async fn send_to(&self, buf: &mut [u8], target: &SockAddr) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, target)) {
                Ok(n) => return n,
                Err(_) => continue,
            }
        }
    }
    #[allow(dead_code)]
    pub async fn recv(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| inner.get_ref().recv(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

async fn build_syn_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut tcp_packet = tcp::MutableTcpPacket::new(&mut vec[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..]).unwrap();
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_sequence(0);
    tcp_packet.set_options(&[tcp::TcpOption::mss(1460)
    , tcp::TcpOption::sack_perm()
    , tcp::TcpOption::nop()
    , tcp::TcpOption::nop()
    , tcp::TcpOption::wscale(7)]);
    tcp_packet.set_flags(tcp::TcpFlags::SYN);
    let checksum: u16 = match src_ip {
        IpAddr::V4(src_ipv4) => {
            match dst_ip {
                IpAddr::V4(dst_ipv4) => {
                    tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ipv4, &dst_ipv4)
                },
                IpAddr::V6(_) => return tcp_packet.packet().to_vec(),
            }
        },
        IpAddr::V6(src_ipv6) => {
            match dst_ip {
                IpAddr::V4(_) => return tcp_packet.packet().to_vec(),
                IpAddr::V6(dst_ipv6) => {
                    tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_ipv6, &dst_ipv6)
                },
            }
        },
    };
    tcp_packet.set_checksum(checksum);
    tcp_packet.packet().to_vec()
}

pub async fn scan_ports(scanner: AsyncPortScanner) -> (Vec<PortInfo>, ScanStatus) {
    let mut result: Vec<PortInfo> = vec![];
    let async_socket = match AsyncSocket::new(scanner.src_ip.clone(), Protocol::TCP) {
        Ok(socket) => socket,
        Err(_) => return (result, ScanStatus::Error),
    };
    let port_results: Arc<Mutex<Vec<PortInfo>>> = Arc::new(Mutex::new(vec![]));
    let stop: Arc<TokioMutex<bool>> = Arc::new(TokioMutex::new(false));
    let src_ip = scanner.src_ip.clone();
    let src_port = scanner.src_port.clone();
    let dst_ip = scanner.dst_ip.clone();
    let default_index = default_net::get_default_interface_index().unwrap();
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == default_index).next().expect("Failed to get Interface");
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
    let stop_receive = Arc::clone(&stop);
    let port_results_receive = Arc::clone(&port_results);
    tokio::spawn(async move {
        receive_packets(&mut rx, &stop_receive, &port_results_receive).await;
    });
    for port in scanner.dst_ports.clone() {
        let socket = async_socket.clone();
        let mut syn_packet: Vec<u8> = build_syn_packet(src_ip, src_port, dst_ip, port).await;
        let socket_addr = SocketAddr::new(dst_ip, port);
        let sock_addr = SockAddr::from(socket_addr);
        tokio::spawn(async move {
            match socket.send_to(&mut syn_packet, &sock_addr).await {
                Ok(_) => {},
                Err(_) => {},       
            }
        });
    }
    thread::sleep(scanner.wait_time);
    *stop.lock().await = true;
    for port_info in port_results.lock().unwrap().iter() {
        result.push(port_info.clone());
    }
    (result, ScanStatus::Done)
}

async fn receive_packets(rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>, stop: &Arc<TokioMutex<bool>>, port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = pnet::packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet::packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, port_results);
                    },
                    pnet::packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, port_results);
                    },
                    _ => {},
                }
            },
            Err(e) => {
                panic!("Failed to read: {}", e);
            }
        }
        if *stop.lock().await {
            break;
        }
    }
}

fn ipv4_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    if let Some(packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()){
        match packet.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler_v4(&packet, port_results);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler_v4(&packet, port_results);
            },
            _ => {}
        }
    }
}

fn ipv6_handler(ethernet: &pnet::packet::ethernet::EthernetPacket, port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    if let Some(packet) = pnet::packet::ipv6::Ipv6Packet::new(ethernet.payload()){
        match packet.get_next_header() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                tcp_handler_v6(&packet, port_results);
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                udp_handler_v6(&packet, port_results);
            },
            _ => {}
        }
    }
}

fn tcp_handler_v4(packet: &pnet::packet::ipv4::Ipv4Packet, port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    let tcp_packet = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp_packet) = tcp_packet {
        handle_tcp_packet(tcp_packet, port_results);
    }
}

fn tcp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    let tcp_packet = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp_packet) = tcp_packet {
        handle_tcp_packet(tcp_packet, port_results);
    }
}

fn udp_handler_v4(packet: &pnet::packet::ipv4::Ipv4Packet, port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.get_payload());
    if let Some(udp) = udp {
        handle_udp_packet(udp, port_results);
    }
}

fn udp_handler_v6(packet: &pnet::packet::ipv6::Ipv6Packet, port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.get_payload());
    if let Some(udp) = udp {
        handle_udp_packet(udp, port_results);
    }
}

fn handle_tcp_packet(tcp_packet: pnet::packet::tcp::TcpPacket, port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    if tcp_packet.get_flags() == pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK {
        port_results.lock().unwrap().push(
            PortInfo{
                port: tcp_packet.get_source(),
                status: PortStatus::Open,
            }
        );
    }else if tcp_packet.get_flags() == pnet::packet::tcp::TcpFlags::RST | pnet::packet::tcp::TcpFlags::ACK {
        port_results.lock().unwrap().push(
            PortInfo{
                port: tcp_packet.get_source(),
                status: PortStatus::Closed,
            }
        );
    }
}

fn handle_udp_packet(_udp_packet: pnet::packet::udp::UdpPacket, _port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    //TODO
}
