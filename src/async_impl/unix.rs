use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::mem::MaybeUninit;
use std::sync::Mutex;
use std::thread;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use pnet_packet::Packet;
use crate::result::{HostScanResult, PortScanResult, ScanResult};
use crate::setting::{ScanSetting};
use crate::setting::{ScanType};
use crate::packet;
use crate::async_impl::receiver;

#[derive(Clone, Debug)]
pub struct AsyncSocket {
    inner: Arc<AsyncFd<Socket>>,
}

impl AsyncSocket {
    pub fn new(addr: IpAddr, socket_type: Type, protocol: Protocol) -> io::Result<AsyncSocket> {
        let socket = match addr {
            IpAddr::V4(_) => Socket::new(Domain::IPV4, socket_type, Some(protocol))?,
            IpAddr::V6(_) => Socket::new(Domain::IPV6, socket_type, Some(protocol))?,
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
    pub async fn recv_from(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<(usize, SockAddr)> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

async fn build_icmpv4_echo_packet() -> Vec<u8> {
    let mut buf = vec![0; 16];
    let mut icmp_packet = pnet_packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
    packet::icmp::build_icmp_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

async fn build_tcp_syn_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut tcp_packet = pnet_packet::tcp::MutableTcpPacket::new(&mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..]).unwrap();
    packet::tcp::build_tcp_packet(&mut tcp_packet, src_ip, src_port, dst_ip, dst_port);
    tcp_packet.packet().to_vec()
}

async fn build_udp_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 66];
    let mut udp_packet = pnet_packet::udp::MutableUdpPacket::new(&mut vec[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..]).unwrap();
    packet::udp::build_udp_packet(&mut udp_packet, src_ip, src_port, dst_ip, dst_port);
    udp_packet.packet().to_vec()
}

async fn send_icmp_echo_packets(socket: &AsyncSocket, scan_setting: &ScanSetting) {
    for dst in scan_setting.destinations.clone() {
        let socket_addr = SocketAddr::new(dst.dst_ip, 0);
        let sock_addr = SockAddr::from(socket_addr);
        let mut icmp_packet: Vec<u8> = build_icmpv4_echo_packet().await;
        match socket.send_to(&mut icmp_packet, &sock_addr).await {
            Ok(_) => {},
            Err(_) => {},
        }
    }
}

async fn send_tcp_syn_packets(socket: &AsyncSocket, scan_setting: &ScanSetting){
    for dst in scan_setting.destinations.clone() {
        for port in dst.dst_ports {
            let socket_addr = SocketAddr::new(dst.dst_ip, port);
            let sock_addr = SockAddr::from(socket_addr);
            let mut tcp_packet: Vec<u8> = build_tcp_syn_packet(scan_setting.src_ip, scan_setting.src_port, dst.dst_ip, port).await;
            match socket.send_to(&mut tcp_packet, &sock_addr).await {
                Ok(_) => {},
                Err(_) => {},
            }
        }
    }
}

async fn send_udp_packets(socket: &AsyncSocket, scan_setting: &ScanSetting) {
    for dst in scan_setting.destinations.clone() {
        for port in dst.dst_ports {
            let socket_addr = SocketAddr::new(dst.dst_ip, port);
            let sock_addr = SockAddr::from(socket_addr);
            let mut udp_packet: Vec<u8> = build_udp_packet(scan_setting.src_ip, scan_setting.src_port, dst.dst_ip, port).await;
            match socket.send_to(&mut udp_packet, &sock_addr).await {
                Ok(_) => {},
                Err(_) => {},
            }
        }
    }
}

async fn try_connect(_socket: &AsyncSocket, _scan_setting: &ScanSetting) {
    
}

async fn send_ping_packet(socket: &AsyncSocket, scan_setting: &ScanSetting) {
    match scan_setting.scan_type {
        ScanType::IcmpPingScan => {
            send_icmp_echo_packets(socket, scan_setting).await;
        },
        ScanType::TcpPingScan => {
            send_tcp_syn_packets(socket, scan_setting).await;
        },
        ScanType::UdpPingScan => {
            send_udp_packets(socket, scan_setting).await;
        },
        _ => {
            return;
        },
    }
}

async fn send_tcp_packets(socket: &AsyncSocket, scan_setting: &ScanSetting) {
    match scan_setting.scan_type {
        ScanType::TcpSynScan => {
            send_tcp_syn_packets(socket, scan_setting).await;
        },
        ScanType::TcpConnectScan => {
            try_connect(socket, scan_setting).await;
        },
        _ => {
            return;
        },
    }
}

pub async fn scan_hosts(scan_setting: ScanSetting) -> HostScanResult {
    let socket = match scan_setting.scan_type {
        ScanType::IcmpPingScan => AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::ICMPV4).unwrap(),
        ScanType::TcpPingScan => AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::TCP).unwrap(),
        ScanType::UdpPingScan => AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::UDP).unwrap(),
        _ => {
            return HostScanResult::new()
        },
    };
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
    let (mut _tx, mut rx) = match pnet_datalink::channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let receive_result: Arc<Mutex<ScanResult>>  = Arc::clone(&scan_result);
    let receive_stop: Arc<Mutex<bool>> = Arc::clone(&stop);
    let receive_setting: ScanSetting = scan_setting.clone();
    tokio::spawn(async move {
        receiver::receive_packets(&mut rx, receive_setting, &receive_result, &receive_stop).await;    
    });
    send_ping_packet(&socket, &scan_setting).await;
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
    let result: HostScanResult = scan_result.lock().unwrap().host_scan_result.clone(); 
    return result;
}

pub async fn scan_ports(scan_setting: ScanSetting) -> PortScanResult {
    let socket = match scan_setting.scan_type {
        ScanType::TcpSynScan => AsyncSocket::new(scan_setting.src_ip, Type::RAW, Protocol::TCP).unwrap(),
        ScanType::TcpConnectScan => AsyncSocket::new(scan_setting.src_ip, Type::STREAM, Protocol::TCP).unwrap(),
        _ => {
            return PortScanResult::new()
        },
    };
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
    let (mut _tx, mut rx) = match pnet_datalink::channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let receive_result: Arc<Mutex<ScanResult>>  = Arc::clone(&scan_result);
    let receive_stop: Arc<Mutex<bool>> = Arc::clone(&stop);
    let receive_setting: ScanSetting = scan_setting.clone();
    tokio::spawn(async move {
        receiver::receive_packets(&mut rx, receive_setting, &receive_result, &receive_stop).await;    
    });
    send_tcp_packets(&socket, &scan_setting).await;
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
    let result: PortScanResult = scan_result.lock().unwrap().port_scan_result.clone(); 
    return result;
}
