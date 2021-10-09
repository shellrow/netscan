use std::io;
use std::thread;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::Mutex as TokioMutex;
use std::sync::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use pnet::packet::{tcp, Packet};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use crate::scanner::shared::{self, PortScanType, HostScanResult, PortScanResult, PortStatus, PortInfo, ScanStatus};
use crate::packet::EndPoints;

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

#[derive(Clone)]
pub struct AsyncHostScanner {
    /// Source IP Address  
    pub src_ip: IpAddr,
    /// Destination IP Addresses 
    pub dst_ips: Vec<IpAddr>,
    /// Timeout setting of host scan  
    pub timeout: Duration,
    /// Timeout setting of host scan  
    pub wait_time: Duration,
    /// Result of host scan  
    pub scan_result: HostScanResult,
    /// Async Socket
    pub socket: AsyncSocket,
}

impl AsyncHostScanner{
    pub fn new(src_ip: IpAddr) -> Result<AsyncHostScanner, String> {
        Ok(
            AsyncHostScanner {
                src_ip: src_ip,
                dst_ips: vec![],
                timeout: Duration::from_millis(30000),
                wait_time: Duration::from_millis(100),
                scan_result: HostScanResult::new(),
                socket: {
                    match src_ip {
                        IpAddr::V4(_) => AsyncSocket::new(src_ip, Protocol::ICMPV4).unwrap(),
                        IpAddr::V6(_) => AsyncSocket::new(src_ip, Protocol::ICMPV6).unwrap(),
                    }
                },
            }
        )
    }
    pub fn set_src_ip(&mut self, ip_addr: IpAddr) {
        self.src_ip = ip_addr;
    }
    pub fn add_dst_ip(&mut self, ip_addr: IpAddr) {
        self.dst_ips.push(ip_addr);
    }
    pub fn set_dst_ips(&mut self, ips: Vec<IpAddr>) {
        self.dst_ips = ips;
    }
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    pub fn set_wait_time(&mut self, wait_time: Duration) {
        self.wait_time = wait_time;
    }
    pub fn set_scan_result(&mut self, scan_result: HostScanResult) {
        self.scan_result = scan_result;
    }
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    pub fn get_dst_ips(&self) -> Vec<IpAddr> {
        self.dst_ips.clone()
    }
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    pub fn get_wait_time(&self) -> Duration {
        self.wait_time
    }
    pub fn get_scan_result(&self) -> HostScanResult {
        self.scan_result.clone()
    }
    pub async fn run_scan(&mut self) {
        
    }
}

#[derive(Clone, Debug)]
pub struct AsyncPortScanner {
    /// Source IP Address  
    pub src_ip: IpAddr,
    /// Destination IP Address  
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination ports
    pub dst_ports: Vec<u16>,
    /// Type of port scan. Default is PortScanType::SynScan  
    pub scan_type: PortScanType,
    /// Timeout setting of port scan   
    pub timeout: Duration,
    /// Wait time after send task is finished
    pub wait_time: Duration,
    /// Packet send rate
    pub send_rate: Duration,
    /// Result of port scan  
    pub scan_result: PortScanResult,
    /// Async Socket
    pub socket: AsyncSocket,
}

impl AsyncPortScanner {
    pub fn new(src_ip: IpAddr) -> Result<AsyncPortScanner, String> {
        Ok(
            AsyncPortScanner {
                src_ip: src_ip,
                dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                src_port: shared::DEFAULT_SRC_PORT,
                dst_ports: vec![],
                scan_type: PortScanType::SynScan,
                timeout: Duration::from_millis(30000),
                wait_time: Duration::from_millis(100),
                send_rate: Duration::from_millis(30000),
                scan_result: PortScanResult::new(),
                socket: {
                    match AsyncSocket::new(src_ip, Protocol::TCP) {
                        Ok(socket) => socket,
                        Err(e) => return Err(format!("{}",e)),
                    }
                },
            }
        )
    }
    pub fn set_src_ip(&mut self, ip_addr: IpAddr) {
        self.src_ip = ip_addr;
    }
    pub fn set_dst_ip(&mut self, ip_addr: IpAddr) {
        self.dst_ip = ip_addr;
    }
    pub fn set_src_port(&mut self, port: u16) {
        self.src_port = port;
    }
    pub fn add_dst_port(&mut self, port: u16) {
        self.dst_ports.push(port);
    }
    pub fn set_dst_port_range(&mut self, start_port: u16, end_port: u16) {
        for i in start_port..end_port + 1{
            self.add_dst_port(i);
        }
    }
    pub fn set_dst_ports(&mut self, ports: Vec<u16>) {
        self.dst_ports = ports;
    }
    pub fn set_scan_type(&mut self, scan_type: PortScanType) {
        self.scan_type = scan_type;
    }
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    pub fn set_wait_time(&mut self, wait_time: Duration) {
        self.wait_time = wait_time;
    }
    pub fn set_send_rate(&mut self, send_rate: Duration) {
        self.send_rate = send_rate;
    }
    pub fn set_scan_result(&mut self, scan_result: PortScanResult) {
        self.scan_result = scan_result;
    }
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip
    }
    pub fn get_dst_ip(&self) -> IpAddr {
        self.dst_ip
    }
    pub fn get_src_port(&self) -> u16 {
        self.src_port
    }
    pub fn get_dst_ports(&self) -> Vec<u16> {
        self.dst_ports.clone()
    }
    pub fn get_scan_type(&self) -> PortScanType {
        self.scan_type
    }
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    pub fn get_wait_time(&self) -> Duration {
        self.wait_time
    }
    pub fn get_send_rate(&self) -> Duration {
        self.send_rate
    }
    pub fn get_scan_result(&self) -> PortScanResult {
        self.scan_result.clone()
    }
    pub async fn run_scan(&mut self) {
        let start_time = Instant::now();
        let (ports, status) = scan_ports(self.clone()).await;
        let scan_time = Instant::now().duration_since(start_time);
        self.scan_result.ports = ports;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = scan_time;
    }
}

async fn build_syn_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
    let mut vec: Vec<u8> = vec![0; 1024];
    let mut tcp_packet = tcp::MutableTcpPacket::new(&mut vec[..]).unwrap();
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

async fn scan_ports(scanner: AsyncPortScanner) -> (Vec<PortInfo>, ScanStatus) {
    let mut result: Vec<PortInfo> = vec![];
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
        let socket = scanner.socket.clone();
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
        //println!("Open: {}", tcp_packet.get_source());
    }else if tcp_packet.get_flags() == pnet::packet::tcp::TcpFlags::RST | pnet::packet::tcp::TcpFlags::ACK {
        port_results.lock().unwrap().push(
            PortInfo{
                port: tcp_packet.get_source(),
                status: PortStatus::Closed,
            }
        );
        //println!("Close: {}", tcp_packet.get_source());
    }
}

fn handle_udp_packet(_udp_packet: pnet::packet::udp::UdpPacket, _port_results: &Arc<Mutex<Vec<PortInfo>>>) {
    //TODO
}
