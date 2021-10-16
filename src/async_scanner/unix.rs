use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use crate::base_type::{PortScanType, HostScanResult, PortScanResult};
use crate::async_scanner::port_scan;
use crate::define::DEFAULT_SRC_PORT;

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
                src_port: DEFAULT_SRC_PORT,
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
        for i in start_port..end_port + 1 {
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
        let (ports, status) = port_scan::scan_ports(self.clone()).await;
        let scan_time = Instant::now().duration_since(start_time);
        self.scan_result.ports = ports;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = scan_time;
    }
}

