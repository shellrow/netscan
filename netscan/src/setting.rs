use crate::host::HostInfo;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use xenet::net::mac::MacAddr;

pub(crate) const DEFAULT_SRC_PORT: u16 = 53443;
pub(crate) const DEFAULT_HOSTS_CONCURRENCY: usize = 50;
pub(crate) const DEFAULT_PORTS_CONCURRENCY: usize = 100;
/// Listener thread wait time (milliseconds)
pub(crate) const LISTENER_WAIT_TIME_MILLIS: u64 = 100;

/// Scan Type
#[derive(Clone, Debug)]
pub enum ScanType {
    /// Default fast port scan type.
    ///
    /// Send TCP packet with SYN flag to the target ports and check response.
    TcpSynScan,
    /// Attempt TCP connection and check port status.
    ///
    /// Slow but can be run without administrator privileges.
    TcpConnectScan,
    /// Default host scan type.
    ///
    /// Send ICMP echo request and check response.
    IcmpPingScan,
    /// Perform host scan for a specific service.
    ///
    /// Send TCP packets with SYN flag to a specific port and check response.
    TcpPingScan,
    UdpPingScan,
}

#[derive(Clone, Debug)]
pub struct ScanSetting {
    pub if_index: u32,
    pub if_name: String,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub targets: Vec<HostInfo>,
    pub ip_map: HashMap<IpAddr, String>,
    pub scan_type: ScanType,
    pub hosts_concurrency: usize,
    pub ports_concurrency: usize,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub tunnel: bool,
    pub loopback: bool,
    pub minimize_packet: bool,
}

impl ScanSetting {
    pub fn new() -> ScanSetting {
        ScanSetting {
            if_index: 0,
            if_name: String::new(),
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: DEFAULT_SRC_PORT,
            targets: vec![],
            ip_map: HashMap::new(),
            scan_type: ScanType::TcpSynScan,
            hosts_concurrency: DEFAULT_HOSTS_CONCURRENCY,
            ports_concurrency: DEFAULT_PORTS_CONCURRENCY,
            timeout: Duration::from_secs(30),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(0),
            tunnel: false,
            loopback: false,
            minimize_packet: false,
        }
    }
    /// Set source IP address
    pub fn set_src_ip(&mut self, src_ip: IpAddr) {
        self.src_ip = src_ip;
    }
    /// Get source IP address
    pub fn get_src_ip(&self) -> IpAddr {
        self.src_ip.clone()
    }
    /// Add Target
    pub fn add_target(&mut self, dst: HostInfo) {
        self.targets.push(dst);
    }
    /// Set Targets
    pub fn set_targets(&mut self, dst: Vec<HostInfo>) {
        self.targets = dst;
    }
    /// Get Targets
    pub fn get_targets(&self) -> Vec<HostInfo> {
        self.targets.clone()
    }
    /// Set ScanType
    pub fn set_scan_type(&mut self, scan_type: ScanType) {
        self.scan_type = scan_type;
    }
    /// Get ScanType
    pub fn get_scan_type(&self) -> ScanType {
        self.scan_type.clone()
    }
    /// Set timeout
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    /// Get timeout
    pub fn get_timeout(&self) -> Duration {
        self.timeout.clone()
    }
    /// Set wait time
    pub fn set_wait_time(&mut self, wait_time: Duration) {
        self.wait_time = wait_time;
    }
    /// Get wait time
    pub fn get_wait_time(&self) -> Duration {
        self.wait_time.clone()
    }
    /// Set send rate
    pub fn set_send_rate(&mut self, send_rate: Duration) {
        self.send_rate = send_rate;
    }
    /// Get send rate
    pub fn get_send_rate(&self) -> Duration {
        self.send_rate.clone()
    }
    /// Set hosts concurrency
    pub fn set_hosts_concurrency(&mut self, concurrency: usize) {
        self.hosts_concurrency = concurrency;
    }
}
