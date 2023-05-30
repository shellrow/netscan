use pnet_datalink::MacAddr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::host::HostInfo;

pub(crate) const DEFAULT_SRC_PORT: u16 = 53443;
pub(crate) const DEFAULT_HOSTS_CONCURRENCY: usize = 50;
pub(crate) const DEFAULT_PORTS_CONCURRENCY: usize = 100;

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
pub(crate) struct ScanSetting {
    pub if_index: u32,
    #[allow(dead_code)]
    pub src_mac: MacAddr,
    #[allow(dead_code)]
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub targets: Vec<HostInfo>,
    pub ip_map: HashMap<IpAddr, String>,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub scan_type: ScanType,
    #[allow(dead_code)]
    pub hosts_concurrency: usize,
    #[allow(dead_code)]
    pub ports_concurrency: usize,
}
