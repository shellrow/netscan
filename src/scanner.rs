use crate::async_io;
use crate::blocking;
use crate::interface;
use crate::result::{ScanResult, ScanStatus};
use crate::setting::{
    ScanSetting, ScanType, DEFAULT_HOSTS_CONCURRENCY, DEFAULT_PORTS_CONCURRENCY, DEFAULT_SRC_PORT,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Host Scanner
#[derive(Clone, Debug)]
pub struct HostScanner {
    /// Scan Setting
    pub scan_setting: ScanSetting,
    /// Host Scan Result
    pub scan_result: ScanResult,
    /// Sender for progress messaging
    pub tx: Arc<Mutex<Sender<SocketAddr>>>,
    /// Receiver for progress messaging
    pub rx: Arc<Mutex<Receiver<SocketAddr>>>,
}

impl HostScanner {
    /// Create new HostScanner with source IP address
    ///
    /// Initialized with default value based on the specified IP address
    pub fn new(src_ip: IpAddr) -> Result<HostScanner, String> {
        let mut if_index: u32 = 0;
        let mut if_name: String = String::new();
        let mut src_mac: pnet_datalink::MacAddr = pnet_datalink::MacAddr::zero();
        for iface in pnet_datalink::interfaces() {
            for ip in iface.ips {
                if ip.ip() == src_ip {
                    if_index = iface.index;
                    if_name = iface.name;
                    src_mac = iface.mac.unwrap_or(pnet_datalink::MacAddr::zero());
                    break;
                }
            }
        }
        if if_index == 0 || if_name.is_empty() || src_mac == pnet_datalink::MacAddr::zero() {
            return Err(String::from(
                "Failed to create Scanner. Network Interface not found.",
            ));
        }
        let (tx, rx) = channel();
        let scan_setting: ScanSetting = ScanSetting {
            if_index: if_index,
            if_name: if_name,
            src_mac: src_mac.octets(),
            dst_mac: interface::get_default_gateway_macaddr(),
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            targets: vec![],
            ip_map: HashMap::new(),
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(0),
            scan_type: ScanType::IcmpPingScan,
            hosts_concurrency: DEFAULT_HOSTS_CONCURRENCY,
            ports_concurrency: DEFAULT_PORTS_CONCURRENCY,
        };
        let host_scanner = HostScanner {
            scan_setting: scan_setting,
            scan_result: ScanResult::new(),
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        };
        Ok(host_scanner)
    }
    /// Get scan result
    pub fn get_scan_result(&self) -> ScanResult {
        self.scan_result.clone()
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<SocketAddr>>> {
        self.rx.clone()
    }
    /// Run Host Scan
    pub async fn run_scan(&mut self) {
        let mut ip_map: HashMap<IpAddr, String> = HashMap::new();
        for dst in self.scan_setting.targets.clone() {
            ip_map.insert(dst.ip_addr, dst.host_name);
        }
        self.scan_setting.ip_map = ip_map;
        let start_time = Instant::now();
        let mut result: ScanResult =
            async_io::scan_hosts(self.scan_setting.clone(), &self.tx).await;
        result.scan_time = Instant::now().duration_since(start_time);
        if result.scan_time > self.scan_setting.timeout {
            result.scan_status = ScanStatus::Timeout;
        } else {
            result.scan_status = ScanStatus::Done;
        }
        self.scan_result = result;
    }
    pub fn run_async_scan(&mut self) {
        let mut ip_map: HashMap<IpAddr, String> = HashMap::new();
        for dst in self.scan_setting.targets.clone() {
            ip_map.insert(dst.ip_addr, dst.host_name);
        }
        self.scan_setting.ip_map = ip_map;
        let start_time = Instant::now();
        let mut result: ScanResult = blocking::scan_hosts(self.scan_setting.clone(), &self.tx);
        result.scan_time = Instant::now().duration_since(start_time);
        if result.scan_time > self.scan_setting.timeout {
            result.scan_status = ScanStatus::Timeout;
        } else {
            result.scan_status = ScanStatus::Done;
        }
        self.scan_result = result;
    }
    /// Run scan and return result
    pub async fn scan(&mut self) -> ScanResult {
        self.run_scan().await;
        self.scan_result.clone()
    }
    pub fn sync_scan(&mut self) -> ScanResult {
        self.run_async_scan();
        self.scan_result.clone()
    }
}

/// Port Scanner
#[derive(Clone, Debug)]
pub struct PortScanner {
    /// Scan Setting
    pub scan_setting: ScanSetting,
    /// Port Scan Result
    pub scan_result: ScanResult,
    /// Sender for progress messaging
    pub tx: Arc<Mutex<Sender<SocketAddr>>>,
    /// Receiver for progress messaging
    pub rx: Arc<Mutex<Receiver<SocketAddr>>>,
}

impl PortScanner {
    /// Create new PortScanner with source IP address
    ///
    /// Initialized with default value based on the specified IP address
    pub fn new(src_ip: IpAddr) -> Result<PortScanner, String> {
        let mut if_index: u32 = 0;
        let mut if_name: String = String::new();
        let mut src_mac: pnet_datalink::MacAddr = pnet_datalink::MacAddr::zero();
        for iface in pnet_datalink::interfaces() {
            for ip in iface.ips {
                if ip.ip() == src_ip {
                    if_index = iface.index;
                    if_name = iface.name;
                    src_mac = iface.mac.unwrap_or(pnet_datalink::MacAddr::zero());
                    break;
                }
            }
        }
        if if_index == 0 || if_name.is_empty() || src_mac == pnet_datalink::MacAddr::zero() {
            return Err(String::from(
                "Failed to create Scanner. Network Interface not found.",
            ));
        }
        let (tx, rx) = channel();
        let scan_setting = ScanSetting {
            if_index: if_index,
            if_name: if_name,
            src_mac: src_mac.octets(),
            dst_mac: interface::get_default_gateway_macaddr(),
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            targets: vec![],
            ip_map: HashMap::new(),
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(0),
            scan_type: ScanType::TcpSynScan,
            hosts_concurrency: DEFAULT_HOSTS_CONCURRENCY,
            ports_concurrency: DEFAULT_PORTS_CONCURRENCY,
        };
        let port_scanner = PortScanner {
            scan_setting: scan_setting,
            scan_result: ScanResult::new(),
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        };
        Ok(port_scanner)
    }
    /// Get scan result
    pub fn get_scan_result(&self) -> ScanResult {
        self.scan_result.clone()
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<SocketAddr>>> {
        self.rx.clone()
    }
    /// Run Port Scan
    pub async fn run_scan(&mut self) {
        let mut ip_map: HashMap<IpAddr, String> = HashMap::new();
        for dst in self.scan_setting.targets.clone() {
            ip_map.insert(dst.ip_addr, dst.host_name);
        }
        self.scan_setting.ip_map = ip_map;
        let start_time = Instant::now();
        let mut result: ScanResult =
            async_io::scan_ports(self.scan_setting.clone(), &self.tx).await;
        result.scan_time = Instant::now().duration_since(start_time);
        if result.scan_status != ScanStatus::Error {
            if result.scan_time > self.scan_setting.timeout {
                result.scan_status = ScanStatus::Timeout;
            } else {
                result.scan_status = ScanStatus::Done;
            }
        }
        self.scan_result = result;
    }
    pub fn run_sync_scan(&mut self) {
        let mut ip_map: HashMap<IpAddr, String> = HashMap::new();
        for dst in self.scan_setting.targets.clone() {
            ip_map.insert(dst.ip_addr, dst.host_name);
        }
        self.scan_setting.ip_map = ip_map;
        let start_time = Instant::now();
        let mut result: ScanResult = blocking::scan_ports(self.scan_setting.clone(), &self.tx);
        result.scan_time = Instant::now().duration_since(start_time);
        if result.scan_status != ScanStatus::Error {
            if result.scan_time > self.scan_setting.timeout {
                result.scan_status = ScanStatus::Timeout;
            } else {
                result.scan_status = ScanStatus::Done;
            }
        }
        self.scan_result = result;
    }
    /// Run scan and return result
    pub async fn scan(&mut self) -> ScanResult {
        self.run_scan().await;
        self.scan_result.clone()
    }
    pub fn sync_scan(&mut self) -> ScanResult {
        self.run_sync_scan();
        self.scan_result.clone()
    }
}
