use std::net::{IpAddr, Ipv4Addr};

/// Status of the scanned port
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
}

/// Port Information
#[derive(Clone, Copy, Debug)]
pub struct PortInfo {
    /// Port number
    pub port: u16,
    /// Port status
    pub status: PortStatus,
}

/// Host Information
#[derive(Clone, Debug)]
pub struct HostInfo {
    /// IP address of the host
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: String,
    /// IP Time to Live (Hop Limit)
    pub ttl: u8,
    /// List of PortInfo  
    ///
    /// Port scan results or ports used for host scan
    pub ports: Vec<PortInfo>,
}

impl HostInfo {
    /// Create new HostInfo with default values
    pub fn new() -> HostInfo {
        HostInfo {
            ip_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_name: String::new(),
            ttl: 64,
            ports: vec![],
        }
    }
    /// Create new HostInfo with IP address
    pub fn new_with_ip_addr(ip_addr: IpAddr) -> HostInfo {
        HostInfo {
            ip_addr: ip_addr,
            host_name: String::new(),
            ttl: 64,
            ports: vec![],
        }
    }
    /// Create new HostInfo with Host Name
    pub fn new_with_host_name(host_name: String) -> HostInfo {
        let ip_addr = match dns_lookup::lookup_host(host_name.as_str()) {
            Ok(ips) => {
                let mut ip_addr = ips.first().unwrap().clone();
                for ip in ips {
                    if ip.is_ipv4() {
                        ip_addr = ip;
                        break;
                    }
                }
                ip_addr
            }
            Err(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        HostInfo {
            ip_addr: ip_addr,
            host_name: host_name,
            ttl: 64,
            ports: vec![],
        }
    }
    /// Set host name and return HostInfo
    pub fn with_host_name(&mut self, host_name: String) -> Self {
        self.host_name = host_name;
        self.clone()
    }
    /// Set ports and return HostInfo
    pub fn with_ports(&mut self, port_list: Vec<u16>) -> Self {
        let mut ports: Vec<PortInfo> = vec![];
        for port in port_list {
            ports.push(PortInfo {
                port: port,
                status: PortStatus::Unknown,
            });
        }
        self.ports = ports;
        self.clone()
    }
    /// Set port range and return HostInfo
    pub fn with_port_range(&mut self, start_port: u16, end_port: u16) -> Self {
        let mut ports: Vec<PortInfo> = vec![];
        for p in start_port..end_port + 1 {
            ports.push(PortInfo {
                port: p,
                status: PortStatus::Unknown,
            });
        }
        self.ports = ports;
        self.clone()
    }
    /// Set ports
    pub fn set_ports(&mut self, port_list: Vec<u16>) {
        let mut ports: Vec<PortInfo> = vec![];
        for port in port_list {
            ports.push(PortInfo {
                port: port,
                status: PortStatus::Unknown,
            });
        }
        self.ports = ports;
    }
    /// Set port range
    pub fn set_port_range(&mut self, start_port: u16, end_port: u16) {
        let mut ports: Vec<PortInfo> = vec![];
        for p in start_port..end_port + 1 {
            ports.push(PortInfo {
                port: p,
                status: PortStatus::Unknown,
            });
        }
        self.ports = ports;
    }
    // Get ports (numbers)
    pub fn get_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = vec![];
        for port_info in self.ports.clone() {
            ports.push(port_info.port);
        }
        ports
    }
    // Get open ports (numbers)
    pub fn get_open_ports(&self) -> Vec<u16> {
        let mut open_ports: Vec<u16> = vec![];
        for port_info in self.ports.clone() {
            match port_info.status {
                PortStatus::Open => {
                    open_ports.push(port_info.port);
                }
                _ => {}
            }
        }
        open_ports
    }
}
