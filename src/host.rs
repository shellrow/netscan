use std::net::IpAddr;

/// Status of the scanned port 
#[derive(Clone, Copy, Debug)]
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
    pub fn new() -> HostInfo {
        HostInfo{
            ip_addr: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            host_name: String::new(),
            ttl: 64,
            ports: vec![],
        }
    }
    /// Create new HostInfo with IP address
    pub fn new_with_ip_addr(ip_addr: IpAddr) -> HostInfo {
        HostInfo{
            ip_addr: ip_addr,
            host_name: String::new(),
            ttl: 64,
            ports: vec![],
        }
    }
    /// Create new HostInfo with IP address and ports 
    pub fn new_with_ports(ip_addr: IpAddr, port_list: Vec<u16>) -> HostInfo {
        let mut ports: Vec<PortInfo> = vec![];
        for port in port_list {
            ports.push(PortInfo { port: port, status: PortStatus::Unknown });
        }
        HostInfo {
            ip_addr: ip_addr,
            host_name: String::new(),
            ttl: 64,
            ports: ports,
        }
    }
    /// Create new HostInfo with IP address and port range 
    pub fn new_with_port_range(ip_addr: IpAddr, start_port: u16, end_port: u16) -> HostInfo {
        let mut ports: Vec<PortInfo> = vec![];
        for i in start_port..end_port + 1 {
            ports.push(PortInfo { port: i, status: PortStatus::Unknown });
        }
        HostInfo {
            ip_addr: ip_addr,
            host_name: String::new(),
            ttl: 64,
            ports: ports,
        }
    }
    pub fn get_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = vec![];
        for port_info in self.ports.clone() {
            ports.push(port_info.port);
        }
        ports
    }
}
