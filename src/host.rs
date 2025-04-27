use crate::dns;
use netdev::mac::MacAddr;
use std::net::IpAddr;

/// Status of the scanned port
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl PortStatus {
    pub fn id(&self) -> String {
        match *self {
            PortStatus::Open => String::from("open"),
            PortStatus::Closed => String::from("closed"),
            PortStatus::Filtered => String::from("filtered"),
            PortStatus::Unknown => String::from("unknown"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            PortStatus::Open => String::from("Open"),
            PortStatus::Closed => String::from("Closed"),
            PortStatus::Filtered => String::from("Filtered"),
            PortStatus::Unknown => String::from("Unknown"),
        }
    }
}

/// Port Information
#[derive(Clone, Debug, PartialEq)]
pub struct Port {
    /// Port number
    pub number: u16,
    /// Port status
    pub status: PortStatus,
    /// Service name
    pub service_name: String,
    /// Service version
    pub service_version: String,
}

impl Port {
    pub fn new(number: u16) -> Self {
        Self {
            number: number,
            status: PortStatus::Unknown,
            service_name: String::new(),
            service_version: String::new(),
        }
    }
}

/// Host Information
#[derive(Clone, Debug, PartialEq)]
pub struct Host {
    /// IP address of the host
    pub ip_addr: IpAddr,
    /// Host name
    pub hostname: String,
    /// List of ports
    pub ports: Vec<Port>,
    /// MAC address of the host
    pub mac_addr: MacAddr,
    /// TTL
    pub ttl: u8,
}

impl Host {
    pub fn new(ip_addr: IpAddr, hostname: String) -> Self {
        Self {
            ip_addr: ip_addr,
            hostname: hostname,
            ports: Vec::new(),
            mac_addr: MacAddr::zero(),
            ttl: 0,
        }
    }
    pub fn with_port_range(mut self, start: u16, end: u16) -> Self {
        for port in start..end {
            self.ports.push(Port::new(port));
        }
        self
    }
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        for port in ports {
            self.ports.push(Port::new(port));
        }
        self
    }
    pub fn get_ports(&self) -> Vec<u16> {
        self.ports.iter().map(|port| port.number).collect()
    }
    pub fn get_open_port_numbers(&self) -> Vec<u16> {
        self.ports
            .iter()
            .filter(|port| port.status == PortStatus::Open)
            .map(|port| port.number)
            .collect()
    }
    pub fn get_open_ports(&self) -> Vec<Port> {
        self.ports
            .iter()
            .filter(|port| port.status == PortStatus::Open)
            .map(|port| port.clone())
            .collect()
    }
}

/// Node type
#[derive(Clone, Debug, PartialEq)]
pub enum NodeType {
    DefaultGateway,
    Relay,
    Destination,
}

impl NodeType {
    pub fn id(&self) -> String {
        match *self {
            NodeType::DefaultGateway => String::from("default_gateway"),
            NodeType::Relay => String::from("relay"),
            NodeType::Destination => String::from("destination"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            NodeType::DefaultGateway => String::from("DefaultGateway"),
            NodeType::Relay => String::from("Relay"),
            NodeType::Destination => String::from("Destination"),
        }
    }
}

// Check if the target is an IP address
pub fn is_valid_ip_addr(target: &str) -> bool {
    match target.parse::<IpAddr>() {
        Ok(_) => true,
        Err(_) => false,
    }
}

// Check if the target is a valid hostname
pub fn is_valid_hostname(target: &str) -> bool {
    dns::lookup_host_name(target).is_some()
}

// Check if the target is valid
pub fn is_valid_target(target: &str) -> bool {
    is_valid_ip_addr(target) || is_valid_hostname(target)
}
