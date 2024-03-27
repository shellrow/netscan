use netdev::mac::MacAddr;
use netdev::Interface;
use nex::packet::tcp::TcpFlags;

use crate::packet::frame::PacketFrame;
use crate::host::{Host, Port, PortStatus};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::setting::{HostScanSetting, HostScanType, PortScanSetting};

/// Status of scan task
#[derive(Clone, Debug, PartialEq)]
pub enum ScanStatus {
    Done,
    Timeout,
    Error(String),
}

/// Result of scan
#[derive(Clone, Debug)]
pub struct ScanResult {
    /// List of scanned Host info and their respective ports
    pub hosts: Vec<Host>,
    /// Time taken to scan
    pub scan_time: Duration,
    /// Status of the scan task
    pub scan_status: ScanStatus,
    /// Captured packet fingerprints
    pub fingerprints: Vec<PacketFrame>,
}

impl ScanResult {
    pub fn new() -> ScanResult {
        ScanResult {
            hosts: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Done,
            fingerprints: vec![],
        }
    }
    pub fn error(message: String) -> ScanResult {
        ScanResult {
            hosts: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Error(message),
            fingerprints: vec![],
        }
    }
    /// Returns IP addresses from the scan result
    pub fn get_hosts(&self) -> Vec<IpAddr> {
        let mut hosts: Vec<IpAddr> = vec![];
        for host in self.hosts.clone() {
            hosts.push(host.ip_addr);
        }
        hosts
    }
    /// Get open ports of the specified IP address from the scan results
    pub fn get_open_port_numbers(&self, ip_addr: IpAddr) -> Vec<u16> {
        let mut open_ports: Vec<u16> = vec![];
        self.hosts.iter().for_each(|host_info| {
            if host_info.ip_addr == ip_addr {
                host_info
                    .ports
                    .iter()
                    .for_each(|port_info| match port_info.status {
                        PortStatus::Open => {
                            open_ports.push(port_info.number);
                        }
                        _ => {}
                    });
            }
        });
        open_ports
    }
    /// Get open port fingerprint
    pub fn get_syn_ack_fingerprint(&self, ip_addr: IpAddr, port: u16) -> Option<PacketFrame> {
        for fingerprint in self.fingerprints.iter() {
            if let Some(ipv4_packet) = &fingerprint.ipv4_header {
                if ipv4_packet.source == ip_addr {
                    if let Some(tcp_packet) = &fingerprint.tcp_header {
                        if tcp_packet.source == port && tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK {
                            return Some(fingerprint.clone());
                        }
                    }
                }
            } else if let Some(ipv6_packet) = &fingerprint.ipv6_header {
                if ipv6_packet.source == ip_addr {
                    if let Some(tcp_packet) = &fingerprint.tcp_header {
                        if tcp_packet.source == port && tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK {
                            return Some(fingerprint.clone());
                        }
                    }
                }
            }
        }
        None
    }
    pub fn get_host(&self, ip_addr: IpAddr) -> Option<Host> {
        for host in self.hosts.iter() {
            if host.ip_addr == ip_addr {
                return Some(host.clone());
            }
        }
        None
    }
    pub fn sort_hosts(&mut self) {
        self.hosts.sort_by(|a, b| a.ip_addr.cmp(&b.ip_addr));
    }
    pub fn sort_ports(&mut self) {
        for host in self.hosts.iter_mut() {
            host.ports.sort_by(|a, b| a.number.cmp(&b.number));
        }
    }
}

/// Result of a service probe
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceProbeResult {
    pub port: u16,
    pub service_name: String,
    pub service_detail: Option<String>,
    pub response: Vec<u8>,
    pub error: Option<ServiceProbeError>,
}

impl ServiceProbeResult {
    /// Create a new successful probe result
    pub fn new(port: u16, service_name: String, response: Vec<u8>) -> Self {
        ServiceProbeResult {
            port,
            service_name,
            service_detail: None,
            response,
            error: None,
        }
    }

    /// Create a new probe result with an error
    pub fn with_error(port: u16, service_name: String, error: ServiceProbeError) -> Self {
        ServiceProbeResult {
            port,
            service_name,
            service_detail: None,
            response: Vec::new(),
            error: Some(error),
        }
    }

    /// Check if the result contains an error
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get a reference to the contained error, if any
    pub fn error(&self) -> Option<&ServiceProbeError> {
        self.error.as_ref()
    }

    /// Extract the error, consuming the result
    pub fn into_error(self) -> Option<ServiceProbeError> {
        self.error
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ServiceProbeError {
    ConnectionError(String),
    WriteError(String),
    ReadError(String),
    TlsError(String),
    CustomError(String),
}

pub (crate) fn parse_hostscan_result(packets: Vec<PacketFrame>, scan_setting: HostScanSetting) -> ScanResult {
    let mut result: ScanResult = ScanResult::new();
    let iface: Interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(iface) => iface,
        None => return ScanResult::error("Interface not found".to_string()),
    };
    let iface_ips: HashSet<IpAddr> = crate::interface::get_local_ips(scan_setting.if_index);
    for p in packets {
        let mac_addr: MacAddr;
        if let Some(ethernet_frame) = &p.ethernet_header {
            if ethernet_frame.destination != iface.mac_addr.unwrap_or(MacAddr::zero()) {
                continue;
            }
            mac_addr = ethernet_frame.source;
        } else {
            mac_addr = MacAddr::zero();
        }
        let mut ports: Vec<Port> = vec![];
        match scan_setting.scan_type {
            HostScanType::IcmpPingScan => {
                if p.icmp_header.is_none() && p.icmpv6_header.is_none() {
                    continue;
                }
            }
            HostScanType::TcpPingScan => {
                if p.tcp_header.is_none() {
                    continue;
                }
                if let Some(tcp_packet) = &p.tcp_header {
                    if tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK {
                        let port_info: Port = Port {
                            number: tcp_packet.source,
                            status: PortStatus::Open,
                            service_name: String::new(),
                            service_version: String::new(),
                        };
                        ports.push(port_info);
                    } else if tcp_packet.flags == TcpFlags::RST | TcpFlags::ACK {
                        let port_info: Port = Port {
                            number: tcp_packet.source,
                            status: PortStatus::Closed,
                            service_name: String::new(),
                            service_version: String::new(),
                        };
                        ports.push(port_info);
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            HostScanType::UdpPingScan => {
                if p.icmp_header.is_none() && p.icmp_header.is_none() {
                    continue;
                }
            }
        }
        let host_info: Host = if let Some(ipv4_packet) = &p.ipv4_header {
            Host {
                ip_addr: IpAddr::V4(ipv4_packet.source),
                hostname: scan_setting
                    .dns_map
                    .get(&IpAddr::V4(ipv4_packet.source))
                    .unwrap_or(&String::new())
                    .clone(),
                ports: ports,
                mac_addr: if iface_ips.contains(&IpAddr::V4(ipv4_packet.source)) {iface.mac_addr.unwrap_or(MacAddr::zero())} else { mac_addr },
                ttl: ipv4_packet.ttl,
            }
        } else if let Some(ipv6_packet) = &p.ipv6_header {
            Host {
                ip_addr: IpAddr::V6(ipv6_packet.source),
                hostname: scan_setting
                    .dns_map
                    .get(&IpAddr::V6(ipv6_packet.source))
                    .unwrap_or(&String::new())
                    .clone(),
                ports: ports,
                mac_addr: if iface_ips.contains(&IpAddr::V6(ipv6_packet.source)) {iface.mac_addr.unwrap_or(MacAddr::zero())} else { mac_addr },
                ttl: ipv6_packet.hop_limit,
            }
        } else {
            continue;
        };
        if !result.hosts.contains(&host_info) {
            result.hosts.push(host_info);
            result.fingerprints.push(p.clone());
        }
    }
    return result;
}

pub (crate) fn parse_portscan_result(packets: Vec<PacketFrame>, scan_setting: PortScanSetting) -> ScanResult {
    let mut result: ScanResult = ScanResult::new();
    let mut socket_set: HashSet<SocketAddr> = HashSet::new();
    let iface: Interface = match crate::interface::get_interface_by_index(scan_setting.if_index) {
        Some(iface) => iface,
        None => return ScanResult::error("Interface not found".to_string()),
    };
    for p in packets {
        if p.ipv4_header.is_none() && p.ipv6_header.is_none() {
            continue;
        }
        let mac_addr: MacAddr;
        if let Some(ethernet_frame) = &p.ethernet_header {
            if ethernet_frame.destination != iface.mac_addr.unwrap_or(MacAddr::zero()) {
                continue;
            }
            mac_addr = ethernet_frame.source;
        } else {
            mac_addr = MacAddr::zero();
        }
        let ip_addr: IpAddr = {
            if let Some(ipv4_packet) = &p.ipv4_header {
                if let Some(tcp_packet) = &p.tcp_header {
                    if socket_set.contains(&SocketAddr::new(
                        IpAddr::V4(ipv4_packet.source),
                        tcp_packet.source,
                    )) {
                        continue;
                    }
                } else {
                    continue;
                }
                IpAddr::V4(ipv4_packet.source)
            } else if let Some(ipv6_packet) = &p.ipv6_header {
                if let Some(tcp_packet) = &p.tcp_header {
                    if socket_set.contains(&SocketAddr::new(
                        IpAddr::V6(ipv6_packet.source),
                        tcp_packet.source,
                    )) {
                        continue;
                    }
                } else {
                    continue;
                }
                IpAddr::V6(ipv6_packet.source)
            } else {
                continue;
            }
        };
        let ttl = if let Some(ipv4_packet) = &p.ipv4_header {
            ipv4_packet.ttl
        } else if let Some(ipv6_packet) = &p.ipv6_header {
            ipv6_packet.hop_limit
        } else {
            0
        };
        let port_info: Port = if let Some(tcp_packet) = &p.tcp_header {
            if tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK {
                Port {
                    number: tcp_packet.source,
                    status: PortStatus::Open,
                    service_name: String::new(),
                    service_version: String::new(),
                }
            } else if tcp_packet.flags == TcpFlags::RST | TcpFlags::ACK {
                Port {
                    number: tcp_packet.source,
                    status: PortStatus::Closed,
                    service_name: String::new(),
                    service_version: String::new(),
                }
            } else {
                continue;
            }
        } else {
            continue;
        };
        let mut exists: bool = false;
        for host in result.hosts.iter_mut() {
            if host.ip_addr == ip_addr {
                host.ports.push(port_info.clone());
                exists = true;
            }
        }
        if !exists {
            let host_info: Host = Host {
                ip_addr: ip_addr,
                hostname: scan_setting
                    .dns_map
                    .get(&ip_addr)
                    .unwrap_or(&String::new())
                    .clone(),
                ports: vec![port_info.clone()],
                mac_addr: mac_addr,
                ttl: ttl,
            };
            result.hosts.push(host_info);
        }
        result.fingerprints.push(p.clone());
        socket_set.insert(SocketAddr::new(ip_addr, port_info.number));
    }
    result
}
