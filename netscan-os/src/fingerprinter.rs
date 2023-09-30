use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use cross_socket::packet::builder::PacketBuildOption;
use cross_socket::packet::ipv4::{Ipv4Packet, Ipv4Flags};
use cross_socket::packet::ipv6::Ipv6Packet;
use cross_socket::packet::udp::UdpPacket;
use cross_socket::pcap::listener::Listner;
use cross_socket::pcap::PacketCaptureOptions;
use cross_socket::packet::PacketFrame;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::icmp::IcmpType;
use cross_socket::packet::icmpv6::Icmpv6Type;
use cross_socket::socket::DataLinkSocket;
use cross_socket::packet::tcp::TcpFlag;
use default_net::interface::MacAddr;

use super::result::ProbeResult;
use super::send;
use super::setting::{ProbeSetting, ProbeTarget, ProbeType};

const DEFAULT_SRC_PORT: u16 = 54433;
const ICMP_UNUSED_BYTE_SIZE: usize = 4;

/// Struct for fingerprint probe
pub struct Fingerprinter {
    /// Index of network interface  
    pub if_index: u32,
    /// Name of network interface  
    pub if_name: String,
    /// Source MAC Address
    pub src_mac: String,
    /// Destination MAC Address (Gateway)
    pub dst_mac: String,
    /// Source IP Address  
    pub src_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Probe Targets
    pub probe_targets: Vec<ProbeTarget>,
    /// Probe Types  
    pub probe_types: Vec<ProbeType>,
    /// Timeout setting    
    pub timeout: Duration,
    /// Wait time after send task is finished
    pub wait_time: Duration,
    /// Packet send rate
    pub send_rate: Duration,
    /// Result of probes  
    pub probe_results: Vec<ProbeResult>,
}

impl Fingerprinter {
    /// Create new fingerprinter with interfece IP
    pub fn new(src_ip: IpAddr) -> Result<Fingerprinter, String> {
        let mut if_index: u32 = 0;
        let mut if_name: String = String::new();
        let mut src_mac: default_net::interface::MacAddr = default_net::interface::MacAddr::zero();
        match src_ip {
            IpAddr::V4(_) => {
                for iface in default_net::get_interfaces() {
                    for ip in iface.ipv4 {
                        if ip.addr == src_ip {
                            if_index = iface.index;
                            if_name = iface.name;
                            src_mac = iface.mac_addr.unwrap_or(default_net::interface::MacAddr::zero());
                            break;
                        }
                    }
                }
            }
            IpAddr::V6(_) => {
                for iface in default_net::get_interfaces() {
                    for ip in iface.ipv6 {
                        if ip.addr == src_ip {
                            if_index = iface.index;
                            if_name = iface.name;
                            src_mac = iface.mac_addr.unwrap_or(default_net::interface::MacAddr::zero());
                            break;
                        }
                    }
                }
            }
        }
        if if_index == 0 || if_name.is_empty() || src_mac.octets() == default_net::interface::MacAddr::zero().octets() {
            return Err(String::from(
                "Failed to create Scanner. Network Interface not found.",
            ));
        }
        let dst_mac: MacAddr = match default_net::get_default_gateway() {
            Ok(default_gateway) => {
                default_gateway.mac_addr
            }
            Err(_) => return Err(String::from("Failed to get gateway mac")),
        };
        let fingerprinter = Fingerprinter {
            if_index: if_index,
            if_name: if_name,
            src_mac: src_mac.to_string(),
            dst_mac: dst_mac.to_string(),
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            probe_targets: vec![],
            probe_types: vec![],
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            probe_results: vec![],
        };
        Ok(fingerprinter)
    }

    /// Create new fingerprinter with interfece IP and gateway IP
    pub fn new_with_gateway_ip(
        src_ip: IpAddr,
        gateway_ip: IpAddr,
    ) -> Result<Fingerprinter, String> {
        let mut if_index: u32 = 0;
        let mut if_name: String = String::new();
        let mut src_mac: default_net::interface::MacAddr = default_net::interface::MacAddr::zero();
        match src_ip {
            IpAddr::V4(_) => {
                for iface in default_net::get_interfaces() {
                    for ip in iface.ipv4 {
                        if ip.addr == src_ip {
                            if_index = iface.index;
                            if_name = iface.name;
                            src_mac = iface.mac_addr.unwrap_or(default_net::interface::MacAddr::zero());
                            break;
                        }
                    }
                }
            }
            IpAddr::V6(_) => {
                for iface in default_net::get_interfaces() {
                    for ip in iface.ipv6 {
                        if ip.addr == src_ip {
                            if_index = iface.index;
                            if_name = iface.name;
                            src_mac = iface.mac_addr.unwrap_or(default_net::interface::MacAddr::zero());
                            break;
                        }
                    }
                }
            }
        }
        if if_index == 0 || if_name.is_empty() || src_mac.octets() == default_net::interface::MacAddr::zero().octets() {
            return Err(String::from(
                "Failed to create Scanner. Network Interface not found.",
            ));
        }
        let interface = crate::interface::get_interface_by_index(if_index).unwrap();
        let dst_mac: MacAddr = match gateway_ip {
            IpAddr::V4(ip) => {
                get_mac_through_arp(interface, ip)
            }
            IpAddr::V6(_) => {
                return Err(String::from(
                    "Failed to create Fingerprinter. Invalid Gateway IP address.",
                ))
            }
        };
        let fingerprinter = Fingerprinter {
            if_index: if_index,
            if_name: if_name,
            src_mac: src_mac.to_string(),
            dst_mac: dst_mac.to_string(),
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            probe_targets: vec![],
            probe_types: vec![],
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            probe_results: vec![],
        };
        Ok(fingerprinter)
    }
    /// Set source port number
    pub fn set_src_port(&mut self, src_port: u16) {
        self.src_port = src_port;
    }
    /// Add probe target (IP address and tcp/udp port)
    pub fn add_probe_target(&mut self, dst_info: ProbeTarget) {
        self.probe_targets.push(dst_info);
    }
    /// Set probe targets
    pub fn set_probe_targets(&mut self, probe_targets: Vec<ProbeTarget>) {
        self.probe_targets = probe_targets;
    }
    /// Add probe type
    pub fn add_probe_type(&mut self, probe_type: ProbeType) {
        self.probe_types.push(probe_type);
    }
    /// Set probe types
    pub fn set_probe_types(&mut self, probe_types: Vec<ProbeType>) {
        self.probe_types = probe_types;
    }
    /// Set all probe types
    pub fn set_full_probe(&mut self) {
        self.probe_types.clear();
        self.probe_types.push(ProbeType::IcmpEchoProbe);
        if self.src_ip.is_ipv4() {
            self.probe_types.push(ProbeType::IcmpTimestampProbe);
            self.probe_types.push(ProbeType::IcmpAddressMaskProbe);
            self.probe_types.push(ProbeType::IcmpInformationProbe);
        }
        self.probe_types.push(ProbeType::IcmpUnreachableProbe);
        self.probe_types.push(ProbeType::TcpSynAckProbe);
        self.probe_types.push(ProbeType::TcpRstAckProbe);
        self.probe_types.push(ProbeType::TcpEcnProbe);
        self.probe_types.push(ProbeType::TcpProbe);
    }
    /// Set probe timeout  
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    /// Set wait-time after the sending task is completed  
    pub fn set_wait_time(&mut self, wait_time: Duration) {
        self.wait_time = wait_time;
    }
    /// Set packet send rate
    pub fn set_send_rate(&mut self, send_rate: Duration) {
        self.send_rate = send_rate;
    }
    /// Get probe result
    pub fn get_probe_results(&self) -> Vec<ProbeResult> {
        self.probe_results.clone()
    }
    /// Run probe with the current settings
    pub fn run_probe(&mut self) {
        let interface: default_net::Interface = crate::interface::get_interface_by_index(self.if_index).unwrap();
        let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
        for dst in self.probe_targets.clone() {
            let mut probe_setting: ProbeSetting = ProbeSetting {
                src_mac: cross_socket::datalink::MacAddr::from_hex_format(self.src_mac.as_str()),
                dst_mac: cross_socket::datalink::MacAddr::from_hex_format(self.dst_mac.as_str()),
                src_ip: self.src_ip,
                src_port: self.src_port,
                probe_target: dst.clone(),
                probe_types: self.probe_types.clone(),
                timeout: self.timeout,
                wait_time: self.wait_time,
                send_rate: self.send_rate,
            };
            let result: ProbeResult = probe(&mut socket, &mut probe_setting);
            self.probe_results.push(result);
        }
    }
    /// Run probe and return result
    pub fn probe(&mut self) -> Vec<ProbeResult> {
        self.run_probe();
        self.probe_results.clone()
    }
}

fn probe(socket: &mut DataLinkSocket, probe_setting: &ProbeSetting) -> ProbeResult {
    let capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: socket.interface.index,
        interface_name: socket.interface.name.clone(),
        src_ips: [probe_setting.probe_target.ip_addr].iter().cloned().collect(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        duration: probe_setting.timeout,
        promiscuous: false,
        store: true,
        store_limit: u32::MAX,
        receive_undefined: false,
    };
    let listener: Listner = Listner::new(capture_options);
    let stop_handle = listener.get_stop_handle();
    let fingerprints: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_fingerprints: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&fingerprints);

    let handler = thread::spawn(move || {
        listener.start();
        for f in listener.get_packets() {
            receive_fingerprints.lock().unwrap().push(f);
        }
    });

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(1));

    send::send_packets(socket, &probe_setting);
    thread::sleep(probe_setting.wait_time);
    *stop_handle.lock().unwrap() = true;

    // Wait for listener to stop
    handler.join().unwrap();
    
    // Parse fingerprints and set result
    let mut result: ProbeResult = ProbeResult::new_with_types(probe_setting.probe_target.ip_addr, probe_setting.probe_types.clone());
    for f in fingerprints.lock().unwrap().iter() {
        let ip_next_protocol: IpNextLevelProtocol = if let Some(ip_packet) = &f.ipv4_packet {
            ip_packet.next_protocol
        }else {
            if let Some(ip_packet) = &f.ipv6_packet {
                ip_packet.next_protocol
            } else {
                continue;
            }
        };
        match ip_next_protocol {
            IpNextLevelProtocol::Tcp => {
                if let Some(tcp_fingerprint) = &f.tcp_packet {
                    if tcp_fingerprint.flags.contains(&TcpFlag::Syn) && tcp_fingerprint.flags.contains(&TcpFlag::Ack) && !tcp_fingerprint.flags.contains(&TcpFlag::Ece) {
                        if let Some(tcp_syn_ack_result) = &mut result.tcp_syn_ack_result {
                            tcp_syn_ack_result.syn_ack_response = true;
                            tcp_syn_ack_result.fingerprints.push(f.clone());
                        }
                    }else if tcp_fingerprint.flags.contains(&TcpFlag::Rst) && tcp_fingerprint.flags.contains(&TcpFlag::Ack) {
                        if let Some(tcp_rst_ack_result) = &mut result.tcp_rst_ack_result {
                            tcp_rst_ack_result.rst_ack_response = true;
                            tcp_rst_ack_result.fingerprints.push(f.clone());
                        }
                    } else if tcp_fingerprint.flags.contains(&TcpFlag::Syn) && tcp_fingerprint.flags.contains(&TcpFlag::Ack) && tcp_fingerprint.flags.contains(&TcpFlag::Ece) {
                        if let Some(tcp_rst_ack_result) = &mut result.tcp_ecn_result {
                            tcp_rst_ack_result.syn_ack_ece_response = true;
                            tcp_rst_ack_result.fingerprints.push(f.clone());
                        }
                    }
                }
            }
            IpNextLevelProtocol::Udp => {}
            IpNextLevelProtocol::Icmp => {
                if let Some(icmp_fingerprint) = &f.icmp_packet {
                    match icmp_fingerprint.icmp_type {
                        IcmpType::EchoReply => {
                            if let Some(icmp_echo_result) = &mut result.icmp_echo_result {
                                icmp_echo_result.icmp_echo_reply = true;
                                icmp_echo_result.fingerprints.push(f.clone());
                            }
                        }
                        IcmpType::DestinationUnreachable => {
                            if let Some(icmp_unreachable_ip_result) = &mut result.icmp_unreachable_ip_result {
                                icmp_unreachable_ip_result.icmp_unreachable_reply = true;
                                let ipv4_packet: Ipv4Packet = Ipv4Packet::from_bytes(&icmp_fingerprint.payload[ICMP_UNUSED_BYTE_SIZE..cross_socket::packet::ipv4::IPV4_HEADER_LEN + ICMP_UNUSED_BYTE_SIZE]);
                                let _udp_packet: UdpPacket = UdpPacket::from_bytes(&icmp_fingerprint.payload[cross_socket::packet::ipv4::IPV4_HEADER_LEN + ICMP_UNUSED_BYTE_SIZE..]);
                                icmp_unreachable_ip_result.icmp_unreachable_size = icmp_fingerprint.payload.len() - ICMP_UNUSED_BYTE_SIZE;
                                icmp_unreachable_ip_result.ip_total_length = ipv4_packet.total_length;
                                icmp_unreachable_ip_result.ip_id = ipv4_packet.identification;
                                if Ipv4Flags::from_u8(ipv4_packet.flags) == Ipv4Flags::DontFragment {
                                    icmp_unreachable_ip_result.ip_df = true;
                                }
                                icmp_unreachable_ip_result.ip_ttl = ipv4_packet.ttl;
                                icmp_unreachable_ip_result.fingerprints.push(f.clone());
                            }
                        }
                        IcmpType::TimestampReply => {
                            if let Some(icmp_timestamp_result) = &mut result.icmp_timestamp_result {
                                icmp_timestamp_result.icmp_timestamp_reply = true;
                                icmp_timestamp_result.fingerprints.push(f.clone());
                            }
                        }
                        IcmpType::AddressMaskReply => {
                            if let Some(icmp_address_mask_result) = &mut result.icmp_address_mask_result {
                                icmp_address_mask_result.icmp_address_mask_reply = true;
                                icmp_address_mask_result.fingerprints.push(f.clone());
                            }
                        }
                        IcmpType::InformationReply => {
                            if let Some(icmp_information_result) = &mut result.icmp_information_result {
                                icmp_information_result.icmp_information_reply = true;
                                icmp_information_result.fingerprints.push(f.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
            IpNextLevelProtocol::Icmpv6 => {
                if let Some(icmpv6_fingerprint) = &f.icmpv6_packet {
                    match icmpv6_fingerprint.icmpv6_type {
                        Icmpv6Type::EchoReply => {
                            if let Some(icmp_echo_result) = &mut result.icmp_echo_result {
                                icmp_echo_result.icmp_echo_reply = true;
                                icmp_echo_result.fingerprints.push(f.clone());
                            }
                        }
                        Icmpv6Type::DestinationUnreachable => {
                            if let Some(icmp_unreachable_ip_result) = &mut result.icmp_unreachable_ip_result {
                                icmp_unreachable_ip_result.icmp_unreachable_reply = true;
                                let ipv6_packet: Ipv6Packet = Ipv6Packet::from_bytes(&icmpv6_fingerprint.payload[ICMP_UNUSED_BYTE_SIZE..cross_socket::packet::ipv6::IPV6_HEADER_LEN + ICMP_UNUSED_BYTE_SIZE]);
                                let _udp_packet: UdpPacket = UdpPacket::from_bytes(&icmpv6_fingerprint.payload[cross_socket::packet::ipv6::IPV6_HEADER_LEN + ICMP_UNUSED_BYTE_SIZE..]);
                                icmp_unreachable_ip_result.icmp_unreachable_size = icmpv6_fingerprint.payload.len() - ICMP_UNUSED_BYTE_SIZE;
                                icmp_unreachable_ip_result.ip_total_length = (icmpv6_fingerprint.payload.len() - 4) as u16;
                                icmp_unreachable_ip_result.ip_ttl = ipv6_packet.hop_limit;
                                icmp_unreachable_ip_result.fingerprints.push(f.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    return result;
}

fn get_mac_through_arp(
    interface: cross_socket::datalink::interface::Interface,
    target_ip: Ipv4Addr,
) -> MacAddr {
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Packet option for ARP request
    let mut packet_option = PacketBuildOption::new();
    packet_option.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_option.dst_mac = MacAddr::zero();
    packet_option.ether_type = cross_socket::packet::ethernet::EtherType::Arp;
    packet_option.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_option.dst_ip = IpAddr::V4(target_ip);

    // Send ARP request to default gateway
    match socket.send(packet_option) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
    let src_mac = socket.interface.mac_addr.clone().unwrap();
    let timeout = Duration::from_millis(10000);
    let start = std::time::Instant::now();
    // Receive packets
    loop {
        match socket.receive() {
            Ok(packet) => {
                let ethernet_packet = cross_socket::packet::ethernet::EthernetPacket::from_bytes(&packet);
                if ethernet_packet.ethertype != cross_socket::packet::ethernet::EtherType::Arp {
                    continue;
                }
                let arp_packet =
                    cross_socket::packet::arp::ArpPacket::from_bytes(&ethernet_packet.payload);
                if arp_packet.sender_hw_addr.address() != src_mac.address() {
                    return arp_packet.sender_hw_addr;
                }
            }
            Err(_) => {}
        }
        // break if timeout
        if start.elapsed() > timeout {
            return MacAddr::zero();
        }
    }
}
