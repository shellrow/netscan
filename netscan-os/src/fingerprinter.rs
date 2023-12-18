use netscan_pcap::listener::Listner;
use netscan_pcap::PacketCaptureOptions;
use netscan_pcap::PacketFrame;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use xenet::datalink::DataLinkSender;
use xenet::net::interface::Interface;
use xenet::net::mac::MacAddr;
use xenet::packet::frame::{Frame, ParseOption};
use xenet::packet::icmp::IcmpType;
use xenet::packet::icmpv6::Icmpv6Type;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use xenet::packet::ipv6::Ipv6Packet;
use xenet::packet::tcp::TcpFlags;
use xenet::packet::udp::UdpPacket;
use xenet::util::packet_builder::util::PacketBuildOption;

use crate::interface;

use super::result::ProbeResult;
use super::send;
use super::setting::LISTENER_WAIT_TIME_MILLIS;
use super::setting::{ProbeSetting, ProbeTarget, ProbeType};

const DEFAULT_SRC_PORT: u16 = 54433;
const ICMP_UNUSED_BYTE_SIZE: usize = 4;

/// Struct for fingerprint probe
pub struct Fingerprinter {
    /// Probe setting
    pub probe_setting: ProbeSetting,
    /// Result of probes  
    pub probe_result: ProbeResult,
}

impl Fingerprinter {
    /// Create new fingerprinter with Interfece IP
    pub fn new(src_ip: IpAddr) -> Result<Fingerprinter, String> {
        let network_interface =
            if let Some(network_interface) = interface::get_interface_by_ip(src_ip) {
                network_interface
            } else {
                return Err(String::from(
                    "Failed to create Scanner. Network Interface not found.",
                ));
            };
        let use_tun = network_interface.is_tun();
        let loopback = network_interface.is_loopback();
        let probe_setting: ProbeSetting = ProbeSetting {
            if_index: network_interface.index,
            if_name: network_interface.name.clone(),
            src_mac: if use_tun {
                MacAddr::zero()
            } else {
                interface::get_interface_macaddr(&network_interface)
            },
            dst_mac: if use_tun {
                MacAddr::zero()
            } else {
                interface::get_gateway_macaddr(&network_interface)
            },
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            probe_target: ProbeTarget::new(),
            probe_types: vec![],
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        let fingerprinter = Fingerprinter {
            probe_setting: probe_setting,
            probe_result: ProbeResult::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        };
        Ok(fingerprinter)
    }
    /// Create new fingerprinter with Interfece Index
    pub fn new_with_index(if_index: u32) -> Result<Fingerprinter, String> {
        let network_interface =
            if let Some(network_interface) = interface::get_interface_by_index(if_index) {
                network_interface
            } else {
                return Err(String::from(
                    "Failed to create Scanner. Network Interface not found.",
                ));
            };
        let src_ip: IpAddr = match interface::get_interface_ipv4(&network_interface) {
            Some(ip) => ip,
            None => match interface::get_interface_ipv6(&network_interface) {
                Some(ip) => ip,
                None => {
                    return Err(String::from(
                        "Failed to create Fingerprinter. Invalid Interface IP address.",
                    ))
                }
            },
        };
        let use_tun = network_interface.is_tun();
        let loopback = network_interface.is_loopback();
        let probe_setting: ProbeSetting = ProbeSetting {
            if_index: network_interface.index,
            if_name: network_interface.name.clone(),
            src_mac: if use_tun {
                MacAddr::zero()
            } else {
                interface::get_interface_macaddr(&network_interface)
            },
            dst_mac: if use_tun {
                MacAddr::zero()
            } else {
                interface::get_gateway_macaddr(&network_interface)
            },
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            probe_target: ProbeTarget::new(),
            probe_types: vec![],
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        let fingerprinter = Fingerprinter {
            probe_setting: probe_setting,
            probe_result: ProbeResult::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        };
        Ok(fingerprinter)
    }
    /// Create new fingerprinter with Interfece Name
    pub fn new_with_name(if_name: String) -> Result<Fingerprinter, String> {
        let network_interface =
            if let Some(network_interface) = interface::get_interface_by_name(if_name) {
                network_interface
            } else {
                return Err(String::from(
                    "Failed to create Scanner. Network Interface not found.",
                ));
            };
        let src_ip = interface::get_interface_ipv4(&network_interface).unwrap_or(
            interface::get_interface_ipv6(&network_interface)
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        );
        let use_tun = network_interface.is_tun();
        let loopback = network_interface.is_loopback();
        let probe_setting: ProbeSetting = ProbeSetting {
            if_index: network_interface.index,
            if_name: network_interface.name.clone(),
            src_mac: if use_tun {
                MacAddr::zero()
            } else {
                interface::get_interface_macaddr(&network_interface)
            },
            dst_mac: if use_tun {
                MacAddr::zero()
            } else {
                interface::get_gateway_macaddr(&network_interface)
            },
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            probe_target: ProbeTarget::new(),
            probe_types: vec![],
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        let fingerprinter = Fingerprinter {
            probe_setting: probe_setting,
            probe_result: ProbeResult::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        };
        Ok(fingerprinter)
    }
    /// Create new fingerprinter with interfece IP and gateway IP
    pub fn new_with_gateway_ip(
        src_ip: IpAddr,
        gateway_ip: IpAddr,
    ) -> Result<Fingerprinter, String> {
        let network_interface =
            if let Some(network_interface) = interface::get_interface_by_ip(src_ip) {
                network_interface
            } else {
                return Err(String::from(
                    "Failed to create Scanner. Network Interface not found.",
                ));
            };
        let use_tun = network_interface.is_tun();
        let loopback = network_interface.is_loopback();
        let dst_mac: MacAddr = match gateway_ip {
            IpAddr::V4(ip) => get_mac_through_arp(network_interface.clone(), ip),
            IpAddr::V6(_) => {
                return Err(String::from(
                    "Failed to create Fingerprinter. Invalid Gateway IP address.",
                ))
            }
        };
        let probe_setting: ProbeSetting = ProbeSetting {
            if_index: network_interface.index,
            if_name: network_interface.name,
            src_mac: if use_tun {
                MacAddr::zero()
            } else {
                network_interface.mac_addr.unwrap_or(MacAddr::zero())
            },
            dst_mac: dst_mac,
            src_ip: src_ip,
            src_port: DEFAULT_SRC_PORT,
            probe_target: ProbeTarget::new(),
            probe_types: vec![],
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        let fingerprinter = Fingerprinter {
            probe_setting: probe_setting,
            probe_result: ProbeResult::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        };
        Ok(fingerprinter)
    }
    /// Set source port number
    pub fn set_src_port(&mut self, src_port: u16) {
        self.probe_setting.src_port = src_port;
    }
    /// Set probe target (IP address and tcp/udp port)
    pub fn set_probe_target(&mut self, probe_target: ProbeTarget) {
        self.probe_setting.probe_target = probe_target;
    }
    /// Add probe type
    pub fn add_probe_type(&mut self, probe_type: ProbeType) {
        self.probe_setting.probe_types.push(probe_type);
    }
    /// Set probe types
    pub fn set_probe_types(&mut self, probe_types: Vec<ProbeType>) {
        self.probe_setting.probe_types = probe_types;
    }
    /// Set all probe types
    pub fn set_full_probe(&mut self) {
        self.probe_setting.probe_types.clear();
        self.probe_setting
            .probe_types
            .push(ProbeType::IcmpEchoProbe);
        if self.probe_setting.src_ip.is_ipv4() {
            self.probe_setting
                .probe_types
                .push(ProbeType::IcmpTimestampProbe);
            self.probe_setting
                .probe_types
                .push(ProbeType::IcmpAddressMaskProbe);
            self.probe_setting
                .probe_types
                .push(ProbeType::IcmpInformationProbe);
        }
        self.probe_setting
            .probe_types
            .push(ProbeType::IcmpUnreachableProbe);
        self.probe_setting
            .probe_types
            .push(ProbeType::TcpSynAckProbe);
        self.probe_setting
            .probe_types
            .push(ProbeType::TcpRstAckProbe);
        self.probe_setting.probe_types.push(ProbeType::TcpEcnProbe);
        self.probe_setting.probe_types.push(ProbeType::TcpProbe);
    }
    /// Set probe timeout  
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.probe_setting.timeout = timeout;
    }
    /// Set wait-time after the sending task is completed  
    pub fn set_wait_time(&mut self, wait_time: Duration) {
        self.probe_setting.wait_time = wait_time;
    }
    /// Set packet send rate
    pub fn set_send_rate(&mut self, send_rate: Duration) {
        self.probe_setting.send_rate = send_rate;
    }
    /// Get probe result
    pub fn get_probe_result(&self) -> ProbeResult {
        self.probe_result.clone()
    }
    /// Run probe with the current settings
    pub fn run_probe(&mut self) {
        let interface: Interface =
            match crate::interface::get_interface_by_index(self.probe_setting.if_index) {
                Some(interface) => interface,
                None => {
                    return;
                }
            };
        let config = xenet::datalink::Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: Some(self.probe_setting.wait_time),
            write_timeout: None,
            channel_type: xenet::datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: false,
        };
        let (mut tx, mut _rx) = match xenet::datalink::channel(&interface, config) {
            Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!("Failed to create channel: {}", e),
        };
        let result: ProbeResult = probe(&mut tx, &mut self.probe_setting);
        self.probe_result = result;
    }
    /// Run probe and return result
    pub fn probe(&mut self) -> ProbeResult {
        self.run_probe();
        self.probe_result.clone()
    }
}

fn probe(sender: &mut Box<dyn DataLinkSender>, probe_setting: &ProbeSetting) -> ProbeResult {
    let capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: probe_setting.if_index,
        interface_name: probe_setting.if_name.clone(),
        src_ips: [probe_setting.probe_target.ip_addr]
            .iter()
            .cloned()
            .collect(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        duration: probe_setting.timeout,
        read_timeout: probe_setting.wait_time,
        promiscuous: false,
        store: true,
        store_limit: u32::MAX,
        receive_undefined: false,
        tunnel: probe_setting.tunnel,
        loopback: probe_setting.loopback,
    };
    let listener: Listner = Listner::new(capture_options);
    let stop_handle = listener.get_stop_handle();
    let fingerprints: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_fingerprints: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&fingerprints);

    let handler = thread::spawn(move || {
        let packets: Vec<PacketFrame> = listener.start();
        for f in packets {
            match receive_fingerprints.lock() {
                Ok(mut fingerprints) => {
                    fingerprints.push(f);
                }
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                }
            }
        }
    });

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(LISTENER_WAIT_TIME_MILLIS));

    send::send_packets(sender, &probe_setting);
    thread::sleep(probe_setting.wait_time);

    // Stop listener
    match stop_handle.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }

    // Wait for listener to stop
    match handler.join() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    // Parse fingerprints and set result
    let mut result: ProbeResult = ProbeResult::new_with_types(
        probe_setting.probe_target.ip_addr,
        probe_setting.probe_types.clone(),
    );
    match fingerprints.lock() {
        Ok(fingerprints) => {
            for f in fingerprints.iter() {
                let ip_next_protocol: IpNextLevelProtocol = if let Some(ip_packet) = &f.ipv4_header
                {
                    ip_packet.next_level_protocol
                } else {
                    if let Some(ip_packet) = &f.ipv6_header {
                        ip_packet.next_header
                    } else {
                        continue;
                    }
                };
                match ip_next_protocol {
                    IpNextLevelProtocol::Tcp => {
                        if let Some(tcp_fingerprint) = &f.tcp_header {
                            if tcp_fingerprint.flags == TcpFlags::SYN | TcpFlags::ACK
                                && tcp_fingerprint.flags
                                    != TcpFlags::SYN | TcpFlags::ACK | TcpFlags::ECE
                            {
                                if let Some(tcp_syn_ack_result) = &mut result.tcp_syn_ack_result {
                                    tcp_syn_ack_result.syn_ack_response = true;
                                    tcp_syn_ack_result.fingerprints.push(f.clone());
                                }
                            } else if tcp_fingerprint.flags == TcpFlags::RST | TcpFlags::ACK {
                                if let Some(tcp_rst_ack_result) = &mut result.tcp_rst_ack_result {
                                    tcp_rst_ack_result.rst_ack_response = true;
                                    tcp_rst_ack_result.fingerprints.push(f.clone());
                                }
                            } else if tcp_fingerprint.flags
                                == TcpFlags::SYN | TcpFlags::ACK | TcpFlags::ECE
                            {
                                if let Some(tcp_rst_ack_result) = &mut result.tcp_ecn_result {
                                    tcp_rst_ack_result.syn_ack_ece_response = true;
                                    tcp_rst_ack_result.fingerprints.push(f.clone());
                                }
                            }
                        }
                    }
                    IpNextLevelProtocol::Udp => {}
                    IpNextLevelProtocol::Icmp => {
                        if let Some(icmp_fingerprint) = &f.icmp_header {
                            match icmp_fingerprint.icmp_type {
                                IcmpType::EchoReply => {
                                    if let Some(icmp_echo_result) = &mut result.icmp_echo_result {
                                        icmp_echo_result.icmp_echo_reply = true;
                                        icmp_echo_result.fingerprints.push(f.clone());
                                    }
                                }
                                IcmpType::DestinationUnreachable => {
                                    if let Some(icmp_unreachable_ip_result) =
                                        &mut result.icmp_unreachable_ip_result
                                    {
                                        icmp_unreachable_ip_result.icmp_unreachable_reply = true;
                                        if let Some(ipv4_packet) = Ipv4Packet::new(
                                            &f.payload[ICMP_UNUSED_BYTE_SIZE
                                                ..xenet::packet::ipv4::IPV4_HEADER_LEN
                                                    + ICMP_UNUSED_BYTE_SIZE],
                                        ) {
                                            if let Some(_udp_packet) = UdpPacket::new(
                                                &f.payload[xenet::packet::ipv4::IPV4_HEADER_LEN
                                                    + ICMP_UNUSED_BYTE_SIZE..],
                                            ) {
                                                // TODO
                                            }
                                            icmp_unreachable_ip_result.ip_total_length =
                                                ipv4_packet.get_total_length();
                                            icmp_unreachable_ip_result.ip_id =
                                                ipv4_packet.get_identification();
                                            if ipv4_packet.get_flags() == Ipv4Flags::DontFragment {
                                                icmp_unreachable_ip_result.ip_df = true;
                                            }
                                            icmp_unreachable_ip_result.ip_ttl =
                                                ipv4_packet.get_ttl();
                                        }
                                        icmp_unreachable_ip_result.icmp_unreachable_size =
                                            f.payload.len() - ICMP_UNUSED_BYTE_SIZE;
                                        icmp_unreachable_ip_result.fingerprints.push(f.clone());
                                    }
                                }
                                IcmpType::TimestampReply => {
                                    if let Some(icmp_timestamp_result) =
                                        &mut result.icmp_timestamp_result
                                    {
                                        icmp_timestamp_result.icmp_timestamp_reply = true;
                                        icmp_timestamp_result.fingerprints.push(f.clone());
                                    }
                                }
                                IcmpType::AddressMaskReply => {
                                    if let Some(icmp_address_mask_result) =
                                        &mut result.icmp_address_mask_result
                                    {
                                        icmp_address_mask_result.icmp_address_mask_reply = true;
                                        icmp_address_mask_result.fingerprints.push(f.clone());
                                    }
                                }
                                IcmpType::InformationReply => {
                                    if let Some(icmp_information_result) =
                                        &mut result.icmp_information_result
                                    {
                                        icmp_information_result.icmp_information_reply = true;
                                        icmp_information_result.fingerprints.push(f.clone());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    IpNextLevelProtocol::Icmpv6 => {
                        if let Some(icmpv6_fingerprint) = &f.icmpv6_header {
                            match icmpv6_fingerprint.icmpv6_type {
                                Icmpv6Type::EchoReply => {
                                    if let Some(icmp_echo_result) = &mut result.icmp_echo_result {
                                        icmp_echo_result.icmp_echo_reply = true;
                                        icmp_echo_result.fingerprints.push(f.clone());
                                    }
                                }
                                Icmpv6Type::DestinationUnreachable => {
                                    if let Some(icmp_unreachable_ip_result) =
                                        &mut result.icmp_unreachable_ip_result
                                    {
                                        icmp_unreachable_ip_result.icmp_unreachable_reply = true;
                                        if let Some(ipv6_packet) = Ipv6Packet::new(
                                            &f.payload[ICMP_UNUSED_BYTE_SIZE
                                                ..xenet::packet::ipv6::IPV6_HEADER_LEN
                                                    + ICMP_UNUSED_BYTE_SIZE],
                                        ) {
                                            if let Some(_udp_packet) = UdpPacket::new(
                                                &f.payload[xenet::packet::ipv6::IPV6_HEADER_LEN
                                                    + ICMP_UNUSED_BYTE_SIZE..],
                                            ) {
                                                // TODO
                                            }
                                            icmp_unreachable_ip_result.ip_ttl =
                                                ipv6_packet.get_hop_limit();
                                        }
                                        icmp_unreachable_ip_result.icmp_unreachable_size =
                                            f.payload.len() - ICMP_UNUSED_BYTE_SIZE;
                                        icmp_unreachable_ip_result.ip_total_length =
                                            (f.payload.len() - ICMP_UNUSED_BYTE_SIZE) as u16;
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
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    return result;
}

fn get_mac_through_arp(interface: Interface, target_ip: Ipv4Addr) -> MacAddr {
    // Create new socket
    let config = xenet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(Duration::from_millis(100)),
        write_timeout: None,
        channel_type: xenet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut tx, mut rx) = match xenet::datalink::channel(&interface, config) {
        Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create channel: {}", e),
    };
    let src_mac = match interface.mac_addr {
        Some(mac) => mac,
        None => {
            return MacAddr::zero();
        }
    };
    // Packet option for ARP request
    let mut packet_option = PacketBuildOption::new();
    packet_option.src_mac = src_mac;
    packet_option.dst_mac = MacAddr::zero();
    packet_option.ether_type = xenet::packet::ethernet::EtherType::Arp;
    packet_option.src_ip = IpAddr::V4(interface.ipv4[0].addr);
    packet_option.dst_ip = IpAddr::V4(target_ip);

    let arp_packet: Vec<u8> =
        xenet::util::packet_builder::util::build_full_arp_packet(packet_option);
    // Send ARP request
    match tx.send(&arp_packet) {
        Some(_) => {}
        None => {}
    }

    let timeout = Duration::from_millis(10000);
    let start = std::time::Instant::now();
    // Receive packets until timeout
    loop {
        if start.elapsed() > timeout {
            return MacAddr::zero();
        }
        match rx.next() {
            Ok(packet) => {
                let frame: Frame = Frame::from_bytes(&packet, ParseOption::default());
                if let Some(datalink) = frame.datalink {
                    if let Some(ethernet_header) = datalink.ethernet {
                        if ethernet_header.ethertype == xenet::packet::ethernet::EtherType::Arp {
                            if let Some(arp_header) = datalink.arp {
                                if arp_header.sender_hw_addr.address() != src_mac.address()
                                    && arp_header.sender_proto_addr == target_ip
                                {
                                    return arp_header.sender_hw_addr;
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
}
