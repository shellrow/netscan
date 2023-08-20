use np_listener::packet::icmp::{IcmpType, Icmpv6Type};
use np_listener::packet::tcp::TcpFlagKind;
use pnet::datalink::MacAddr;
use pnet::packet::{MutablePacket, Packet};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use np_listener::listener::Listner;
use np_listener::option::PacketCaptureOptions;
use np_listener::packet::TcpIpFingerprint;
use np_listener::packet::ip::IpNextLevelProtocol;

use super::result::ProbeResult;
use super::send;
use super::setting::{ProbeSetting, ProbeTarget, ProbeType};

const DEFAULT_SRC_PORT: u16 = 54433;

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
        let mut src_mac: MacAddr = MacAddr::zero();
        for iface in pnet::datalink::interfaces() {
            for ip in iface.ips {
                if ip.ip() == src_ip {
                    if_index = iface.index;
                    if_name = iface.name;
                    src_mac = iface.mac.unwrap_or(MacAddr::zero());
                    break;
                }
            }
        }
        if if_index == 0 || if_name.is_empty() || src_mac == MacAddr::zero() {
            return Err(String::from(
                "Failed to create Fingerprinter. Network Interface not found.",
            ));
        }
        let dst_mac: MacAddr = match default_net::get_default_gateway() {
            Ok(default_gateway) => {
                let octets = default_gateway.mac_addr.octets();
                MacAddr::new(
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                )
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
        let mut src_mac: MacAddr = MacAddr::zero();
        for iface in pnet::datalink::interfaces() {
            for ip in iface.ips {
                if ip.ip() == src_ip {
                    if_index = iface.index;
                    if_name = iface.name;
                    src_mac = iface.mac.unwrap_or(MacAddr::zero());
                    break;
                }
            }
        }
        if if_index == 0 || if_name.is_empty() || src_mac == MacAddr::zero() {
            return Err(String::from(
                "Failed to create Fingerprinter. Network Interface not found.",
            ));
        }
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(|interface: &pnet::datalink::NetworkInterface| interface.index == if_index)
            .next()
            .expect("Failed to get Interface");
        let dst_mac: MacAddr = match gateway_ip {
            IpAddr::V4(ip) => {
                let dst_mac: MacAddr = get_mac_through_arp(&interface, ip);
                if dst_mac == pnet::datalink::MacAddr::zero() {
                    return Err(String::from(
                        "Failed to create Fingerprinter. Invalid Gateway IP address.",
                    ));
                }
                dst_mac
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
        self.probe_types.push(ProbeType::IcmpTimestampProbe);
        self.probe_types.push(ProbeType::IcmpAddressMaskProbe);
        self.probe_types.push(ProbeType::IcmpInformationProbe);
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
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(|interface: &pnet::datalink::NetworkInterface| interface.index == self.if_index)
            .next()
            .expect("Failed to get Interface");
        for dst in self.probe_targets.clone() {
            let mut probe_setting: ProbeSetting = ProbeSetting {
                src_mac: self.src_mac.parse::<pnet::datalink::MacAddr>().unwrap(),
                dst_mac: self.dst_mac.parse::<pnet::datalink::MacAddr>().unwrap(),
                src_ip: self.src_ip,
                src_port: self.src_port,
                probe_target: dst.clone(),
                probe_types: self.probe_types.clone(),
                timeout: self.timeout,
                wait_time: self.wait_time,
                send_rate: self.send_rate,
            };
            let result: ProbeResult = probe(&interface, &mut probe_setting);
            self.probe_results.push(result);
        }
    }
    /// Run probe and return result
    pub fn probe(&mut self) -> Vec<ProbeResult> {
        self.run_probe();
        self.probe_results.clone()
    }
}

fn probe(interface: &pnet::datalink::NetworkInterface, probe_setting: &ProbeSetting) -> ProbeResult {
    let config = pnet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut tx, mut _rx) = match pnet::datalink::channel(&interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name.clone(),
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
    };
    let listener: Listner = Listner::new(capture_options);
    let stop_handle = listener.get_stop_handle();
    let fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>> = Arc::new(Mutex::new(vec![]));
    let receive_fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>> = Arc::clone(&fingerprints);

    let handler = thread::spawn(move || {
        listener.start();
        for f in listener.get_fingerprints() {
            receive_fingerprints.lock().unwrap().push(f);
        }
    });

    // Wait for listener to start (need fix for better way)
    thread::sleep(Duration::from_millis(1));

    send::send_packets(&mut tx, &probe_setting);
    thread::sleep(probe_setting.wait_time);
    *stop_handle.lock().unwrap() = true;

    // Wait for listener to stop
    handler.join().unwrap();
    
    // Parse fingerprints and set result
    let mut result: ProbeResult = ProbeResult::new_with_types(probe_setting.probe_target.ip_addr, probe_setting.probe_types.clone());
    for f in fingerprints.lock().unwrap().iter() {
        match f.ip_fingerprint.next_level_protocol {
            IpNextLevelProtocol::Tcp => {
                if let Some(tcp_fingerprint) = &f.tcp_fingerprint {
                    if tcp_fingerprint.flags.contains(&TcpFlagKind::Syn) && tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) && !tcp_fingerprint.flags.contains(&TcpFlagKind::Ece) {
                        if let Some(tcp_syn_ack_result) = &mut result.tcp_syn_ack_result {
                            tcp_syn_ack_result.syn_ack_response = true;
                            tcp_syn_ack_result.fingerprints.push(f.clone());
                        }
                    }else if tcp_fingerprint.flags.contains(&TcpFlagKind::Rst) && tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) {
                        if let Some(tcp_rst_ack_result) = &mut result.tcp_rst_ack_result {
                            tcp_rst_ack_result.rst_ack_response = true;
                            tcp_rst_ack_result.fingerprints.push(f.clone());
                        }
                    } else if tcp_fingerprint.flags.contains(&TcpFlagKind::Syn) && tcp_fingerprint.flags.contains(&TcpFlagKind::Ack) && tcp_fingerprint.flags.contains(&TcpFlagKind::Ece) {
                        if let Some(tcp_rst_ack_result) = &mut result.tcp_ecn_result {
                            tcp_rst_ack_result.syn_ack_ece_response = true;
                            tcp_rst_ack_result.fingerprints.push(f.clone());
                        }
                    }
                }
            }
            IpNextLevelProtocol::Udp => {}
            IpNextLevelProtocol::Icmp => {
                if let Some(icmp_fingerprint) = &f.icmp_fingerprint {
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
                if let Some(icmpv6_fingerprint) = &f.icmpv6_fingerprint {
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
                                icmp_unreachable_ip_result.fingerprints.push(f.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        result.fingerprints.push(f.clone());
    }
    return result;
}

fn get_mac_through_arp(
    interface: &pnet::datalink::NetworkInterface,
    target_ip: Ipv4Addr,
) -> MacAddr {
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();

    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet =
        pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(pnet::datalink::MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = pnet::packet::arp::MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(pnet::packet::arp::ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(pnet::datalink::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();

    let mut target_mac_addr: pnet::datalink::MacAddr = pnet::datalink::MacAddr::zero();

    for _ in 0..2 {
        let buf = receiver.next().unwrap();
        let arp = pnet::packet::arp::ArpPacket::new(
            &buf[pnet::packet::ethernet::MutableEthernetPacket::minimum_packet_size()..],
        )
        .unwrap();
        if arp.get_sender_hw_addr() != interface.mac.unwrap() {
            target_mac_addr = arp.get_sender_hw_addr();
            break;
        }
    }
    return target_mac_addr;
}
