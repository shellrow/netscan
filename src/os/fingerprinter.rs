use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use pnet_datalink::{self, MacAddr};
use pnet_packet::{Packet, MutablePacket};

use super::send;
use super::receive;
use super::setting::{ProbeTarget, ProbeType, ProbeSetting};
use super::result::{ProbeStatus, ProbeResult};

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
        for iface in pnet_datalink::interfaces() {
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
            return Err(String::from("Failed to create Fingerprinter. Network Interface not found."));
        }
        let dst_mac: MacAddr = match default_net::get_default_gateway() {
            Ok(default_gateway) => {
                let octets = default_gateway.mac_addr.octets();
                MacAddr::new(octets[0], octets[1], octets[2], octets[3], octets[4], octets[5])
            },
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
            wait_time: Duration::from_millis(100),
            send_rate: Duration::from_millis(1),  
            probe_results: vec![],
        };
        Ok(fingerprinter)
    }

    /// Create new fingerprinter with interfece IP and gateway IP
    pub fn new_with_gateway_ip(src_ip: IpAddr, gateway_ip: IpAddr) -> Result<Fingerprinter, String> {
        let mut if_index: u32 = 0;
        let mut if_name: String = String::new();
        let mut src_mac: MacAddr = MacAddr::zero();
        for iface in pnet_datalink::interfaces() {
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
            return Err(String::from("Failed to create Fingerprinter. Network Interface not found."));
        }
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces.into_iter().filter(|interface: &pnet_datalink::NetworkInterface| interface.index == if_index).next().expect("Failed to get Interface");
        let dst_mac: MacAddr = match gateway_ip {
            IpAddr::V4(ip) =>{
                let dst_mac: MacAddr = get_mac_through_arp(&interface, ip);
                if dst_mac == pnet_datalink::MacAddr::zero() {
                    return Err(String::from("Failed to create Fingerprinter. Invalid Gateway IP address."));
                }
                dst_mac
            },
            IpAddr::V6(_) => return Err(String::from("Failed to create Fingerprinter. Invalid Gateway IP address.")),
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
            wait_time: Duration::from_millis(100),
            send_rate: Duration::from_millis(1),  
            probe_results: vec![],
        };
        Ok(fingerprinter)
    }
    /// Set source port number 
    pub fn set_src_port(&mut self, src_port: u16){
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
        self.probe_types= probe_types;
    }
    /// Set probe timeout  
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    /// Set wait-time after the sending task is completed  
    pub fn set_wait_time(&mut self, wait_time: Duration){
        self.wait_time = wait_time;
    }
    /// Set packet send rate
    pub fn set_send_rate(&mut self, send_rate: Duration){
        self.send_rate = send_rate;
    }
    /// Get probe result
    pub fn get_probe_results(&self) -> Vec<ProbeResult> {
        self.probe_results.clone()
    }
    /// Run probe with the current settings
    pub fn run_probe(&mut self) {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces.into_iter().filter(|interface: &pnet_datalink::NetworkInterface| interface.index == self.if_index).next().expect("Failed to get Interface");
        for dst in self.probe_targets.clone() {
            let mut probe_setting: ProbeSetting = ProbeSetting {
                src_mac: self.src_mac.parse::<pnet_datalink::MacAddr>().unwrap(),
                dst_mac: self.dst_mac.parse::<pnet_datalink::MacAddr>().unwrap(),
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

fn probe(interface: &pnet_datalink::NetworkInterface, probe_setting: &ProbeSetting) -> ProbeResult {
    let probe_result: Arc<Mutex<ProbeResult>> = Arc::new(Mutex::new(ProbeResult::new_with_types(probe_setting.probe_target.ip_addr, probe_setting.probe_types.clone())));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let probe_status: Arc<Mutex<ProbeStatus>> = Arc::new(Mutex::new(ProbeStatus::Ready));
    let config = pnet_datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet_datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    rayon::join(|| send::send_packets(&mut tx, &probe_setting, &stop),
                || receive::receive_packets(&mut rx, &probe_setting, &probe_result, &stop, &probe_status)
    );
    let result: ProbeResult = probe_result.lock().unwrap().clone();
    return result;
}

fn get_mac_through_arp(interface: &pnet_datalink::NetworkInterface, target_ip: Ipv4Addr) -> MacAddr {
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();

    let (mut sender, mut receiver) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = pnet_packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(pnet_datalink::MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(pnet_packet::ethernet::EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = pnet_packet::arp::MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(pnet_packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(pnet_packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(pnet_packet::arp::ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(pnet_datalink::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender.send_to(ethernet_packet.packet(), None).unwrap().unwrap();

    let mut target_mac_addr: pnet_datalink::MacAddr = pnet_datalink::MacAddr::zero();

    for _ in 0..2 {
        let buf = receiver.next().unwrap();
        let arp = pnet_packet::arp::ArpPacket::new(&buf[pnet_packet::ethernet::MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_hw_addr() != interface.mac.unwrap() {
            target_mac_addr = arp.get_sender_hw_addr();
            break;
        }
    }
    return target_mac_addr;
}
