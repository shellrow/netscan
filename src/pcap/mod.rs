use std::net::IpAddr;
//use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::time::Instant;
use std::time::Duration;
use nex::datalink::RawReceiver;
use nex::packet::{ip::IpNextLevelProtocol, ethernet::EtherType};
use nex::packet::frame::Frame;
use nex::packet::frame::ParseOption;
use crate::packet::frame::PacketFrame;

/// Packet capture options
#[derive(Debug, Clone)]
pub struct PacketCaptureOptions {
    /// Interface index
    #[allow(dead_code)]
    pub interface_index: u32,
    /// Source IP addresses to filter. If empty, all source IP addresses will be captured
    pub src_ips: HashSet<IpAddr>,
    /// Destination IP addresses to filter. If empty, all destination IP addresses will be captured
    pub dst_ips: HashSet<IpAddr>,
    /// Source ports to filter. If empty, all source ports will be captured
    pub src_ports: HashSet<u16>,
    /// Destination ports to filter. If empty, all destination ports will be captured
    pub dst_ports: HashSet<u16>,
    /// Ether types to filter. If empty, all ether types will be captured
    pub ether_types: HashSet<EtherType>,
    /// IP protocols to filter. If empty, all IP protocols will be captured
    pub ip_protocols: HashSet<IpNextLevelProtocol>,
    /// Capture duration limit
    pub capture_timeout: Duration,
    /// Use TUN interface
    pub tunnel: bool,
    /// Loopback interface
    pub loopback: bool,
}

/// Start packet capture
pub fn start_capture(
    rx: &mut Box<dyn RawReceiver>,
    capture_options: PacketCaptureOptions,
    stop: &Arc<Mutex<bool>>,
) -> Vec<PacketFrame> {
    let mut frames = Vec::new();
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if capture_options.tunnel || (cfg!(any(target_os = "macos", target_os = "ios")) && capture_options.loopback) {
                    let payload_offset;
                    if capture_options.loopback {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                if filter_packet(&frame, &capture_options) {
                    let packet_frame = PacketFrame::from_nex_frame(&frame);
                    frames.push(packet_frame);
                    /* match msg_tx.send(packet_frame) {
                        Ok(_) => {}
                        Err(_) => {}
                    } */
                }
            }
            Err(_) => {}
        }
        match stop.lock() {
            Ok(stop) => {
                if *stop {
                    break;
                }
            }
            Err(_) => {}
        }
        if Instant::now().duration_since(start_time) > capture_options.capture_timeout {
            break;
        }
    }
    frames
}

/* /// Start packet capture
pub fn start_capture(
    capture_options: PacketCaptureOptions,
    stop: &Arc<Mutex<bool>>,
    interface: Interface,
) -> Vec<PacketFrame> {
    let mut frames = Vec::new();
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(capture_options.read_timeout),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: capture_options.promiscuous,
    };
    let (mut _tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            //thread_log!(warn, "Unknown channel type");
            return frames;
        },
        Err(_e) => {
            //thread_log!(error, "Error happened {}", e);
            return frames;
        },
    };
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() || (cfg!(any(target_os = "macos", target_os = "ios")) && interface.is_loopback()) {
                    let payload_offset;
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                if filter_packet(&frame, &capture_options) {
                    let packet_frame = PacketFrame::from_nex_frame(&frame);
                    frames.push(packet_frame);
                    /* match msg_tx.send(packet_frame) {
                        Ok(_) => {}
                        Err(_) => {}
                    } */
                }
            }
            Err(_) => {}
        }
        match stop.lock() {
            Ok(stop) => {
                if *stop {
                    break;
                }
            }
            Err(_) => {}
        }
        if Instant::now().duration_since(start_time) > capture_options.capture_timeout {
            break;
        }
    }
    frames
} */

fn filter_packet(frame: &Frame, capture_options: &PacketCaptureOptions) -> bool {
    if let Some(datalink) = &frame.datalink {
        if let Some(ethernet_header) = &datalink.ethernet {
            if !filter_ether_type(ethernet_header.ethertype, capture_options) {
                return false;
            }
        }
        if let Some(arp_header) = &datalink.arp {
            if !filter_host(
                IpAddr::V4(arp_header.sender_proto_addr),
                IpAddr::V4(arp_header.target_proto_addr),
                capture_options,
            ) {
                return false;
            }
        }
    }
    if let Some(ip) = &frame.ip {
        if let Some(ipv4_header) = &ip.ipv4 {
            if !filter_host(
                IpAddr::V4(ipv4_header.source),
                IpAddr::V4(ipv4_header.destination),
                capture_options,
            ) {
                return false;
            }
            if !filter_ip_protocol(ipv4_header.next_level_protocol, capture_options) {
                return false;
            }
        }
        if let Some(ipv6_header) = &ip.ipv6 {
            if !filter_host(
                IpAddr::V6(ipv6_header.source),
                IpAddr::V6(ipv6_header.destination),
                capture_options,
            ) {
                return false;
            }
            if !filter_ip_protocol(ipv6_header.next_header, capture_options) {
                return false;
            }
        }
    }
    if let Some(transport) = &frame.transport {
        if let Some(tcp_header) = &transport.tcp {
            if !filter_port(tcp_header.source, tcp_header.destination, capture_options) {
                return false;
            }
        }
        if let Some(udp_header) = &transport.udp {
            if !filter_port(udp_header.source, udp_header.destination, capture_options) {
                return false;
            }
        }
    }
    true
}

fn filter_host(src_ip: IpAddr, dst_ip: IpAddr, capture_options: &PacketCaptureOptions) -> bool {
    if capture_options.src_ips.len() == 0 && capture_options.dst_ips.len() == 0 {
        return true;
    }
    if capture_options.src_ips.contains(&src_ip) || capture_options.dst_ips.contains(&dst_ip) {
        return true;
    } else {
        return false;
    }
}

fn filter_port(src_port: u16, dst_port: u16, capture_options: &PacketCaptureOptions) -> bool {
    if capture_options.src_ports.len() == 0 && capture_options.dst_ports.len() == 0 {
        return true;
    }
    if capture_options.src_ports.contains(&src_port)
        || capture_options.dst_ports.contains(&dst_port)
    {
        return true;
    } else {
        return false;
    }
}

fn filter_ether_type(ether_type: EtherType, capture_options: &PacketCaptureOptions) -> bool {
    if capture_options.ether_types.len() == 0 || capture_options.ether_types.contains(&ether_type) {
        return true;
    } else {
        return false;
    }
}

fn filter_ip_protocol(
    protocol: IpNextLevelProtocol,
    capture_options: &PacketCaptureOptions,
) -> bool {
    if capture_options.ip_protocols.len() == 0 || capture_options.ip_protocols.contains(&protocol) {
        return true;
    } else {
        return false;
    }
}
