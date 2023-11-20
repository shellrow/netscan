use xenet::net::interface::Interface;
use xenet::packet::ethernet::EtherType;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::packet::frame::Frame;
use xenet::packet::frame::ParseOption;
use crate::PacketCaptureOptions;
use crate::PacketFrame;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Start packet capture
pub(crate) fn start_capture (
    capture_options: PacketCaptureOptions,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    stop: &Arc<Mutex<bool>>,
) -> Vec<PacketFrame> {
    let interfaces = xenet::net::interface::get_interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|interface: &Interface| {
            interface.index == capture_options.interface_index
        })
        .next()
        .expect("Failed to get Interface");
    let config = xenet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(capture_options.read_timeout),
        write_timeout: None,
        channel_type: xenet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: capture_options.promiscuous,
    };
    let (mut _tx, mut rx) = match xenet::datalink::channel(&interface, config) {
        Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(Vec::new()));
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() {
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
                    let packet_frame = PacketFrame::from_xenet_frame(frame);
                    msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
                    if capture_options.store {
                        let mut packets = packets.lock().unwrap();
                        if packets.len() < capture_options.store_limit as usize {
                            packets.push(packet_frame.clone());
                        }
                    }
                    //packets.lock().unwrap().push(packet_frame);
                }
            }
            Err(_) => {},
        }
        if *stop.lock().unwrap() {
            break;
        }
        if Instant::now().duration_since(start_time) > capture_options.duration {
            break;
        }
    }
    let packets = packets.lock().unwrap().clone(); 
    packets
}

fn filter_packet(frame: &Frame, capture_options: &PacketCaptureOptions) -> bool {
    if let Some(datalink) = &frame.datalink {
        if let Some(ethernet_header) = &datalink.ethernet {
            if !filter_ether_type(ethernet_header.ethertype, capture_options) {
                return false;
            }
        }
        if let Some(arp_header) = &datalink.arp {
            if !filter_host(IpAddr::V4(arp_header.sender_proto_addr), IpAddr::V4(arp_header.target_proto_addr), capture_options) {
                return false;   
            }
        }
    }
    if let Some(ip) = &frame.ip {
        if let Some(ipv4_header) = &ip.ipv4 {
            if !filter_host(IpAddr::V4(ipv4_header.source), IpAddr::V4(ipv4_header.destination), capture_options) {
                return false;
            }
            if !filter_ip_protocol(ipv4_header.next_level_protocol, capture_options) {
                return false;
            }
        }
        if let Some(ipv6_header) = &ip.ipv6 {
            if !filter_host(IpAddr::V6(ipv6_header.source), IpAddr::V6(ipv6_header.destination), capture_options) {
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
