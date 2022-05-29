use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::net::IpAddr;
use pnet_packet::Packet;
use pnet_packet::icmp::IcmpTypes;
use pnet_packet::icmpv6::Icmpv6Types;
use pnet_packet::tcp::TcpOptionNumbers;
use pnet_packet::icmp::destination_unreachable;
use super::setting::{ProbeSetting, TcpOptionKind};
use super::result::*;
use crate::packet::ipv4::IPV4_HEADER_LEN;
use crate::packet::ipv6::IPV6_HEADER_LEN;

pub(crate) fn receive_packets(rx: &mut Box<dyn pnet_datalink::DataLinkReceiver>, probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>,  stop: &Arc<Mutex<bool>>, probe_status: &Arc<Mutex<ProbeStatus>>) {
    let start_time = Instant::now();
    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = pnet_packet::ethernet::EthernetPacket::new(frame).unwrap();
                match frame.get_ethertype() {
                    pnet_packet::ethernet::EtherTypes::Ipv4 => {
                        ipv4_handler(&frame, probe_setting, &probe_result);
                    },
                    pnet_packet::ethernet::EtherTypes::Ipv6 => {
                        ipv6_handler(&frame, probe_setting, &probe_result);
                    },
                    _ => {},
                }
            },
            Err(e) => {
                panic!("Failed to read: {}", e);
            }
        }
        if *stop.lock().unwrap(){
            *probe_status.lock().unwrap() = ProbeStatus::Done;
            break;
        }
        if Instant::now().duration_since(start_time) > probe_setting.timeout {
            *probe_status.lock().unwrap() = ProbeStatus::Timeout;
            break;
        }
    }
}

fn ipv4_handler(ethernet: &pnet_packet::ethernet::EthernetPacket, probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>) {
    if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(ethernet.payload()){
        if IpAddr::V4(packet.get_source()) == probe_setting.probe_target.ip_addr {
            match packet.get_next_level_protocol() {
                pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                    tcp_handler_v4(&packet, probe_setting, probe_result);
                },
                pnet_packet::ip::IpNextHeaderProtocols::Udp => {
                    udp_handler_v4(&packet, probe_setting, probe_result);
                },
                pnet_packet::ip::IpNextHeaderProtocols::Icmp => {
                    icmp_handler_v4(&packet, probe_setting, probe_result);
                }
                _ => {}
            }
        }
    }
}

fn ipv6_handler(ethernet: &pnet_packet::ethernet::EthernetPacket, probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>) {
    if let Some(packet) = pnet_packet::ipv6::Ipv6Packet::new(ethernet.payload()){
        if IpAddr::V6(packet.get_source()) == probe_setting.probe_target.ip_addr {
            match packet.get_next_header() {
                pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                    tcp_handler_v6(&packet, probe_setting, probe_result);
                },
                pnet_packet::ip::IpNextHeaderProtocols::Udp => {
                    udp_handler_v6(&packet, probe_setting, probe_result);
                },
                pnet_packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                    icmp_handler_v6(&packet, probe_setting, probe_result);
                },
                _ => {}
            }
        }
    }
}

fn tcp_handler_v4(packet: &pnet_packet::ipv4::Ipv4Packet, _probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>) {
    let tcp_packet = pnet_packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp_packet) = tcp_packet {
        let mut tcp_options: Vec<TcpOptionKind> = vec![];
        for opt in tcp_packet.get_options_iter() {
            match opt.get_number() {
                TcpOptionNumbers::EOL => tcp_options.push(TcpOptionKind::Eol),
                TcpOptionNumbers::NOP => tcp_options.push(TcpOptionKind::Nop),
                TcpOptionNumbers::MSS => tcp_options.push(TcpOptionKind::Mss),
                TcpOptionNumbers::WSCALE => tcp_options.push(TcpOptionKind::Wscale),
                TcpOptionNumbers::SACK_PERMITTED => tcp_options.push(TcpOptionKind::SackParmitted),
                TcpOptionNumbers::SACK => tcp_options.push(TcpOptionKind::Sack),
                TcpOptionNumbers::TIMESTAMPS => tcp_options.push(TcpOptionKind::Timestamp),
                _ => {},
            }
        }
        let header_result: TcpHeaderResult = TcpHeaderResult {
            tcp_window_size: tcp_packet.get_window(),
            tcp_option_order: tcp_options,
        };
        if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK {
            probe_result.lock().unwrap().tcp_header_result = Some(header_result);
            let result: TcpSynAckResult = TcpSynAckResult{
                syn_ack_response: true,
                ip_id: packet.get_identification(),
                ip_df: if packet.get_flags() >= 2 {true}else{false},
                ip_ttl: packet.get_ttl(),
            };
            probe_result.lock().unwrap().tcp_syn_ack_result = Some(result);
        }else if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::RST | pnet_packet::tcp::TcpFlags::ACK {
            let result: TcpRstAckResult = TcpRstAckResult{
                rst_ack_response: true,
                tcp_payload_size: tcp_packet.payload().len() as u16,
                ip_id: packet.get_identification(),
                ip_df: if packet.get_flags() >= 2 {true}else{false},
                ip_ttl: packet.get_ttl(),
            };
            probe_result.lock().unwrap().tcp_rst_ack_result = Some(result);
        }else if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK | pnet_packet::tcp::TcpFlags::ECE {
            let tcp_header_result: Option<TcpHeaderResult> = probe_result.lock().unwrap().tcp_header_result.clone();
            match tcp_header_result {
                Some(_) => {},
                None => {
                    probe_result.lock().unwrap().tcp_header_result = Some(header_result);
                },
            }
            let result: TcpEcnResult = TcpEcnResult{
                syn_ack_ece_response: true,
                tcp_payload_size: tcp_packet.payload().len() as u16,
                ip_id: packet.get_identification(),
                ip_df: if packet.get_flags() >= 2 {true}else{false},
                ip_ttl: packet.get_ttl(),
            };
            probe_result.lock().unwrap().tcp_ecn_result = Some(result);
        }
    }
}

fn tcp_handler_v6(packet: &pnet_packet::ipv6::Ipv6Packet, _probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>) {
    let tcp_packet = pnet_packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp_packet) = tcp_packet {
        let mut tcp_options: Vec<TcpOptionKind> = vec![];
        for opt in tcp_packet.get_options_iter() {
            match opt.get_number() {
                TcpOptionNumbers::EOL => tcp_options.push(TcpOptionKind::Eol),
                TcpOptionNumbers::NOP => tcp_options.push(TcpOptionKind::Nop),
                TcpOptionNumbers::MSS => tcp_options.push(TcpOptionKind::Mss),
                TcpOptionNumbers::WSCALE => tcp_options.push(TcpOptionKind::Wscale),
                TcpOptionNumbers::SACK_PERMITTED => tcp_options.push(TcpOptionKind::SackParmitted),
                TcpOptionNumbers::SACK => tcp_options.push(TcpOptionKind::Sack),
                TcpOptionNumbers::TIMESTAMPS => tcp_options.push(TcpOptionKind::Timestamp),
                _ => {},
            }
        }
        let header_result: TcpHeaderResult = TcpHeaderResult {
            tcp_window_size: tcp_packet.get_window(),
            tcp_option_order: tcp_options,
        };
        if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK {
            probe_result.lock().unwrap().tcp_header_result = Some(header_result);
            let result: TcpSynAckResult = TcpSynAckResult{
                syn_ack_response: true,
                ip_id: 0,
                ip_df: false,
                ip_ttl: packet.get_hop_limit(),
            };
            probe_result.lock().unwrap().tcp_syn_ack_result = Some(result);
        }else if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::RST | pnet_packet::tcp::TcpFlags::ACK {
            let result: TcpRstAckResult = TcpRstAckResult{
                rst_ack_response: true,
                tcp_payload_size: tcp_packet.payload().len() as u16,
                ip_id: 0,
                ip_df: false,
                ip_ttl: packet.get_hop_limit(),
            };
            probe_result.lock().unwrap().tcp_rst_ack_result = Some(result);
        }else if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK | pnet_packet::tcp::TcpFlags::ECE {
            let tcp_header_result: Option<TcpHeaderResult> = probe_result.lock().unwrap().tcp_header_result.clone();
            match tcp_header_result {
                Some(_) => {},
                None => {
                    probe_result.lock().unwrap().tcp_header_result = Some(header_result);
                },
            }
            let result: TcpEcnResult = TcpEcnResult{
                syn_ack_ece_response: true,
                tcp_payload_size: tcp_packet.payload().len() as u16,
                ip_id: 0,
                ip_df: false,
                ip_ttl: packet.get_hop_limit(),
            };
            probe_result.lock().unwrap().tcp_ecn_result = Some(result);
        }
    }
}

fn udp_handler_v4(packet: &pnet_packet::ipv4::Ipv4Packet, probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>) {
    let udp = pnet_packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        handle_udp_packet(udp, probe_setting, probe_result);
    }
}

fn udp_handler_v6(packet: &pnet_packet::ipv6::Ipv6Packet, probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>) {
    let udp = pnet_packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        handle_udp_packet(udp, probe_setting, probe_result);
    }
}

fn icmp_handler_v4(packet: &pnet_packet::ipv4::Ipv4Packet, _probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>) {
    let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
    if let Some(icmp) = icmp_packet {
        match icmp.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let result: IcmpEchoResult = IcmpEchoResult{
                    icmp_echo_reply: true,
                    icmp_echo_code: 0,
                    ip_id: packet.get_identification(),
                    ip_df: if packet.get_flags() >= 2 {true}else{false},
                    ip_ttl: packet.get_ttl(),
                };
                probe_result.lock().unwrap().icmp_echo_result = Some(result);   
            },
            IcmpTypes::DestinationUnreachable => {
                let icmp_unreach_packet = destination_unreachable::DestinationUnreachablePacket::new(packet.payload()).unwrap();
                let org_ip_packet = pnet_packet::ipv4::Ipv4Packet::new(&icmp_unreach_packet.payload()[..IPV4_HEADER_LEN]).unwrap();
                let org_udp_packet = pnet_packet::udp::UdpPacket::new(&icmp_unreach_packet.payload()[IPV4_HEADER_LEN..]).unwrap();
                let ip_result: IcmpUnreachableIpResult = IcmpUnreachableIpResult{
                    icmp_unreachable_reply: true,
                    icmp_unreachable_size: (packet.get_total_length() - IPV4_HEADER_LEN as u16),
                    ip_total_length: packet.get_total_length(),
                    ip_id: packet.get_identification(),
                    ip_df: if packet.get_flags() >= 2 {true}else{false},
                    ip_ttl: packet.get_ttl(),
                };
                probe_result.lock().unwrap().icmp_unreachable_ip_result = Some(ip_result);
                let org_data_resault = IcmpUnreachableOriginalDataResult {
                    udp_checksum: org_udp_packet.get_checksum(),
                    udp_header_length: (icmp_unreach_packet.payload().len() - IPV4_HEADER_LEN - org_udp_packet.payload().len()) as u16,
                    udp_payload_length: org_udp_packet.payload().len() as u16,
                    ip_checksum: org_ip_packet.get_checksum(),
                    ip_id: org_ip_packet.get_identification(),
                    ip_total_length: org_ip_packet.get_total_length(),
                    ip_df: if org_ip_packet.get_flags() >= 2 {true}else{false},
                    ip_ttl: org_ip_packet.get_ttl(),
                };
                probe_result.lock().unwrap().icmp_unreachable_data_result = Some(org_data_resault);
            },
            IcmpTypes::TimestampReply => {
                let result: IcmpTimestampResult = IcmpTimestampResult {
                    icmp_timestamp_reply: true,
                    ip_id: packet.get_identification(),
                    ip_ttl: packet.get_ttl(),
                };
                probe_result.lock().unwrap().icmp_timestamp_result = Some(result);
            },
            IcmpTypes::AddressMaskReply => {
                let result: IcmpAddressMaskResult = IcmpAddressMaskResult {
                    icmp_address_mask_reply: true,
                    ip_id: packet.get_identification(),
                    ip_ttl: packet.get_ttl(),
                };
                probe_result.lock().unwrap().icmp_address_mask_result = Some(result);
            },
            IcmpTypes::InformationReply => {
                let result: IcmpInformationResult = IcmpInformationResult {
                    icmp_information_reply: true,
                    ip_id: packet.get_identification(),
                    ip_ttl: packet.get_ttl(),
                };
                probe_result.lock().unwrap().icmp_information_result = Some(result);
            },
            _ => {},
        }
    }
}

fn icmp_handler_v6(packet: &pnet_packet::ipv6::Ipv6Packet, _probe_setting: &ProbeSetting, probe_result: &Arc<Mutex<ProbeResult>>) {
    let icmp_packet = pnet_packet::icmpv6::Icmpv6Packet::new(packet.payload());
    if let Some(icmp) = icmp_packet {
        match icmp.get_icmpv6_type() {
            Icmpv6Types::EchoReply => {
                let result: IcmpEchoResult = IcmpEchoResult{
                    icmp_echo_reply: true,
                    icmp_echo_code: 0,
                    ip_id: 0,
                    ip_df: false,
                    ip_ttl: packet.get_hop_limit(),
                };
                probe_result.lock().unwrap().icmp_echo_result = Some(result);   
            },
            Icmpv6Types::DestinationUnreachable => {
                let org_ip_packet = pnet_packet::ipv6::Ipv6Packet::new(&packet.payload()[..IPV6_HEADER_LEN]).unwrap();
                let org_udp_packet = pnet_packet::udp::UdpPacket::new(&packet.payload()[IPV6_HEADER_LEN..]).unwrap();
                let ip_result: IcmpUnreachableIpResult = IcmpUnreachableIpResult{
                    icmp_unreachable_reply: true,
                    icmp_unreachable_size: (packet.packet().len() - IPV6_HEADER_LEN) as u16,
                    ip_total_length: packet.packet().len() as u16,
                    ip_id: 0,
                    ip_df: false,
                    ip_ttl: packet.get_hop_limit(),
                };
                probe_result.lock().unwrap().icmp_unreachable_ip_result = Some(ip_result);
                let org_data_resault = IcmpUnreachableOriginalDataResult {
                    udp_checksum: org_udp_packet.get_checksum(),
                    udp_header_length: (packet.payload().len() - IPV4_HEADER_LEN - org_udp_packet.payload().len()) as u16,
                    udp_payload_length: org_udp_packet.payload().len() as u16,
                    ip_checksum: 0,
                    ip_id: 0,
                    ip_total_length: org_ip_packet.packet().len() as u16,
                    ip_df: false,
                    ip_ttl: org_ip_packet.get_hop_limit(),
                };
                probe_result.lock().unwrap().icmp_unreachable_data_result = Some(org_data_resault);
            },
            _ => {},
        }
    }
}

fn handle_udp_packet(_udp_packet: pnet_packet::udp::UdpPacket, _probe_setting: &ProbeSetting, _probe_result: &Arc<Mutex<ProbeResult>>) {
    
}
