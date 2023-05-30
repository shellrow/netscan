use super::packet::{ethernet, icmp, ipv4, tcp, udp};
use super::packet::{ICMP_PACKET_SIZE, TCP_PACKET_SIZE, UDP_PACKET_SIZE};
use super::setting::{ProbeSetting, ProbeType};
use pnet_packet::ethernet::EtherTypes;
use pnet_packet::icmp::{IcmpType, IcmpTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;

fn build_tcp_probe_packet(
    probe_setting: &ProbeSetting,
    tmp_packet: &mut [u8],
    probe_type: ProbeType,
    option: Option<tcp::TcpProbeOption>,
) {
    // Setup Ethernet header
    let mut eth_header = pnet_packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    ethernet::build_ethernet_packet(
        &mut eth_header,
        probe_setting.src_mac,
        probe_setting.dst_mac,
        EtherTypes::Ipv4,
    );
    // Setup IP header
    let mut ip_header = pnet_packet::ipv4::MutableIpv4Packet::new(
        &mut tmp_packet[ethernet::ETHERNET_HEADER_LEN
            ..(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)],
    )
    .unwrap();
    match probe_setting.src_ip {
        IpAddr::V4(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ip) => {
                ipv4::build_ipv4_packet(&mut ip_header, src_ip, dst_ip, IpNextHeaderProtocols::Tcp);
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(_ip) => {}
    }
    // Setup TCP header
    let mut tcp_header = pnet_packet::tcp::MutableTcpPacket::new(
        &mut tmp_packet[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
    match probe_type {
        ProbeType::TcpSynAckProbe => {
            let dst_port: u16 = *probe_setting
                .probe_target
                .open_tcp_ports
                .get(0)
                .unwrap_or(&80);
            tcp::build_tcp_packet(
                &mut tcp_header,
                probe_setting.src_ip,
                probe_setting.src_port,
                probe_setting.probe_target.ip_addr,
                dst_port,
                probe_type,
                option,
            );
        }
        ProbeType::TcpRstAckProbe => {
            tcp::build_tcp_packet(
                &mut tcp_header,
                probe_setting.src_ip,
                probe_setting.src_port,
                probe_setting.probe_target.ip_addr,
                probe_setting.probe_target.closed_tcp_port,
                probe_type,
                option,
            );
        }
        ProbeType::TcpEcnProbe => {
            let dst_port: u16 = match probe_setting.probe_target.open_tcp_ports.get(1) {
                Some(dst_port) => dst_port.clone(),
                None => *probe_setting
                    .probe_target
                    .open_tcp_ports
                    .get(0)
                    .unwrap_or(&80),
            };
            tcp::build_tcp_packet(
                &mut tcp_header,
                probe_setting.src_ip,
                probe_setting.src_port,
                probe_setting.probe_target.ip_addr,
                dst_port,
                probe_type,
                option,
            );
        }
        ProbeType::TcpProbe => {
            let dst_port: u16 = *probe_setting
                .probe_target
                .open_tcp_ports
                .get(0)
                .unwrap_or(&80);
            tcp::build_tcp_packet(
                &mut tcp_header,
                probe_setting.src_ip,
                probe_setting.src_port,
                probe_setting.probe_target.ip_addr,
                dst_port,
                probe_type,
                option,
            );
        }
        _ => {
            let dst_port: u16 = *probe_setting
                .probe_target
                .open_tcp_ports
                .get(0)
                .unwrap_or(&80);
            tcp::build_tcp_packet(
                &mut tcp_header,
                probe_setting.src_ip,
                probe_setting.src_port,
                probe_setting.probe_target.ip_addr,
                dst_port,
                probe_type,
                option,
            );
        }
    }
}

fn build_icmp_probe_packet(
    probe_setting: &ProbeSetting,
    tmp_packet: &mut [u8],
    icmp_type: IcmpType,
) {
    // Setup Ethernet header
    let mut eth_header = pnet_packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    ethernet::build_ethernet_packet(
        &mut eth_header,
        probe_setting.src_mac,
        probe_setting.dst_mac,
        EtherTypes::Ipv4,
    );
    // Setup IP header
    let mut ip_header = pnet_packet::ipv4::MutableIpv4Packet::new(
        &mut tmp_packet[ethernet::ETHERNET_HEADER_LEN
            ..(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)],
    )
    .unwrap();
    match probe_setting.src_ip {
        IpAddr::V4(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ip) => {
                ipv4::build_ipv4_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Icmp,
                );
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(_ip) => {}
    }
    // Setup ICMP header
    match icmp_type {
        IcmpTypes::EchoRequest => {
            let mut icmp_packet = pnet_packet::icmp::echo_request::MutableEchoRequestPacket::new(
                &mut tmp_packet[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..],
            )
            .unwrap();
            icmp::build_icmp_echo_packet(&mut icmp_packet, IcmpTypes::EchoRequest);
        }
        _ => {
            let mut icmp_packet = pnet_packet::icmp::MutableIcmpPacket::new(
                &mut tmp_packet[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..],
            )
            .unwrap();
            icmp::build_icmp_packet(&mut icmp_packet, icmp_type);
        }
    }
}

fn build_udp_probe_packet(probe_setting: &ProbeSetting, tmp_packet: &mut [u8]) {
    // Setup Ethernet header
    let mut eth_header = pnet_packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    ethernet::build_ethernet_packet(
        &mut eth_header,
        probe_setting.src_mac,
        probe_setting.dst_mac,
        EtherTypes::Ipv4,
    );
    // Setup IP header
    let mut ip_header = pnet_packet::ipv4::MutableIpv4Packet::new(
        &mut tmp_packet[ethernet::ETHERNET_HEADER_LEN
            ..(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)],
    )
    .unwrap();
    match probe_setting.src_ip {
        IpAddr::V4(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ip) => {
                ipv4::build_ipv4_packet(&mut ip_header, src_ip, dst_ip, IpNextHeaderProtocols::Udp);
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(_ip) => {}
    }
    // Setup UDP header
    let mut udp_header = pnet_packet::udp::MutableUdpPacket::new(
        &mut tmp_packet[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..],
    )
    .unwrap();
    udp::build_udp_packet(
        &mut udp_header,
        probe_setting.src_ip,
        probe_setting.src_port,
        probe_setting.probe_target.ip_addr,
        probe_setting.probe_target.closed_udp_port,
    );
}

pub(crate) fn send_packets(
    tx: &mut Box<dyn pnet_datalink::DataLinkSender>,
    probe_setting: &ProbeSetting,
    stop: &Arc<Mutex<bool>>,
) {
    for probe_type in probe_setting.probe_types.clone() {
        match probe_type {
            ProbeType::IcmpEchoProbe => {
                tx.build_and_send(1, ICMP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                    build_icmp_probe_packet(probe_setting, packet, IcmpTypes::EchoRequest);
                });
            }
            ProbeType::IcmpTimestampProbe => {
                tx.build_and_send(1, ICMP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                    build_icmp_probe_packet(probe_setting, packet, IcmpTypes::Timestamp);
                });
            }
            ProbeType::IcmpAddressMaskProbe => {
                tx.build_and_send(1, ICMP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                    build_icmp_probe_packet(probe_setting, packet, IcmpTypes::AddressMaskRequest);
                });
            }
            ProbeType::IcmpInformationProbe => {
                tx.build_and_send(1, ICMP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                    build_icmp_probe_packet(probe_setting, packet, IcmpTypes::InformationRequest);
                });
            }
            ProbeType::IcmpUnreachableProbe => {
                tx.build_and_send(1, UDP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                    build_udp_probe_packet(probe_setting, packet);
                });
            }
            ProbeType::TcpProbe => {
                for option in tcp::TcpProbeOption::VALUES.iter().copied() {
                    tx.build_and_send(1, TCP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                        build_tcp_probe_packet(probe_setting, packet, probe_type, Some(option));
                    });
                }
            }
            ProbeType::TcpSynAckProbe => {
                tx.build_and_send(1, TCP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                    build_tcp_probe_packet(probe_setting, packet, probe_type, None);
                });
            }
            ProbeType::TcpRstAckProbe => {
                tx.build_and_send(1, TCP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                    build_tcp_probe_packet(probe_setting, packet, probe_type, None);
                });
            }
            ProbeType::TcpEcnProbe => {
                tx.build_and_send(1, TCP_PACKET_SIZE, &mut |packet: &mut [u8]| {
                    build_tcp_probe_packet(probe_setting, packet, probe_type, None);
                });
            }
        }
    }
    thread::sleep(probe_setting.wait_time);
    *stop.lock().unwrap() = true;
}
