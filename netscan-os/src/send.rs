use super::packet;
use super::setting::{ProbeSetting, ProbeType};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::icmp::{IcmpType, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Type, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::IpAddr;

fn build_tcp_probe_packet(
    probe_setting: &ProbeSetting,
    tmp_packet: &mut [u8],
    probe_type: ProbeType,
    option: Option<packet::tcp::TcpProbeOption>,
) {
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    packet::ethernet::build_ethernet_packet(
        &mut eth_header,
        probe_setting.src_mac,
        probe_setting.dst_mac,
        if probe_setting.src_ip.is_ipv4() {
            EtherTypes::Ipv4
        } else {
            EtherTypes::Ipv6
        },
    );
    // Setup IP header
    match probe_setting.src_ip {
        IpAddr::V4(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ip) => {
                let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(
                    &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
                        ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)],
                )
                .unwrap();
                packet::ipv4::build_ipv4_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Tcp,
                );
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(_ip) => {}
            IpAddr::V6(dst_ip) => {
                let mut ip_header = pnet::packet::ipv6::MutableIpv6Packet::new(
                    &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
                        ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)],
                )
                .unwrap();
                packet::ipv6::build_ipv6_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Tcp,
                );
            }
        }
    }
    // Setup TCP header
    let mut tcp_header = if probe_setting.src_ip.is_ipv4() {
        pnet::packet::tcp::MutableTcpPacket::new(
            &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
        )
        .unwrap()
    } else {
        pnet::packet::tcp::MutableTcpPacket::new(
            &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)..],
        )
        .unwrap()
    };
    match probe_type {
        ProbeType::TcpSynAckProbe => {
            let dst_port: u16 = *probe_setting
                .probe_target
                .open_tcp_ports
                .get(0)
                .unwrap_or(&80);
            packet::tcp::build_tcp_packet(
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
            packet::tcp::build_tcp_packet(
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
            packet::tcp::build_tcp_packet(
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
            packet::tcp::build_tcp_packet(
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
            packet::tcp::build_tcp_packet(
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
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    packet::ethernet::build_ethernet_packet(
        &mut eth_header,
        probe_setting.src_mac,
        probe_setting.dst_mac,
        EtherTypes::Ipv4,
    );
    // Setup IP header
    match probe_setting.src_ip {
        IpAddr::V4(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ip) => {
                let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(
                    &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
                        ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)],
                )
                .unwrap();
                packet::ipv4::build_ipv4_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Icmp,
                );
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(_ip) =>  {}
    }
    // Setup ICMP header
    match icmp_type {
        IcmpTypes::EchoRequest => {
            match probe_setting.src_ip {
                IpAddr::V4(_ip) => {
                    let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(
                        &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
                    )
                    .unwrap();
                    packet::icmp::build_icmp_echo_packet(&mut icmp_packet, IcmpTypes::EchoRequest);
                }
                IpAddr::V6(_ip) => {}
            }
        }
        _ => {
            match probe_setting.src_ip {
                IpAddr::V4(_ip) => {
                    let mut icmp_packet = pnet::packet::icmp::MutableIcmpPacket::new(
                        &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
                    )
                    .unwrap();
                    packet::icmp::build_icmp_packet(&mut icmp_packet, icmp_type);
                }
                IpAddr::V6(_ip) => {}
            }
        }
    }
}

fn build_icmpv6_probe_packet(
    probe_setting: &ProbeSetting,
    tmp_packet: &mut [u8],
    icmp_type: Icmpv6Type,
) {
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    packet::ethernet::build_ethernet_packet(
        &mut eth_header,
        probe_setting.src_mac,
        probe_setting.dst_mac,
        EtherTypes::Ipv6,
    );
    // Setup IP header
    match probe_setting.src_ip {
        IpAddr::V4(_ip) => {},
        IpAddr::V6(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(_ip) => {}
            IpAddr::V6(dst_ip) => {
                let mut ip_header = pnet::packet::ipv6::MutableIpv6Packet::new(
                    &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
                        ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)],
                )
                .unwrap();
                packet::ipv6::build_ipv6_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Icmpv6,
                );
            }
        }
    }
    // Setup ICMP header
    match icmp_type {
        Icmpv6Types::EchoRequest => {
            match probe_setting.src_ip {
                IpAddr::V4(_ip) => {},
                IpAddr::V6(src_ipv6) => match probe_setting.probe_target.ip_addr {
                    IpAddr::V4(_ip) => {},
                    IpAddr::V6(dst_ipv6) => {
                        let mut icmp_packet = pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::new(
                            &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)..],
                        )
                        .unwrap();
                        packet::icmpv6::build_icmpv6_echo_packet(&mut icmp_packet, src_ipv6, dst_ipv6);
                    }
                }
            }
        }
        _ => {
            match probe_setting.src_ip {
                IpAddr::V4(_ip) => {},
                IpAddr::V6(src_ipv6) => match probe_setting.probe_target.ip_addr {
                    IpAddr::V4(_ip) => {},
                    IpAddr::V6(dst_ipv6) => {
                        let mut icmp_packet = pnet::packet::icmpv6::MutableIcmpv6Packet::new(
                            &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)..],
                        )
                        .unwrap();
                        packet::icmpv6::build_icmpv6_packet(&mut icmp_packet, src_ipv6, dst_ipv6, icmp_type);
                    }
                }
            }
        }
    }
}

fn build_udp_probe_packet(probe_setting: &ProbeSetting, tmp_packet: &mut [u8]) {
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(
        &mut tmp_packet[..packet::ethernet::ETHERNET_HEADER_LEN],
    )
    .unwrap();
    packet::ethernet::build_ethernet_packet(
        &mut eth_header,
        probe_setting.src_mac,
        probe_setting.dst_mac,
        if probe_setting.src_ip.is_ipv4() {
            EtherTypes::Ipv4
        } else {
            EtherTypes::Ipv6
        },
    );
    // Setup IP header
    match probe_setting.src_ip {
        IpAddr::V4(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ip) => {
                let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(
                    &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
                        ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)],
                )
                .unwrap();
                packet::ipv4::build_ipv4_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Udp,
                );
            }
            IpAddr::V6(_ip) => {}
        },
        IpAddr::V6(src_ip) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(_ip) => {}
            IpAddr::V6(dst_ip) => {
                let mut ip_header = pnet::packet::ipv6::MutableIpv6Packet::new(
                    &mut tmp_packet[packet::ethernet::ETHERNET_HEADER_LEN
                        ..(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)],
                )
                .unwrap();
                packet::ipv6::build_ipv6_packet(
                    &mut ip_header,
                    src_ip,
                    dst_ip,
                    IpNextHeaderProtocols::Udp,
                );
            }
        }
    }
    // Setup UDP header
    match probe_setting.src_ip {
        IpAddr::V4(_ip) => {
            let mut udp_header = pnet::packet::udp::MutableUdpPacket::new(
                &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN)..],
            )
            .unwrap();
            packet::udp::build_udp_packet(
                &mut udp_header,
                probe_setting.src_ip,
                probe_setting.src_port,
                probe_setting.probe_target.ip_addr,
                probe_setting.probe_target.closed_udp_port,
            );
        },
        IpAddr::V6(_ip) => {
            let mut udp_header = pnet::packet::udp::MutableUdpPacket::new(
                &mut tmp_packet[(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN)..],
            )
            .unwrap();
            packet::udp::build_udp_packet(
                &mut udp_header,
                probe_setting.src_ip,
                probe_setting.src_port,
                probe_setting.probe_target.ip_addr,
                probe_setting.probe_target.closed_udp_port,
            );
        }
    }
}

pub(crate) fn send_packets(
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    probe_setting: &ProbeSetting
) {
    for probe_type in probe_setting.probe_types.clone() {
        match probe_type {
            ProbeType::IcmpEchoProbe => {
                if probe_setting.src_ip.is_ipv4() {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::icmp::ICMPV4_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_icmp_probe_packet(probe_setting, packet, IcmpTypes::EchoRequest);
                    });
                } else {
                    let packet_size: usize =  packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + packet::icmpv6::ICMPV6_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_icmpv6_probe_packet(probe_setting, packet, Icmpv6Types::EchoRequest);
                    });
                }
            }
            ProbeType::IcmpTimestampProbe => {
                if probe_setting.src_ip.is_ipv4() {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::icmp::ICMPV4_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_icmp_probe_packet(probe_setting, packet, IcmpTypes::Timestamp);
                    });
                }
            }
            ProbeType::IcmpAddressMaskProbe => {
                if probe_setting.src_ip.is_ipv4() {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::icmp::ICMPV4_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_icmp_probe_packet(probe_setting, packet, IcmpTypes::AddressMaskRequest);
                    });
                }
            }
            ProbeType::IcmpInformationProbe => {
                if probe_setting.src_ip.is_ipv4() {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::icmp::ICMPV4_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_icmp_probe_packet(probe_setting, packet, IcmpTypes::InformationRequest);
                    });
                }
            }
            ProbeType::IcmpUnreachableProbe => {
                let packet_size: usize = match probe_setting.src_ip {
                    IpAddr::V4(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv4::IPV4_HEADER_LEN
                        + packet::udp::UDP_HEADER_LEN,
                    IpAddr::V6(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv6::IPV6_HEADER_LEN
                        + packet::udp::UDP_HEADER_LEN,
                };
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_udp_probe_packet(probe_setting, packet);
                });
            }
            ProbeType::TcpProbe => {
                let packet_size: usize = match probe_setting.src_ip {
                    IpAddr::V4(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv4::IPV4_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN,
                    IpAddr::V6(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv6::IPV6_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN,
                };
                for option in packet::tcp::TcpProbeOption::VALUES.iter().copied() {
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_tcp_probe_packet(probe_setting, packet, probe_type, Some(option));
                    });
                }
            }
            ProbeType::TcpSynAckProbe => {
                let packet_size: usize = match probe_setting.src_ip {
                    IpAddr::V4(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv4::IPV4_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN,
                    IpAddr::V6(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv6::IPV6_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN,
                };
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_tcp_probe_packet(probe_setting, packet, probe_type, None);
                });
            }
            ProbeType::TcpRstAckProbe => {
                let packet_size: usize = match probe_setting.src_ip {
                    IpAddr::V4(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv4::IPV4_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN,
                    IpAddr::V6(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv6::IPV6_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN,
                };
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_tcp_probe_packet(probe_setting, packet, probe_type, None);
                });
            }
            ProbeType::TcpEcnProbe => {
                let packet_size: usize = match probe_setting.src_ip {
                    IpAddr::V4(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv4::IPV4_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN,
                    IpAddr::V6(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv6::IPV6_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN,
                };
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_tcp_probe_packet(probe_setting, packet, probe_type, None);
                });
            }
        }
    }
}
