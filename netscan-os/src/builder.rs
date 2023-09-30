use std::net::{IpAddr, SocketAddr};

use cross_socket::packet::ethernet::EtherType;
use cross_socket::packet::icmp::IcmpPacketBuilder;
use cross_socket::packet::icmpv6::Icmpv6PacketBuilder;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::ipv4::Ipv4PacketBuilder;
use cross_socket::packet::ipv6::Ipv6PacketBuilder;
use cross_socket::packet::tcp::{TcpPacketBuilder, TcpFlag, TcpOption};
use cross_socket::packet::{builder::PacketBuilder, ethernet::EthernetPacketBuilder};
use cross_socket::packet::udp::UDP_BASE_DST_PORT;
use super::setting::{ProbeSetting, ProbeType, TcpProbeKind};

pub(crate) fn build_tcp_probe_packet(probe_setting: &ProbeSetting, probe_type: ProbeType, tcp_probe_kind: Option<TcpProbeKind>) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: probe_setting.src_mac.clone(),
        dst_mac: probe_setting.dst_mac.clone(),
        ether_type: if probe_setting.src_ip.is_ipv4() {
            EtherType::Ipv4
        } else {
            EtherType::Ipv6
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    match probe_setting.src_ip {
        IpAddr::V4(src_ipv4) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ipv4) => {
                let mut ipv4_packet_builder = Ipv4PacketBuilder::new(
                    src_ipv4,
                    dst_ipv4,
                    IpNextLevelProtocol::Tcp,
                );
                match probe_type {
                    ProbeType::TcpProbe => {
                        if let Some(probe_kind) = tcp_probe_kind {
                            ipv4_packet_builder.total_length = Some(probe_kind.ipv4_total_length());
                        }
                    },
                    _ => {
                        ipv4_packet_builder.total_length = Some(64);
                    },
                }
                packet_builder.set_ipv4(ipv4_packet_builder);
            },
            IpAddr::V6(_) => {},
        },
        IpAddr::V6(src_ipv6) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(_) => {},
            IpAddr::V6(dst_ipv6) => {
                let mut ipv6_packet_builder = Ipv6PacketBuilder::new(
                    src_ipv6,
                    dst_ipv6,
                    IpNextLevelProtocol::Tcp,
                );
                match probe_type {
                    ProbeType::TcpProbe => {
                        if let Some(probe_kind) = tcp_probe_kind {
                            ipv6_packet_builder.payload_length = Some(probe_kind.ipv6_payload_length());
                        }
                    },
                    _ => {
                        ipv6_packet_builder.payload_length = Some(44);
                    },
                }
                packet_builder.set_ipv6(ipv6_packet_builder);
            },
        },
    }
    let mut tcp_packet_builder = TcpPacketBuilder::new(
        SocketAddr::new(probe_setting.src_ip, probe_setting.src_port),
        SocketAddr::new(probe_setting.probe_target.ip_addr, probe_setting.probe_target.open_tcp_port),
    );
    tcp_packet_builder.window = 65535;
    tcp_packet_builder.options = vec![
                TcpOption::mss(1460),
                TcpOption::nop(),
                TcpOption::wscale(6),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::timestamp(u32::MAX, u32::MIN),
                TcpOption::sack_perm(),
            ];
    match probe_type {
        ProbeType::TcpSynAckProbe => {
            tcp_packet_builder.flags = vec![TcpFlag::Syn];
        },
        ProbeType::TcpRstAckProbe => {
            tcp_packet_builder.dst_port = probe_setting.probe_target.closed_tcp_port; 
            tcp_packet_builder.flags = vec![TcpFlag::Syn];
        },
        ProbeType::TcpEcnProbe => {
            tcp_packet_builder.flags = vec![TcpFlag::Cwr, TcpFlag::Ece, TcpFlag::Syn];
        },
        ProbeType::TcpProbe => {
            if let Some(probe_kind) = tcp_probe_kind {
                match probe_kind {
                    TcpProbeKind::Ecn => {
                        tcp_packet_builder.flags = vec![TcpFlag::Cwr, TcpFlag::Ece, TcpFlag::Syn];
                    },
                    _ => {
                        tcp_packet_builder.flags = vec![TcpFlag::Syn];
                    },
                }
                tcp_packet_builder.options = probe_kind.tcp_options();
            }
        },
        _ => {
            tcp_packet_builder.flags = vec![TcpFlag::Syn];
        },
    }
    packet_builder.set_tcp(tcp_packet_builder);
    packet_builder.packet()
}

pub(crate) fn build_tcp_control_packet(probe_setting: &ProbeSetting, tcp_flags: Vec<TcpFlag>) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: probe_setting.src_mac.clone(),
        dst_mac: probe_setting.dst_mac.clone(),
        ether_type: if probe_setting.src_ip.is_ipv4() {
            EtherType::Ipv4
        } else {
            EtherType::Ipv6
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    match probe_setting.src_ip {
        IpAddr::V4(src_ipv4) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ipv4) => {
                let ipv4_packet_builder = Ipv4PacketBuilder::new(
                    src_ipv4,
                    dst_ipv4,
                    IpNextLevelProtocol::Tcp,
                );
                packet_builder.set_ipv4(ipv4_packet_builder);
            },
            IpAddr::V6(_) => {},
        },
        IpAddr::V6(src_ipv6) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(_) => {},
            IpAddr::V6(dst_ipv6) => {
                let ipv6_packet_builder = Ipv6PacketBuilder::new(
                    src_ipv6,
                    dst_ipv6,
                    IpNextLevelProtocol::Tcp,
                );
                packet_builder.set_ipv6(ipv6_packet_builder);
            },
        },
    }
    let mut tcp_packet_builder = TcpPacketBuilder::new(
        SocketAddr::new(probe_setting.src_ip, probe_setting.src_port),
        SocketAddr::new(probe_setting.probe_target.ip_addr, probe_setting.probe_target.open_tcp_port),
    );
    tcp_packet_builder.window = 65535;
    tcp_packet_builder.flags = tcp_flags;
    packet_builder.set_tcp(tcp_packet_builder);
    packet_builder.packet()
}

pub(crate) fn build_udp_probe_packet(probe_setting: &ProbeSetting) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: probe_setting.src_mac.clone(),
        dst_mac: probe_setting.dst_mac.clone(),
        ether_type: if probe_setting.src_ip.is_ipv4() {
            EtherType::Ipv4
        } else {
            EtherType::Ipv6
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    match probe_setting.src_ip {
        IpAddr::V4(src_ipv4) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ipv4) => {
                let ipv4_packet_builder = Ipv4PacketBuilder::new(
                    src_ipv4,
                    dst_ipv4,
                    IpNextLevelProtocol::Udp,
                );
                packet_builder.set_ipv4(ipv4_packet_builder);
            },
            IpAddr::V6(_) => {},
        },
        IpAddr::V6(src_ipv6) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(_) => {},
            IpAddr::V6(dst_ipv6) => {
                let ipv6_packet_builder = Ipv6PacketBuilder::new(
                    src_ipv6,
                    dst_ipv6,
                    IpNextLevelProtocol::Udp,
                );
                packet_builder.set_ipv6(ipv6_packet_builder);
            },
        },
    }
    let udp_packet_builder = cross_socket::packet::udp::UdpPacketBuilder::new(
        SocketAddr::new(probe_setting.src_ip, probe_setting.src_port),
        SocketAddr::new(probe_setting.probe_target.ip_addr, UDP_BASE_DST_PORT),
    );
    packet_builder.set_udp(udp_packet_builder);
    packet_builder.packet()
}

pub(crate) fn build_icmp_probe_packet(probe_setting: &ProbeSetting, probe_type: ProbeType) -> Vec<u8> {
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: probe_setting.src_mac.clone(),
        dst_mac: probe_setting.dst_mac.clone(),
        ether_type: if probe_setting.src_ip.is_ipv4() {
            EtherType::Ipv4
        } else {
            EtherType::Ipv6
        },
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    match probe_setting.src_ip {
        IpAddr::V4(src_ipv4) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(dst_ipv4) => {
                let ipv4_packet_builder = Ipv4PacketBuilder::new(
                    src_ipv4,
                    dst_ipv4,
                    IpNextLevelProtocol::Icmp,
                );
                packet_builder.set_ipv4(ipv4_packet_builder);
                let mut icmp_packet_builder = IcmpPacketBuilder::new(
                    src_ipv4,
                    dst_ipv4,
                );
                match probe_type {
                    ProbeType::IcmpEchoProbe => {
                        icmp_packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::EchoRequest;
                    },
                    ProbeType::IcmpTimestampProbe => {
                        icmp_packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::TimestampRequest;
                    },
                    ProbeType::IcmpAddressMaskProbe => {
                        icmp_packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::AddressMaskRequest;
                    },
                    ProbeType::IcmpInformationProbe => {
                        icmp_packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::InformationRequest;
                    },
                    _ => {
                        icmp_packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::EchoRequest;
                    },
                }
                
                packet_builder.set_icmp(icmp_packet_builder);
            },
            IpAddr::V6(_) => {},
        },
        IpAddr::V6(src_ipv6) => match probe_setting.probe_target.ip_addr {
            IpAddr::V4(_) => {},
            IpAddr::V6(dst_ipv6) => {
                let ipv6_packet_builder = Ipv6PacketBuilder::new(
                    src_ipv6,
                    dst_ipv6,
                    IpNextLevelProtocol::Icmpv6,
                );
                packet_builder.set_ipv6(ipv6_packet_builder);
                let mut icmpv6_packet_builder = Icmpv6PacketBuilder::new(src_ipv6, dst_ipv6);
                // On ICMPv6, Only EchoRequest is available.
                match probe_type {
                    ProbeType::IcmpEchoProbe => {
                        icmpv6_packet_builder.icmpv6_type = cross_socket::packet::icmpv6::Icmpv6Type::EchoRequest;
                    },
                    _ => {
                        icmpv6_packet_builder.icmpv6_type = cross_socket::packet::icmpv6::Icmpv6Type::EchoRequest;
                    },
                }
                packet_builder.set_icmpv6(icmpv6_packet_builder);
            },
        },
    }
    packet_builder.packet()
}
