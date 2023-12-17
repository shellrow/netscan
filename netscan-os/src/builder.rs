use std::net::{IpAddr, SocketAddr};

use xenet::packet::ethernet::{EtherType, ETHERNET_HEADER_LEN};
use xenet::util::packet_builder::icmp::IcmpPacketBuilder;
use xenet::util::packet_builder::icmpv6::Icmpv6PacketBuilder;
use xenet::packet::ip::IpNextLevelProtocol;
use xenet::util::packet_builder::ipv4::Ipv4PacketBuilder;
use xenet::util::packet_builder::ipv6::Ipv6PacketBuilder;
use xenet::packet::tcp::{TcpFlags, TcpOption};
use xenet::util::packet_builder::tcp::TcpPacketBuilder;
use xenet::util::packet_builder::{builder::PacketBuilder, ethernet::EthernetPacketBuilder};
use super::setting::{ProbeSetting, ProbeType, TcpProbeKind};

const UDP_BASE_DST_PORT: u16 = 33435;

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
            tcp_packet_builder.flags = TcpFlags::SYN;
        },
        ProbeType::TcpRstAckProbe => {
            tcp_packet_builder.dst_port = probe_setting.probe_target.closed_tcp_port; 
            tcp_packet_builder.flags = TcpFlags::SYN;
        },
        ProbeType::TcpEcnProbe => {
            tcp_packet_builder.flags = TcpFlags::CWR | TcpFlags::ECE | TcpFlags::SYN;
        },
        ProbeType::TcpProbe => {
            if let Some(probe_kind) = tcp_probe_kind {
                match probe_kind {
                    TcpProbeKind::Ecn => {
                        tcp_packet_builder.flags = TcpFlags::CWR | TcpFlags::ECE | TcpFlags::SYN;
                    },
                    _ => {
                        tcp_packet_builder.flags = TcpFlags::SYN;
                    },
                }
                tcp_packet_builder.options = probe_kind.tcp_options();
            }
        },
        _ => {
            tcp_packet_builder.flags = TcpFlags::SYN;
        },
    }
    packet_builder.set_tcp(tcp_packet_builder);
    if probe_setting.tunnel {
        packet_builder.packet()[ETHERNET_HEADER_LEN..].to_vec()
    }else {
        packet_builder.packet()
    }
}

pub(crate) fn build_tcp_control_packet(probe_setting: &ProbeSetting, tcp_flags: u8) -> Vec<u8> {
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
    if probe_setting.tunnel {
        packet_builder.packet()[ETHERNET_HEADER_LEN..].to_vec()
    }else {
        packet_builder.packet()
    }
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
    let udp_packet_builder = xenet::util::packet_builder::udp::UdpPacketBuilder::new(
        SocketAddr::new(probe_setting.src_ip, probe_setting.src_port),
        SocketAddr::new(probe_setting.probe_target.ip_addr, UDP_BASE_DST_PORT),
    );
    packet_builder.set_udp(udp_packet_builder);
    if probe_setting.tunnel {
        packet_builder.packet()[ETHERNET_HEADER_LEN..].to_vec()
    }else {
        packet_builder.packet()
    }
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
                        icmp_packet_builder.icmp_type = xenet::packet::icmp::IcmpType::EchoRequest;
                    },
                    ProbeType::IcmpTimestampProbe => {
                        icmp_packet_builder.icmp_type = xenet::packet::icmp::IcmpType::TimestampRequest;
                    },
                    ProbeType::IcmpAddressMaskProbe => {
                        icmp_packet_builder.icmp_type = xenet::packet::icmp::IcmpType::AddressMaskRequest;
                    },
                    ProbeType::IcmpInformationProbe => {
                        icmp_packet_builder.icmp_type = xenet::packet::icmp::IcmpType::InformationRequest;
                    },
                    _ => {
                        icmp_packet_builder.icmp_type = xenet::packet::icmp::IcmpType::EchoRequest;
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
                        icmpv6_packet_builder.icmpv6_type = xenet::packet::icmpv6::Icmpv6Type::EchoRequest;
                    },
                    _ => {
                        icmpv6_packet_builder.icmpv6_type = xenet::packet::icmpv6::Icmpv6Type::EchoRequest;
                    },
                }
                packet_builder.set_icmpv6(icmpv6_packet_builder);
            },
        },
    }
    if probe_setting.tunnel {
        packet_builder.packet()[ETHERNET_HEADER_LEN..].to_vec()
    }else {
        packet_builder.packet()
    }
}
