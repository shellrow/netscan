use pnet::datalink::MacAddr;
use std::net::IpAddr;
use std::time::Duration;

/// Probes for fingerprinting
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProbeType {
    IcmpEchoProbe,
    IcmpTimestampProbe,
    IcmpAddressMaskProbe,
    IcmpInformationProbe,
    IcmpUnreachableProbe,
    TcpProbe,
    TcpSynAckProbe,
    TcpRstAckProbe,
    TcpEcnProbe,
}

/// TCP Options
#[derive(Clone, Copy, Debug)]
pub enum TcpOptionKind {
    Eol,
    Nop,
    Mss,
    Wscale,
    SackParmitted,
    Sack,
    Timestamp,
}

impl TcpOptionKind {
    pub fn number(&self) -> u8 {
        match *self {
            TcpOptionKind::Eol => 0,
            TcpOptionKind::Nop => 1,
            TcpOptionKind::Mss => 2,
            TcpOptionKind::Wscale => 3,
            TcpOptionKind::SackParmitted => 4,
            TcpOptionKind::Sack => 5,
            TcpOptionKind::Timestamp => 8,
        }
    }
    pub fn name(&self) -> String {
        match *self {
            TcpOptionKind::Eol => String::from("EOL"),
            TcpOptionKind::Nop => String::from("NOP"),
            TcpOptionKind::Mss => String::from("MSS"),
            TcpOptionKind::Wscale => String::from("WSCALE"),
            TcpOptionKind::SackParmitted => String::from("SACK_PERMITTED"),
            TcpOptionKind::Sack => String::from("SACK"),
            TcpOptionKind::Timestamp => String::from("TIMESTAMPS"),
        }
    }
}

/// Target host and required port information
#[derive(Clone, Debug)]
pub struct ProbeTarget {
    pub ip_addr: IpAddr,
    pub open_tcp_ports: Vec<u16>,
    pub closed_tcp_port: u16,
    pub open_udp_port: u16,
    pub closed_udp_port: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct ProbeSetting {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub probe_target: ProbeTarget,
    pub probe_types: Vec<ProbeType>,
    pub timeout: Duration,
    pub wait_time: Duration,
    #[allow(dead_code)]
    pub send_rate: Duration,
}
