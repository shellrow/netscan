use cross_socket::datalink::MacAddr;
use std::net::IpAddr;
use std::time::Duration;
use cross_socket::packet::tcp::TcpOption;

/// Listener thread wait time (milliseconds)
pub(crate) const LISTENER_WAIT_TIME_MILLIS: u64 = 100;

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
    pub open_tcp_port: u16,
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

#[derive(Copy, Clone, Debug)]
pub enum TcpProbeKind {
    Syn1,
    Syn2,
    Syn3,
    Syn4,
    Syn5,
    Syn6,
    Ecn,
}

impl TcpProbeKind {
    pub const VALUES: [Self; 7] = [
        Self::Syn1,
        Self::Syn2,
        Self::Syn3,
        Self::Syn4,
        Self::Syn5,
        Self::Syn6,
        Self::Ecn,
    ];
    pub fn ipv4_total_length(&self) -> u16 {
        match *self {
            TcpProbeKind::Syn1 => 60,
            TcpProbeKind::Syn2 => 60,
            TcpProbeKind::Syn3 => 60,
            TcpProbeKind::Syn4 => 56,
            TcpProbeKind::Syn5 => 60,
            TcpProbeKind::Syn6 => 56,
            TcpProbeKind::Ecn => 52,
        }
    }
    pub fn ipv6_payload_length(&self) -> u16 {
        match *self {
            TcpProbeKind::Syn1 => 40,
            TcpProbeKind::Syn2 => 40,
            TcpProbeKind::Syn3 => 40,
            TcpProbeKind::Syn4 => 36,
            TcpProbeKind::Syn5 => 40,
            TcpProbeKind::Syn6 => 36,
            TcpProbeKind::Ecn => 32,
        }
    }
    pub fn tcp_options(&self) -> Vec<TcpOption> {
        match *self {
            TcpProbeKind::Syn1 => vec![
                TcpOption::wscale(10),
                TcpOption::nop(),
                TcpOption::mss(1460),
                TcpOption::timestamp(u32::MAX, u32::MIN),
                TcpOption::sack_perm(),
            ],
            TcpProbeKind::Syn2 => vec![
                TcpOption::mss(1400),
                TcpOption::wscale(0),
                TcpOption::sack_perm(),
                TcpOption::timestamp(u32::MAX, u32::MIN),
            ],
            TcpProbeKind::Syn3 => vec![
                TcpOption::timestamp(u32::MAX, u32::MIN),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::wscale(5),
                TcpOption::nop(),
                TcpOption::mss(640),
            ],
            TcpProbeKind::Syn4 => vec![
                TcpOption::sack_perm(),
                TcpOption::timestamp(u32::MAX, u32::MIN),
                TcpOption::wscale(10),
            ],
            TcpProbeKind::Syn5 => vec![
                TcpOption::mss(536),
                TcpOption::sack_perm(),
                TcpOption::timestamp(u32::MAX, u32::MIN),
                TcpOption::wscale(10),
            ],
            TcpProbeKind::Syn6 => vec![
                TcpOption::mss(265),
                TcpOption::sack_perm(),
                TcpOption::timestamp(u32::MAX, u32::MIN),
            ],
            TcpProbeKind::Ecn => vec![
                TcpOption::wscale(10),
                TcpOption::nop(),
                TcpOption::mss(1460),
                TcpOption::sack_perm(),
                TcpOption::nop(),
                TcpOption::nop(),
            ],
        }
    }
}
