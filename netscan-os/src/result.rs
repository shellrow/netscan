use std::net::IpAddr;
use super::setting::{TcpOptionKind, ProbeType};

#[derive(Clone, Copy, Debug)]
pub struct IcmpEchoResult {
    pub icmp_echo_reply: bool,
    pub icmp_echo_code: u8,
    pub ip_id: u16,
    pub ip_df: bool,
    pub ip_ttl: u8,
}

impl IcmpEchoResult {
    pub fn new() -> IcmpEchoResult {
        IcmpEchoResult {
            icmp_echo_reply: false,
            icmp_echo_code: 0,
            ip_id: 0,
            ip_df: false,
            ip_ttl: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpTimestampResult {
    pub icmp_timestamp_reply: bool,
    pub ip_id: u16,
    pub ip_ttl: u8,
}

impl IcmpTimestampResult {
    pub fn new() -> IcmpTimestampResult {
        IcmpTimestampResult {
            icmp_timestamp_reply: false,
            ip_id: 0,
            ip_ttl: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpAddressMaskResult {
    pub icmp_address_mask_reply: bool,
    pub ip_id: u16,
    pub ip_ttl: u8,
}

impl IcmpAddressMaskResult {
    pub fn new() -> IcmpAddressMaskResult {
        IcmpAddressMaskResult {
            icmp_address_mask_reply: false,
            ip_id: 0,
            ip_ttl: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpInformationResult {
    pub icmp_information_reply: bool,
    pub ip_id: u16,
    pub ip_ttl: u8,
}

impl IcmpInformationResult {
    pub fn new() -> IcmpInformationResult {
        IcmpInformationResult {
            icmp_information_reply: false,
            ip_id: 0,
            ip_ttl: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpUnreachableIpResult {
    pub icmp_unreachable_reply: bool, 
    pub icmp_unreachable_size: u16,
    pub ip_total_length: u16,
    pub ip_id: u16,
    pub ip_df: bool,
    pub ip_ttl: u8,
}

impl IcmpUnreachableIpResult {
    pub fn new() -> IcmpUnreachableIpResult {
        IcmpUnreachableIpResult {
            icmp_unreachable_reply: false, 
            icmp_unreachable_size: 0,
            ip_total_length: 0,
            ip_id: 0,
            ip_df: false,
            ip_ttl: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpUnreachableOriginalDataResult {
    pub udp_checksum: u16,
    pub udp_header_length: u16,
    pub udp_payload_length: u16,
    pub ip_checksum: u16,
    pub ip_id: u16,
    pub ip_total_length: u16,
    pub ip_df: bool,
    pub ip_ttl: u8,
}

#[derive(Clone, Debug)]
pub struct TcpHeaderResult {
    pub tcp_window_size: u16,
    pub tcp_option_order: Vec<TcpOptionKind>,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpSynAckResult {
    pub syn_ack_response: bool,
    pub ip_id: u16,
    pub ip_df: bool,
    pub ip_ttl: u8,
}

impl TcpSynAckResult {
    pub fn new() -> TcpSynAckResult {
        TcpSynAckResult {
            syn_ack_response: false,
            ip_id: 0,
            ip_df: false,
            ip_ttl: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TcpRstAckResult {
    pub rst_ack_response: bool,
    pub tcp_payload_size: u16,
    pub ip_id: u16,
    pub ip_df: bool,
    pub ip_ttl: u8,
}

impl TcpRstAckResult {
    pub fn new() -> TcpRstAckResult {
        TcpRstAckResult {
            rst_ack_response: false,
            tcp_payload_size: 0,
            ip_id: 0,
            ip_df: false,
            ip_ttl: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TcpEcnResult {
    pub syn_ack_ece_response: bool,
    pub tcp_payload_size: u16,
    pub ip_id: u16,
    pub ip_df: bool,
    pub ip_ttl: u8,
}

impl TcpEcnResult {
    pub fn new() -> TcpEcnResult {
        TcpEcnResult {
            syn_ack_ece_response: false,
            tcp_payload_size: 0,
            ip_id: 0,
            ip_df: false,
            ip_ttl: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub ip_addr: IpAddr,
    pub icmp_echo_result: Option<IcmpEchoResult>,
    pub icmp_timestamp_result: Option<IcmpTimestampResult>,
    pub icmp_address_mask_result: Option<IcmpAddressMaskResult>,
    pub icmp_information_result: Option<IcmpInformationResult>,
    pub icmp_unreachable_ip_result: Option<IcmpUnreachableIpResult>,
    pub icmp_unreachable_data_result: Option<IcmpUnreachableOriginalDataResult>,
    pub tcp_syn_ack_result: Option<TcpSynAckResult>,
    pub tcp_rst_ack_result: Option<TcpRstAckResult>,
    pub tcp_ecn_result: Option<TcpEcnResult>,
    pub tcp_header_result: Option<TcpHeaderResult>,
}

impl ProbeResult {
    pub fn new(ip_addr: IpAddr) -> ProbeResult {
        ProbeResult {
            ip_addr: ip_addr,
            icmp_echo_result: None,
            icmp_timestamp_result: None,
            icmp_address_mask_result: None,
            icmp_information_result: None,
            icmp_unreachable_ip_result: None,
            icmp_unreachable_data_result: None,
            tcp_syn_ack_result: None,
            tcp_rst_ack_result: None,
            tcp_ecn_result: None,
            tcp_header_result: None,
        }
    }
    pub fn new_with_types(ip_addr: IpAddr, types: Vec<ProbeType>) -> ProbeResult {
        ProbeResult {
            ip_addr: ip_addr,
            icmp_echo_result: if types.contains(&ProbeType::IcmpEchoProbe) {Some(IcmpEchoResult::new())}else {None},
            icmp_timestamp_result: if types.contains(&ProbeType::IcmpTimestampProbe) {Some(IcmpTimestampResult::new())}else {None},
            icmp_address_mask_result: if types.contains(&ProbeType::IcmpAddressMaskProbe) {Some(IcmpAddressMaskResult::new())}else {None},
            icmp_information_result: if types.contains(&ProbeType::IcmpInformationProbe) {Some(IcmpInformationResult::new())}else {None},
            icmp_unreachable_ip_result: if types.contains(&ProbeType::IcmpUnreachableProbe) {Some(IcmpUnreachableIpResult::new())}else {None},
            icmp_unreachable_data_result: None,
            tcp_syn_ack_result: if types.contains(&ProbeType::TcpSynAckProbe) {Some(TcpSynAckResult::new())}else {None},
            tcp_rst_ack_result: if types.contains(&ProbeType::TcpRstAckProbe) {Some(TcpRstAckResult::new())}else {None},
            tcp_ecn_result: if types.contains(&ProbeType::TcpEcnProbe) {Some(TcpEcnResult::new())}else {None},
            tcp_header_result: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ProbeStatus {
    Ready,
    Done,
    Timeout,
    Error,
}
