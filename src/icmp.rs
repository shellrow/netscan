use std::time;
use std::time::{Duration, Instant};
use std::net::IpAddr;
use pnet::packet::Packet;
use pnet::transport::icmp_packet_iter;

pub fn build_icmp_packet(icmp_packet:&mut pnet::packet::icmp::MutableIcmpPacket) {
    //let mut icmp_header = MutableIcmpPacket::new(ip_header.payload_mut()).unwrap();
    icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(pnet::packet::icmp::IcmpCode::new(0));
    icmp_packet.set_payload(&[0; 44]);
    icmp_packet.set_checksum(pnet::packet::icmp::checksum(&icmp_packet.to_immutable()));
}

pub fn build_echo_request_packet(icmp_packet:&mut pnet::packet::icmp::echo_request::MutableEchoRequestPacket){
    icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
    icmp_packet.set_sequence_number(rand::random::<u16>());
    icmp_packet.set_identifier(rand::random::<u16>());
    let icmp_check_sum = pnet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}

#[cfg(any(unix, macos))]
pub fn receive_icmp_packets(rx: &mut pnet::transport::TransportReceiver, icmp_type: pnet::packet::icmp::IcmpType, timeout: &Duration) -> Result<String, String>{
    let mut iter = icmp_packet_iter(rx);
    let start_time = Instant::now();
    loop {
        match iter.next_with_timeout(time::Duration::from_millis(100)) {
            Ok(r) => {
                if let Some((packet, addr)) = r {
                    if packet.get_icmp_type() == icmp_type {
                        match addr {
                            IpAddr::V4(ipv4_addr) =>{return Ok(ipv4_addr.to_string())},
                            IpAddr::V6(ipv6_addr) =>{return Ok(ipv6_addr.to_string())},
                        }
                    }
                }else{
                    return Err(String::from("Failed to read packet"));
                }
            },
            Err(e) => {
                return Err(format!("An error occurred while reading: {}", e));
            }
        }
        if Instant::now().duration_since(start_time) > *timeout {
            return Err(String::from("timeout"));
        }
    }
}

#[cfg(target_os = "windows")]
pub fn receive_icmp_packets(rx: &mut pnet::transport::TransportReceiver, icmp_type: pnet::packet::icmp::IcmpType, timeout: &Duration) -> Result<String, String>{
    let mut iter = icmp_packet_iter(rx);
    let start_time = Instant::now();
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                if let Some((packet, addr)) = r {
                    if packet.get_icmp_type() == icmp_type {
                        match addr {
                            IpAddr::V4(ipv4_addr) =>{return Ok(ipv4_addr.to_string())},
                            IpAddr::V6(ipv6_addr) =>{return Ok(ipv6_addr.to_string())},
                        }
                    }
                }else{
                    return Err(String::from("Failed to read packet"));
                }
            },
            Err(e) => {
                return Err(format!("An error occurred while reading: {}", e));
            }
        }
    }
    if Instant::now().duration_since(start_time) > *timeout {
        return Err(String::from("timeout"));
    }
}