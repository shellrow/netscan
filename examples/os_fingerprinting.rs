use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use netscan::os::{OSFingerprinter};
use netscan::os::{ProbeType, ProbeTarget};

fn main() {
    let src_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));
    //let gateway_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let mut fingerprinter = OSFingerprinter::new(src_ip).unwrap();
    //let mut fingerprinter = OSFingerprinter::new_with_gateway_ip(src_ip, gateway_ip).unwrap();
    fingerprinter.set_wait_time(Duration::from_millis(200));
    let probe_target1: ProbeTarget = ProbeTarget {
        ip_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        open_tcp_ports: vec![22,80],
        closed_tcp_port: 443,
        open_udp_port: 123,
        closed_udp_port: 33455,
    };
    let probe_target2: ProbeTarget = ProbeTarget {
        ip_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
        open_tcp_ports: vec![80,135],
        closed_tcp_port: 443,
        open_udp_port: 123,
        closed_udp_port: 33455,
    };
    let probe_target3: ProbeTarget = ProbeTarget {
        ip_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
        open_tcp_ports: vec![22,80],
        closed_tcp_port: 443,
        open_udp_port: 123,
        closed_udp_port: 33455,
    };
    let probe_target4: ProbeTarget = ProbeTarget {
        ip_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
        open_tcp_ports: vec![22,80],
        closed_tcp_port: 443,
        open_udp_port: 123,
        closed_udp_port: 33455,
    };
    fingerprinter.add_probe_target(probe_target1);
    fingerprinter.add_probe_target(probe_target2);
    fingerprinter.add_probe_target(probe_target3);
    fingerprinter.add_probe_target(probe_target4);
    fingerprinter.add_probe_type(ProbeType::IcmpEchoProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpTimestampProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpAddressMaskProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpInformationProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpUnreachableProbe);
    fingerprinter.add_probe_type(ProbeType::TcpSynAckProbe);
    fingerprinter.add_probe_type(ProbeType::TcpRstAckProbe);
    fingerprinter.add_probe_type(ProbeType::TcpEcnProbe);
    let results = fingerprinter.probe();
    for result in results {
        println!("{}", result.ip_addr);
        println!("{:?}", result.icmp_echo_result);
        println!("{:?}", result.icmp_timestamp_result);
        println!("{:?}", result.icmp_address_mask_result);
        println!("{:?}", result.icmp_information_result);
        println!("{:?}", result.icmp_unreachable_ip_result);
        println!("{:?}", result.icmp_unreachable_data_result);
        println!("{:?}", result.tcp_syn_ack_result);
        println!("{:?}", result.tcp_rst_ack_result);
        println!("{:?}", result.tcp_ecn_result);
        println!("{:?}", result.tcp_header_result);
        println!();
    }
}
