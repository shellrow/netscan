use netscan::os::{Fingerprinter, ProbeTarget};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

fn main() {
    let interface = default_net::get_default_interface().unwrap();
    let src_ip: IpAddr = IpAddr::V6(interface.ipv6[0].addr);
    let dst_ip: IpAddr = match dns_lookup::lookup_host("cloudflare.com") {
        Ok(ips) => {
            let mut ip_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
            for ip in ips {
                if ip.is_ipv6() {
                    ip_addr = ip;
                    break;
                } else {
                    continue;
                }
            }
            if ip_addr == IpAddr::V6(Ipv6Addr::LOCALHOST) {
                panic!("No IPv6 address found for cloudflare.com");
            }
            ip_addr
        }
        Err(e) => panic!("Error resolving host: {}", e),
    };
    let mut fingerprinter = Fingerprinter::new(src_ip).unwrap();
    fingerprinter.set_wait_time(Duration::from_millis(500));
    let probe_target: ProbeTarget = ProbeTarget {
        ip_addr: dst_ip,
        open_tcp_ports: vec![22, 80],
        closed_tcp_port: 443,
        open_udp_port: 123,
        closed_udp_port: 33455,
    };
    fingerprinter.add_probe_target(probe_target);
    fingerprinter.set_full_probe();
    let results = fingerprinter.probe();
    for result in results {
        println!("{}", result.ip_addr);
        println!("{:?}", result.icmp_echo_result);
        println!("{:?}", result.icmp_timestamp_result);
        println!("{:?}", result.icmp_address_mask_result);
        println!("{:?}", result.icmp_information_result);
        println!("{:?}", result.icmp_unreachable_ip_result);
        println!("{:?}", result.tcp_syn_ack_result);
        println!("{:?}", result.tcp_rst_ack_result);
        println!("{:?}", result.tcp_ecn_result);
        for f in result.fingerprints {
            println!("{:?}", f);
        }
        println!();
    }
}
