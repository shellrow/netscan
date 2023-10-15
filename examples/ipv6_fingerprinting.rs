use default_net::Interface;
use netscan::os::{Fingerprinter, ProbeTarget};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

fn is_global_ipv6(ipv6_addr: &Ipv6Addr) -> bool {
    !(ipv6_addr.is_unspecified()
        || ipv6_addr.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ipv6_addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(ipv6_addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ipv6_addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ipv6_addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(ipv6_addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(ipv6_addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(ipv6_addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(ipv6_addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                || matches!(ipv6_addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
            ))
        // Reserved for documentation
        || ((ipv6_addr.segments()[0] == 0x2001) && (ipv6_addr.segments()[1] == 0x2) && (ipv6_addr.segments()[2] == 0))
        // Unique Local Address
        || ((ipv6_addr.segments()[0] & 0xfe00) == 0xfc00)
        // unicast address with link-local scope (`fc00::/7`)
        || ((ipv6_addr.segments()[0] & 0xffc0) == 0xfe80))
}

fn get_interface_ipv6(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv6.clone() {
        if is_global_ipv6(&ip.addr) {
            return Some(IpAddr::V6(ip.addr));
        }
    }
    return None;
}

fn main() {
    let interface = default_net::get_default_interface().unwrap();
    let src_ip: IpAddr = get_interface_ipv6(&interface).expect("Global IPv6 address not found");
    let dst_ip: IpAddr = match dns_lookup::lookup_host("example.com") {
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
                panic!("No IPv6 address found for example.com");
            }
            ip_addr
        }
        Err(e) => panic!("Error resolving host: {}", e),
    };
    let mut fingerprinter = Fingerprinter::new(src_ip).unwrap();
    fingerprinter.set_wait_time(Duration::from_millis(500));
    let probe_target: ProbeTarget = ProbeTarget {
        ip_addr: dst_ip,
        open_tcp_port: 80,
        closed_tcp_port: 22,
        open_udp_port: 123,
        closed_udp_port: 33455,
    };
    fingerprinter.set_probe_target(probe_target);
    fingerprinter.set_full_probe();
    let result = fingerprinter.probe();
    println!("{}", result.ip_addr);
    println!("{:?}", result.icmp_echo_result);
    println!("{:?}", result.icmp_timestamp_result);
    println!("{:?}", result.icmp_address_mask_result);
    println!("{:?}", result.icmp_information_result);
    println!("{:?}", result.icmp_unreachable_ip_result);
    println!("{:?}", result.tcp_syn_ack_result);
    println!("{:?}", result.tcp_rst_ack_result);
    println!("{:?}", result.tcp_ecn_result);
}
