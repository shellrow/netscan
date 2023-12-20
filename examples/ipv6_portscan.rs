use default_net::Interface;
use netscan::host::{HostInfo, PortStatus};
use netscan::scanner::PortScanner;
use netscan::setting::ScanType;
use std::net::{IpAddr, Ipv6Addr};
use std::thread;
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
    let mut port_scanner = match PortScanner::new(src_ip) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    // Add scan target
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    let dst: HostInfo =
        HostInfo::new_with_ip_addr(dst_ip).with_ports(vec![22, 80, 443, 5000, 8080]);
    //let dst: HostInfo = HostInfo::new_with_ip_addr(dst_ip).with_port_range(1, 1000);
    port_scanner.scan_setting.add_target(dst);
    // Set options
    port_scanner
        .scan_setting
        .set_scan_type(ScanType::TcpSynScan);
    port_scanner
        .scan_setting
        .set_timeout(Duration::from_millis(10000));
    port_scanner
        .scan_setting
        .set_wait_time(Duration::from_millis(500));
    //port_scanner.set_send_rate(Duration::from_millis(1));

    let rx = port_scanner.get_progress_receiver();
    // Run scan
    let handle = thread::spawn(move || port_scanner.sync_scan());
    // Print progress
    while let Ok(_socket_addr) = rx.lock().unwrap().recv() {
        //println!("Check: {}", socket_addr);
    }
    let result = handle.join().unwrap();
    // Print results
    println!("Status: {:?}", result.scan_status);
    println!("Results:");
    for host_info in result.hosts {
        println!("{} {}", host_info.ip_addr, host_info.host_name);
        for port_info in host_info.ports {
            if port_info.status == PortStatus::Open {
                println!("{}: {:?}", port_info.port, port_info.status);
            }
        }
    }
    println!("Fingerprints:");
    for fingerprint in result.fingerprints {
        println!("{:?}", fingerprint);
    }
    println!("Scan Time: {:?} (including wait-time)", result.scan_time);
}
