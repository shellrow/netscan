use netscan::blocking::PortScanner;
use netscan::setting::{ScanType, Destination};
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use netscan::service::{ServiceDetector, PortDatabase};
use default_net;
use dns_lookup;

fn main() {
    let interface = default_net::get_default_interface().unwrap();
    let mut port_scanner = match PortScanner::new(IpAddr::V4(interface.ipv4[0].addr)) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst_ip: IpAddr = 
    match dns_lookup::lookup_host("scanme.nmap.org") {
        Ok(ips) => {
            let mut ip_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
            for ip in ips {
                if ip.is_ipv4() {
                    ip_addr = ip;
                    break;
                } else {
                    continue;
                }
            }
            ip_addr
        },
        Err(e) => panic!("Error resolving host: {}", e),
    };
    let dst: Destination = Destination::new(dst_ip, vec![22, 80, 443, 5000, 8080]);
    //let dst: Destination = Destination::new_with_port_range(dst_ip, 1, 1000);
    port_scanner.add_destination(dst);
    port_scanner.set_scan_type(ScanType::TcpSynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.set_wait_time(Duration::from_millis(500));
    port_scanner.set_send_rate(Duration::from_millis(1));
    let result = port_scanner.scan();
    println!("{:?}", result);
    for (ip, _ports) in result.result_map.clone() {
        println!("{}", ip);
        let mut service_detector = ServiceDetector::new();
        service_detector.set_dst_ip(ip);
        service_detector.set_ports(result.get_open_ports(ip));
        let service_map = service_detector.detect(Some(PortDatabase::default()));
        println!("{:?}", service_map);
    }
}
