use netscan::blocking::PortScanner;
use netscan::host::{HostInfo, PortStatus};
use netscan::setting::{ScanType};
use std::time::Duration;
use std::net::IpAddr;
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
            let mut ip_addr = ips.first().unwrap().clone();
            for ip in ips {
                if ip.is_ipv4() {
                    ip_addr = ip;
                    break;
                }
            }
            ip_addr
        },
        Err(e) => panic!("Error resolving host: {}", e),
    };
    let dst: HostInfo = HostInfo::new_with_ip_addr(dst_ip).with_ports(vec![22, 80, 443, 5000, 8080]);
    //let dst: HostInfo = HostInfo::new_with_ip_addr(dst_ip).with_port_range(1, 1000);
    //let dst: HostInfo = HostInfo::new_with_ip_addr(dst_ip).with_host_name("scanme.nmap.org".to_string()).with_ports(vec![22, 80, 443, 5000, 8080]);
    //let dst: HostInfo = HostInfo::new_with_host_name("scanme.nmap.org".to_string()).with_ports(vec![22, 80, 443, 5000, 8080]);
    port_scanner.add_target(dst);
    port_scanner.set_scan_type(ScanType::TcpSynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.set_wait_time(Duration::from_millis(500));
    port_scanner.set_send_rate(Duration::from_millis(1));

    let result = port_scanner.scan();
    for host_info in &result.results {
        println!("{} {}", host_info.ip_addr, host_info.host_name);
        for port_info in &host_info.ports {
            if port_info.status == PortStatus::Open {
                println!("{}: {:?}", port_info.port, port_info.status);
            }
        }
        let mut service_detector = ServiceDetector::new();
        service_detector.set_dst_ip(host_info.ip_addr);
        service_detector.set_dst_name(host_info.host_name.clone());
        service_detector.set_ports(result.get_open_ports(host_info.ip_addr));
        let service_map = service_detector.detect(Some(PortDatabase::default()));
        println!("{:?}", service_map);
    }
}
