use netscan::blocking::PortScanner;
use netscan::setting::{ScanType, Destination};
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use netscan::service::{ServiceDetector, PortDatabase};

fn main() {
    let mut port_scanner = match PortScanner::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8));
    //let dst: Destination = Destination::new(dst_ip, vec![22, 80, 443]);
    let dst: Destination = Destination::new_with_port_range(dst_ip, 1, 1000);
    port_scanner.add_destination(dst);
    port_scanner.set_scan_type(ScanType::TcpSynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.set_wait_time(Duration::from_millis(100));
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
