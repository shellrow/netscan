use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use netscan::AsyncPortScanner;
use netscan::PortScanType;
use netscan::ScanStatus;

#[tokio::main]
async fn main() {
    let src_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let mut port_scanner = match AsyncPortScanner::new(src_ip) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    port_scanner.set_src_ip(src_ip);
    port_scanner.set_dst_ip(dst_ip);
    port_scanner.set_dst_port_range(1, 1000);
    port_scanner.run_scan().await;
    let result = port_scanner.get_scan_result();
    print!("Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Done")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!("Open Ports:");
    for port in result.ports {
        println!("{:?}", port);
    }
    println!("Scan Time: {:?}", result.scan_time);
    match port_scanner.get_scan_type() {
        PortScanType::ConnectScan => {},
        _=> {
            if port_scanner.get_wait_time() > Duration::from_millis(0) {
                println!("(Including {:?} of wait time)", port_scanner.get_wait_time());
            }
        },
    }
}