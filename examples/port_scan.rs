extern crate netscan;
use netscan::PortScanner;
use netscan::PortScanType;
use netscan::ScanStatus;
use std::time::Duration;

fn main() {
    let mut port_scanner = match PortScanner::new(None, None) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    port_scanner.set_target_ipaddr("192.168.1.92");
    port_scanner.set_range(1, 1000);
    for i in 1..1000{
        port_scanner.add_target_port(i);
    }
    port_scanner.set_scan_type(PortScanType::SynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.run_scan();
    let result = port_scanner.get_result();
    print!("Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Normal end")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!("Open Ports:");
    for port in result.open_ports {
        println!("{}", port);
    }
    println!("Scan Time: {:?}", result.scan_time);
}
