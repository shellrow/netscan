use netscan::blocking::PortScanner;
use netscan::setting::{ScanType, Destination};
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;

fn main() {
    let mut port_scanner = match PortScanner::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    // Add scan target
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8));
    //let dst: Destination = Destination::new(dst_ip, vec![22, 80, 443, 5000, 8080]);
    let dst: Destination = Destination::new_with_port_range(dst_ip, 1, 1000);
    port_scanner.add_destination(dst);
    // Multiple target hosts can be configured
    //let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    //let dst: Destination = Destination::new_with_port_range(dst_ip, 1, 1000);
    //port_scanner.add_destination(dst);
    // Set options
    port_scanner.set_scan_type(ScanType::TcpSynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.set_wait_time(Duration::from_millis(100));
    //port_scanner.set_send_rate(Duration::from_millis(1)); 
    let rx = port_scanner.get_progress_receiver();
    // Run scan 
    let handle = thread::spawn(move|| {
        port_scanner.scan()
    });
    // Print progress
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        println!("Check: {}", socket_addr);
    }
    let result = handle.join().unwrap();
    // Print results 
    println!("Status: {:?}", result.scan_status);
    println!("Results:");
    for (ip, ports) in result.result_map {
        println!("{}", ip);
        for port in ports {
            println!("{:?}", port);
        }
    }
    println!("Scan Time: {:?}", result.scan_time);
}
