use netscan::async_io::HostScanner;
use netscan::host::HostInfo;
use netscan::setting::{ScanType};
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use ipnet::Ipv4Net;
use async_io;

fn main() {
    let interface = default_net::get_default_interface().unwrap();
    let mut host_scanner = match HostScanner::new(IpAddr::V4(interface.ipv4[0].addr)) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let net: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
    let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
    // Add scan target
    for host in hosts {
        let dst: HostInfo = HostInfo::new_with_ip_addr(IpAddr::V4(host));
        host_scanner.add_target(dst);
    }
    // Set options
    host_scanner.set_scan_type(ScanType::IcmpPingScan);
    host_scanner.set_timeout(Duration::from_millis(10000));
    host_scanner.set_wait_time(Duration::from_millis(500));
    
    let rx = host_scanner.get_progress_receiver();
    // Run scan 
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            host_scanner.scan().await
        })
    });
    // Print progress
    while let Ok(_socket_addr) = rx.lock().unwrap().recv() {
        //println!("Check: {}", socket_addr);
    }
    let result = handle.join().unwrap();
    // Print results 
    println!("Status: {:?}", result.scan_status);
    println!("UP Hosts:");
    for host in result.hosts {
        println!("{:?}", host);
    }
    println!("Scan Time: {:?} (including wait-time)", result.scan_time);
}
