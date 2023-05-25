use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use std::thread;
use netscan::async_io::PortScanner;
use netscan::setting::{ScanType, Destination};
use async_io;

fn main() {
    let interface = default_net::get_default_interface().unwrap();
    let mut port_scanner = match PortScanner::new(IpAddr::V4(interface.ipv4[0].addr)) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    // Add scan target
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
    //let dst: Destination = Destination::new(dst_ip, vec![22, 80, 443, 5000, 8080]);
    let dst: Destination = Destination::new_with_port_range(dst_ip, 1, 1000);
    port_scanner.add_destination(dst);
    // Set options
    port_scanner.set_scan_type(ScanType::TcpSynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.set_wait_time(Duration::from_millis(500));

    let rx = port_scanner.get_progress_receiver();
    // Run scan 
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            port_scanner.scan().await
        })
    });
    // Print progress
    while let Ok(_socket_addr) = rx.lock().unwrap().recv() {
        //println!("Check: {}", socket_addr);
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
    println!("Scan Time: {:?} (including waittime)", result.scan_time);
}
