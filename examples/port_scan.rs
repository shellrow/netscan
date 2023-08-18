use netscan::blocking::PortScanner;
use netscan::host::{HostInfo, PortStatus};
use netscan::setting::ScanType;
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

fn main() {
    let interface = default_net::get_default_interface().unwrap();
    let mut port_scanner = match PortScanner::new(IpAddr::V4(interface.ipv4[0].addr)) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    // Add scan target
    let dst_ip: IpAddr = match dns_lookup::lookup_host("scanme.nmap.org") {
        Ok(ips) => {
            let mut ip_addr = ips.first().unwrap().clone();
            for ip in ips {
                if ip.is_ipv4() {
                    ip_addr = ip;
                    break;
                }
            }
            ip_addr
        }
        Err(e) => panic!("Error resolving host: {}", e),
    };
    //let dst: HostInfo = HostInfo::new_with_ip_addr(dst_ip).with_ports(vec![22, 80, 443, 5000, 8080]);
    let dst: HostInfo = HostInfo::new_with_ip_addr(dst_ip).with_port_range(1, 1000);
    port_scanner.scan_setting.add_target(dst);
    // Set options
    port_scanner.scan_setting.set_scan_type(ScanType::TcpSynScan);
    port_scanner.scan_setting.set_timeout(Duration::from_millis(10000));
    port_scanner.scan_setting.set_wait_time(Duration::from_millis(500));
    //port_scanner.set_send_rate(Duration::from_millis(1));

    let rx = port_scanner.get_progress_receiver();
    // Run scan
    let handle = thread::spawn(move || port_scanner.scan());
    // Print progress
    while let Ok(_socket_addr) = rx.lock().unwrap().recv() {
        //println!("Check: {}", socket_addr);
    }
    let result = handle.join().unwrap();
    // Print results
    println!("Status: {:?}", result.scan_status);
    println!("Results:");
    for host_info in result.results {
        println!("{} {}", host_info.ip_addr, host_info.host_name);
        for port_info in host_info.ports {
            if port_info.status == PortStatus::Open {
                println!("{}: {:?}", port_info.port, port_info.status);
            }
        }
    }
    println!("Scan Time: {:?} (including wait-time)", result.scan_time);
}
