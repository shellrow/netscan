use netscan::host::{Host, PortStatus};
use netscan::scan::scanner::PortScanner;
use netscan::scan::setting::{PortScanSetting, PortScanType};
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

fn main() {
    let interface = netdev::get_default_interface().unwrap();
    // Add scan target
    let dst_ip: IpAddr = netscan::dns::lookup_host_name("scanme.nmap.org").expect("Error resolving host");
    let dst: Host = Host::new(dst_ip, String::new()).with_ports(vec![22, 80, 443, 5000, 8080]);
    let scan_setting = PortScanSetting::default()
        .set_if_index(interface.index)
        .set_scan_type(PortScanType::TcpSynScan)
        .add_target(dst)
        .set_timeout(Duration::from_millis(10000))
        .set_wait_time(Duration::from_millis(500))
        .set_send_rate(Duration::from_millis(0));
    let port_scanner = PortScanner::new(scan_setting);

    let rx = port_scanner.get_progress_receiver();
    // Run scan
    let handle = thread::spawn(move || { port_scanner.scan()});
    // Print progress
    while let Ok(_socket_addr) = rx.lock().unwrap().recv() {
        //println!("Check: {}", socket_addr);
    }
    let result = handle.join().unwrap();
    // Print results
    println!("Status: {:?}", result.scan_status);
    println!("Results:");
    for host_info in result.hosts {
        println!("{} {}", host_info.ip_addr, host_info.hostname);
        for port_info in host_info.ports {
            if port_info.status == PortStatus::Open {
                println!("{}: {:?}", port_info.number, port_info.status);
            }
        }
    }
    println!("Fingerprints:");
    for fingerprint in result.fingerprints {
        println!("{:?}", fingerprint);
    }
    println!("Scan Time: {:?} (including wait-time)", result.scan_time);
}
