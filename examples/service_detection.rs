use netscan::host::{Host, PortStatus};
use netscan::scan::scanner::{PortScanner, ServiceDetector};
use netscan::scan::setting::{PortScanSetting, PortScanType, ServiceProbeSetting};
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

fn main() {
    // Get default interface
    let interface = netdev::get_default_interface().unwrap();
    // Add target
    let dst_ip: IpAddr = netscan::dns::lookup_host_name("scanme.nmap.org").expect("Error resolving host");
    let dst: Host = Host::new(dst_ip, String::from("scanme.nmap.org")).with_ports(vec![22, 80, 443, 5000, 8080]);
    //let dst: Host = Host::new(dst_ip, String::from("scanme.nmap.org")).with_port_range(1, 1000);
    let scan_setting = PortScanSetting::default()
        .set_if_index(interface.index)
        .set_scan_type(PortScanType::TcpSynScan)
        .add_target(dst)
        .set_timeout(Duration::from_millis(10000))
        .set_wait_time(Duration::from_millis(200));
    //.set_send_rate(Duration::from_millis(1));
    let port_scanner = PortScanner::new(scan_setting);

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
    for host_info in result.hosts {
        println!("{} {}", host_info.ip_addr, host_info.hostname);
        for port_info in &host_info.ports {
            if port_info.status == PortStatus::Open {
                println!("{}: {:?}", port_info.number, port_info.status);
            }
        }
        let probe_setting: ServiceProbeSetting = ServiceProbeSetting::default(
            host_info.ip_addr,
            "scanme.nmap.org".to_string(),
            host_info.get_open_port_numbers(),
        );
        let service_detector = ServiceDetector::new(probe_setting);
        let service_rx = service_detector.get_progress_receiver();
        let service_handle = thread::spawn(move || service_detector.run());
        // Print progress
        while let Ok(socket_addr) = service_rx.lock().unwrap().recv() {
            println!("Checked: {}", socket_addr);
        }
        let service_result = service_handle.join().unwrap();
        for (port, result) in service_result {
            println!("{}: {:?}", port, result);
        }
    }
}
