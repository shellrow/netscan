use netscan::host::HostInfo;
use netscan::scanner::HostScanner;
use netscan::setting::ScanType;
use std::net::{IpAddr, Ipv6Addr};
use std::thread;
use std::time::Duration;

fn main() {
    let interface = default_net::get_default_interface().unwrap();
    let mut host_scanner = match HostScanner::new(IpAddr::V6(interface.ipv6[0].addr)) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    host_scanner.scan_setting.add_target(HostInfo::new_with_ip_addr(dst_ip));
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001));
    host_scanner.scan_setting.add_target(HostInfo::new_with_ip_addr(dst_ip));
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    host_scanner.scan_setting.add_target(HostInfo::new_with_ip_addr(dst_ip));
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844));
    host_scanner.scan_setting.add_target(HostInfo::new_with_ip_addr(dst_ip));
    // Set options
    host_scanner
        .scan_setting
        .set_scan_type(ScanType::IcmpPingScan);
    host_scanner
        .scan_setting
        .set_timeout(Duration::from_millis(10000));
    host_scanner
        .scan_setting
        .set_wait_time(Duration::from_millis(500));

    let rx = host_scanner.get_progress_receiver();
    // Run scan
    let handle = thread::spawn(move || host_scanner.sync_scan());
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
    println!("Fingerprints:");
    for fingerprint in result.fingerprints {
        println!("{:?}", fingerprint);
    }
    println!("Scan Time: {:?} (including wait-time)", result.scan_time);
}
