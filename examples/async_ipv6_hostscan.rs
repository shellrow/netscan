use netscan::host::Host;
use netscan::scan::scanner::HostScanner;
use netscan::scan::setting::{HostScanSetting, HostScanType};
use std::net::{IpAddr, Ipv6Addr};
use std::thread;
use std::time::Duration;

fn main() {
    let interface = netdev::get_default_interface().unwrap();
    let mut scan_setting: HostScanSetting = HostScanSetting::default()
        .set_if_index(interface.index)
        .set_scan_type(HostScanType::IcmpPingScan)
        .set_timeout(Duration::from_millis(10000))
        .set_wait_time(Duration::from_millis(500))
        .set_async_scan(true);
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    scan_setting.add_target(Host::new(dst_ip, String::new()));
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001));
    scan_setting.add_target(Host::new(dst_ip, String::new()));
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    scan_setting.add_target(Host::new(dst_ip, String::new()));
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844));
    scan_setting.add_target(Host::new(dst_ip, String::new()));
    let host_scanner = HostScanner::new(scan_setting);
    let rx = host_scanner.get_progress_receiver();
    // Run scan
    let handle = thread::spawn(move || host_scanner.scan());
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
