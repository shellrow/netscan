use ipnet::Ipv4Net;
use netscan::host::Host;
use netscan::scan::scanner::HostScanner;
use netscan::scan::setting::{HostScanSetting, HostScanType};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::Duration;

fn main() {
    let interface = netdev::get_default_interface().unwrap();
    let mut scan_setting: HostScanSetting = HostScanSetting::default()
    .set_if_index(interface.index)
    .set_scan_type(HostScanType::IcmpPingScan)
    .set_timeout(Duration::from_millis(10000))
    .set_wait_time(Duration::from_millis(500));
    let src_ip: Ipv4Addr = interface.ipv4[0].addr();
    let net: Ipv4Net = Ipv4Net::new(src_ip, 24).unwrap();
    let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
    let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
    // Add scan target
    for host in hosts {
        let dst: Host = Host::new(IpAddr::V4(host), String::new());
        scan_setting.add_target(dst);
    }
    let host_scanner: HostScanner = HostScanner::new(scan_setting);
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
