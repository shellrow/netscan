extern crate netscan;
use netscan::HostScanner;
use netscan::ScanStatus;
use std::net::{IpAddr, Ipv4Addr};
use ipnet::Ipv4Net;
use std::time::Duration;

fn main(){
    let mut host_scanner = match HostScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    //Get network address
    let net: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    assert_eq!(Ok(net.network()), "192.168.1.0".parse());
    let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
    //Get host list
    let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
    for host in hosts {
        host_scanner.add_dst_ip(IpAddr::V4(host));
    }
    host_scanner.set_timeout(Duration::from_millis(10000));
    host_scanner.run_scan();
    let result = host_scanner.get_scan_result();
    print!("Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Done")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!("Up Hosts:");
    for host in result.up_hosts {
        println!("{}", host);
    }
    println!("Scan Time: {:?}", result.scan_time);
    if host_scanner.get_wait_time() > Duration::from_millis(0) {
        println!("(Including {:?} of wait time)", host_scanner.get_wait_time());
    }
}
