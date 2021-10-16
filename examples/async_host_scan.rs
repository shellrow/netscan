#[cfg(not(target_os="windows"))]
async fn unix_main() {
    use netscan::AsyncHostScanner;
    use netscan::ScanStatus;
    use std::net::{IpAddr, Ipv4Addr};
    use ipnet::Ipv4Net;
    use std::time::Duration;
    let src_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));
    let mut host_scanner = match AsyncHostScanner::new(src_ip) {
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
    host_scanner.run_scan().await;
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

#[tokio::main]
async fn main() {
    #[cfg(not(target_os="windows"))]
    {
        unix_main().await;
    }

    #[cfg(target_os="windows")]
    {
        println!("Windows is not yet supported.");
    }
}
