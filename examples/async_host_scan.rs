#[cfg(target_family="unix")]
async fn unix_main() {
    use netscan::HostScanner;
    use netscan::setting::{ScanType, Destination};
    use std::time::Duration;
    use std::net::{IpAddr, Ipv4Addr};
    use ipnet::Ipv4Net;
    let mut host_scanner = match HostScanner::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let net: Ipv4Net = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
    let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
    for host in hosts {
        let dst: Destination = Destination::new(IpAddr::V4(host), vec![]);
        host_scanner.add_destination(dst);
    }
    host_scanner.set_scan_type(ScanType::IcmpPingScan);
    host_scanner.set_timeout(Duration::from_millis(10000));
    host_scanner.set_wait_time(Duration::from_millis(100));
    host_scanner.run_scan().await;
    let result = host_scanner.get_scan_result();
    println!("Status: {:?}", result.scan_status);
    println!("UP Hosts:");
    for host in result.hosts {
        println!("{:?}", host);
    }
    println!("Scan Time: {:?}", result.scan_time);
}

#[tokio::main]
async fn main() {
    #[cfg(target_family="unix")]
    {
        unix_main().await;
    }

    #[cfg(target_family="windows")]
    {
        println!("Windows is not yet supported.");
    }
}
