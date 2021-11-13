#[cfg(target_family="unix")]
async fn unix_main() {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use netscan::async_io::PortScanner;
    use netscan::setting::{ScanType, Destination};
    let mut port_scanner = match PortScanner::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))) {
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8));
    //let dst: Destination = Destination::new(dst_ip, vec![22, 80, 443]);
    let dst: Destination = Destination::new_with_port_range(dst_ip, 1, 1000);
    port_scanner.add_destination(dst);
    port_scanner.set_scan_type(ScanType::TcpSynScan);
    port_scanner.set_timeout(Duration::from_millis(10000));
    port_scanner.set_wait_time(Duration::from_millis(100));
    port_scanner.run_scan().await;
    let result = port_scanner.get_scan_result();
    println!("Status: {:?}", result.scan_status);
    println!("Open Ports:");
    for port in result.ports {
        println!("{:?}", port);
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