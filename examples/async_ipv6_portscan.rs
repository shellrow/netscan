use netscan::host::{Host, PortStatus};
use netscan::scan::scanner::PortScanner;
use netscan::scan::setting::{PortScanSetting, PortScanType};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let interface = netdev::get_default_interface().unwrap();
    let dst_ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    let dst: Host = Host::new(dst_ip, String::new()).with_ports(vec![22, 80, 443, 5000, 8080]);

    let scan_setting = PortScanSetting::default()
        .with_if_index(interface.index)
        .with_scan_type(PortScanType::TcpSynScan)
        .add_target(dst)
        .with_timeout(Duration::from_millis(10000))
        .with_wait_time(Duration::from_millis(500))
        .with_send_rate(Duration::from_millis(0))
        .with_async_scan(true);

    let result = PortScanner::new(scan_setting).scan_async().await;

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
    println!("Scan Time: {:?} (including wait-time)", result.scan_time);
}
