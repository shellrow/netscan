use netscan::host::Host;
use netscan::scan::scanner::HostScanner;
use netscan::scan::setting::{HostScanSetting, HostScanType};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let interface = netdev::get_default_interface().unwrap();
    let mut scan_setting: HostScanSetting = HostScanSetting::default()
        .with_if_index(interface.index)
        .with_scan_type(HostScanType::IcmpPingScan)
        .with_timeout(Duration::from_millis(10000))
        .with_wait_time(Duration::from_millis(500))
        .with_async_scan(true);

    let targets = [
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
    ];
    for dst_ip in targets {
        scan_setting.add_target(Host::new(dst_ip, String::new()));
    }

    let result = HostScanner::new(scan_setting).scan_async().await;

    println!("Status: {:?}", result.scan_status);
    println!("UP Hosts:");
    for host in result.hosts {
        println!("{:?}", host);
    }
    println!("Scan Time: {:?} (including wait-time)", result.scan_time);
}
