use ipnet::Ipv4Net;
use netscan::host::Host;
use netscan::scan::scanner::HostScanner;
use netscan::scan::setting::{HostScanSetting, HostScanType};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let interface = netdev::get_default_interface().unwrap();
    let mut scan_setting: HostScanSetting = HostScanSetting::default()
        .set_if_index(interface.index)
        .set_scan_type(HostScanType::IcmpPingScan)
        .set_timeout(Duration::from_millis(10000))
        .set_wait_time(Duration::from_millis(500))
        .set_async_scan(true);

    let src_ip: Ipv4Addr = interface.ipv4[0].addr();
    let net: Ipv4Net = Ipv4Net::new(src_ip, 24).unwrap();
    let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
    for host in nw_addr.hosts() {
        scan_setting.add_target(Host::new(IpAddr::V4(host), String::new()));
    }

    let result = HostScanner::new(scan_setting).scan_async().await;

    println!("Status: {:?}", result.scan_status);
    println!("UP Hosts:");
    for host in result.hosts {
        println!("{:?}", host);
    }
    println!("Scan Time: {:?} (including wait-time)", result.scan_time);
}
