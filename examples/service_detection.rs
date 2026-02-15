use netscan::host::{Host, PortStatus};
use netscan::scan::scanner::{PortScanner, ServiceDetector};
use netscan::scan::setting::{PortScanSetting, PortScanType, ServiceProbeSetting};
use std::net::IpAddr;
use std::time::Duration;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let interface = netdev::get_default_interface().unwrap();
    let dst_ip: IpAddr = netscan::dns::lookup_host_name_async("scanme.nmap.org".to_string())
        .await
        .expect("Error resolving host");
    let dst: Host = Host::new(dst_ip, String::from("scanme.nmap.org"))
        .with_ports(vec![22, 80, 443, 5000, 8080]);

    let scan_setting = PortScanSetting::default()
        .with_if_index(interface.index)
        .with_scan_type(PortScanType::TcpSynScan)
        .add_target(dst)
        .with_timeout(Duration::from_millis(10000))
        .with_wait_time(Duration::from_millis(200))
        .with_async_scan(true);

    let scan_result = PortScanner::new(scan_setting).scan_async().await;
    println!("Status: {:?}", scan_result.scan_status);

    for host_info in scan_result.hosts {
        println!("{} {}", host_info.ip_addr, host_info.hostname);
        for port_info in &host_info.ports {
            if port_info.status == PortStatus::Open {
                println!("{}: {:?}", port_info.number, port_info.status);
            }
        }

        let probe_setting = ServiceProbeSetting::default(
            host_info.ip_addr,
            "scanme.nmap.org".to_string(),
            host_info.get_open_port_numbers(),
        );
        let service_result = ServiceDetector::new(probe_setting).run_async().await;
        for (port, result) in service_result {
            println!("{}: {:?}", port, result);
        }
    }
}
