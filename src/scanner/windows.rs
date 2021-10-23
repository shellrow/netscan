use std::time::{Duration, Instant};
use std::net::{IpAddr, ToSocketAddrs, TcpStream};
use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use crate::base_type::{PortScanType, ScanStatus, PortInfo, PortStatus, ScanSetting, ScanResult};
use crate::scan;

pub fn scan_hosts(interface: &pnet::datalink::NetworkInterface, scan_setting: &ScanSetting) ->(Vec<IpAddr>, ScanStatus)
{
    let mut result = vec![];
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let scan_status: Arc<Mutex<ScanStatus>> = Arc::new(Mutex::new(ScanStatus::Ready));
    let config = pnet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    rayon::join(|| scan::send::send_packets(&mut tx, &scan_setting, &stop),
                || scan::receive::receive_packets(&mut rx, &scan_setting, &scan_result, &stop, &scan_status)
    );
    scan_result.lock().unwrap().hosts.sort();
    for host in scan_result.lock().unwrap().hosts.iter(){
        result.push(host.clone());
    }
    return (result, *scan_status.lock().unwrap());
}

pub fn scan_ports(interface: &pnet::datalink::NetworkInterface, scan_setting: &ScanSetting) -> (Vec<PortInfo>, ScanStatus)
{
    let mut result = vec![];
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::new()));
    let scan_status: Arc<Mutex<ScanStatus>> = Arc::new(Mutex::new(ScanStatus::Ready));
    let scan_status_receive = Arc::clone(&scan_status);
    // run port scan
    match scan_setting.scan_type.unwrap() {
        PortScanType::ConnectScan => {
            run_connect_scan(scan_setting, &scan_result, &stop, &scan_status_receive);
        },
        PortScanType::SynScan => {
            run_syn_scan(interface, scan_setting, &scan_result, &stop, &scan_status_receive);
        }
    }
    for port_info in scan_result.lock().unwrap().ports.iter() {
        result.push(port_info.clone());
    }
    let scan_status = *scan_status.lock().unwrap();
    (result, scan_status)
}

fn run_syn_scan(interface: &pnet::datalink::NetworkInterface, scan_setting: &ScanSetting, port_results: &Arc<Mutex<ScanResult>>, stop: &Arc<Mutex<bool>>, scan_status: &Arc<Mutex<ScanStatus>>) {
    let config = pnet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    rayon::join(|| scan::send::send_packets(&mut tx, scan_setting, &stop),
                || scan::receive::receive_packets(&mut rx, scan_setting, &port_results, &stop, &scan_status)
    );
}

fn run_connect_scan(scan_setting: &ScanSetting, port_results: &Arc<Mutex<ScanResult>>, stop: &Arc<Mutex<bool>>, scan_status: &Arc<Mutex<ScanStatus>>){
    let ip_addr = scan_setting.dst_ip.clone();
    let ports = scan_setting.dst_ports.clone();
    let timeout = scan_setting.timeout.clone();
    let conn_timeout = Duration::from_millis(50);
    let start_time = Instant::now();
    ports.into_par_iter().for_each(|port| 
        {
            let socket_addr_str = format!("{}:{}", ip_addr, port);
            let mut addrs = socket_addr_str.to_socket_addrs().unwrap();
            if let Some(addr) = addrs.find(|x| (*x).is_ipv4()) {
                match TcpStream::connect_timeout(&addr, conn_timeout) {
                    Ok(_) => {
                        port_results.lock().unwrap().ports.push(
                            PortInfo{
                                port: port,
                                status: PortStatus::Open,
                            }
                        );
                    },
                    Err(_) => {},
                }
            }
            if Instant::now().duration_since(start_time) > timeout {
                *scan_status.lock().unwrap() = ScanStatus::Timeout;
                *stop.lock().unwrap() = true;
                return;
            }
        }
    );
    *scan_status.lock().unwrap() = ScanStatus::Done;
    *stop.lock().unwrap() = true;
}
