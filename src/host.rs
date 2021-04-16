use crate::icmp;
use crate::status::ScanStatus;
use std::{thread, time};
use std::time::{Duration, Instant};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::icmp_packet_iter;

pub struct HostScanOptions {
    pub target_hosts: Vec<IpAddr>,
    pub timeout: Duration,
    pub wait_time: Duration,
}

pub fn scan_hosts(scan_options: &HostScanOptions) ->(Vec<String>, ScanStatus)
{
    let mut result = vec![];
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let up_hosts:Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(vec![]));
    let scan_status: Arc<Mutex<ScanStatus>> = Arc::new(Mutex::new(ScanStatus::Ready));
    let protocol = Layer4(Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match pnet::transport::transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("Error happened {}", e),
    };
    rayon::join(|| send_icmp_packet(&mut tx, &scan_options, &stop),
                || receive_packets(&mut rx, &scan_options, &stop, &up_hosts, &scan_status)
    );
    up_hosts.lock().unwrap().sort();
    for host in up_hosts.lock().unwrap().iter(){
        result.push(host.to_string());
    }
    return (result, *scan_status.lock().unwrap());
}

fn send_icmp_packet(tx: &mut pnet::transport::TransportSender, scan_options: &HostScanOptions, stop: &Arc<Mutex<bool>>){
    for host in &scan_options.target_hosts{
        thread::sleep(time::Duration::from_millis(1));
        let mut buf = vec![0; 16];
        let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut buf[..]).unwrap();
        icmp::build_icmp_packet(&mut icmp_packet);
        let _result = tx.send_to(icmp_packet, *host);
    }
    thread::sleep(scan_options.wait_time);
    *stop.lock().unwrap() = true;
}

#[cfg(any(unix, macos))]
fn receive_packets(
    rx: &mut pnet::transport::TransportReceiver, 
    scan_options: &HostScanOptions,
    stop: &Arc<Mutex<bool>>, 
    up_hosts: &Arc<Mutex<Vec<IpAddr>>>, 
    scan_status: &Arc<Mutex<ScanStatus>>){
    let mut iter = icmp_packet_iter(rx);
    let start_time = Instant::now();
    loop {
        match iter.next_with_timeout(time::Duration::from_millis(100)) {
            Ok(r) => {
                if let Some((_packet, addr)) = r {
                    if scan_options.target_hosts.contains(&addr) && !up_hosts.lock().unwrap().contains(&addr) {
                        up_hosts.lock().unwrap().push(addr);
                    }
                }else{
                    error!("Failed to read packet");
                }
            },
            Err(e) => {
                error!("An error occurred while reading: {}", e);
            }
        }
        if *stop.lock().unwrap(){
            *scan_status.lock().unwrap() = ScanStatus::Done;
            break;
        }
        if Instant::now().duration_since(start_time) > scan_options.timeout {
            *scan_status.lock().unwrap() = ScanStatus::Timeout;
            break;
        }
    }
}

#[cfg(target_os = "windows")]
fn receive_packets(
    rx: &mut pnet::transport::TransportReceiver, 
    scan_options: &HostScanOptions,
    stop: &Arc<Mutex<bool>>, 
    up_hosts: &Arc<Mutex<Vec<IpAddr>>>, 
    scan_status: &Arc<Mutex<ScanStatus>>){
    let mut iter = icmp_packet_iter(rx);
    let start_time = Instant::now();
    loop {
        match iter.next() {
            Ok((_packet, addr)) => {
                if scan_options.target_hosts.contains(&addr) && !up_hosts.lock().unwrap().contains(&addr) {
                    up_hosts.lock().unwrap().push(addr);
                }
            },
            Err(e) => {
                error!("An error occurred while reading: {}", e);
            }
        }
        if *stop.lock().unwrap(){
            *scan_status.lock().unwrap() = ScanStatus::Done;
            break;
        }
        if Instant::now().duration_since(start_time) > scan_options.timeout {
            *scan_status.lock().unwrap() = ScanStatus::Timeout;
            break;
        }
    }
}
