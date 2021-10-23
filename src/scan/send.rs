use std::thread;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use crate::packet::{icmp, tcp, ipv4, ethernet};
use crate::base_type::{Protocol, ScanSetting};

fn build_tcp_syn_packet(scan_setting: &ScanSetting, tmp_packet: &mut [u8], target_port: u16){
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(&mut tmp_packet[..ethernet::ETHERNET_HEADER_LEN]).unwrap();
    ethernet::build_ethernet_packet(&mut eth_header, scan_setting.src_mac, scan_setting.dst_mac, EtherTypes::Ipv4);
    // Setup IP header
    let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(&mut tmp_packet[ethernet::ETHERNET_HEADER_LEN..(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)]).unwrap();
    match scan_setting.src_ip {
        IpAddr::V4(src_ip) => {
            match scan_setting.dst_ip {
                IpAddr::V4(dst_ip) => {
                    ipv4::build_ipv4_packet(&mut ip_header, src_ip, dst_ip, IpNextHeaderProtocols::Tcp);
                },
                IpAddr::V6(_ip) => {},
            }
        },
        IpAddr::V6(_ip) => {},
    }
    // Setup TCP header
    let mut tcp_header = pnet::packet::tcp::MutableTcpPacket::new(&mut tmp_packet[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..]).unwrap();
    tcp::build_tcp_packet(&mut tcp_header, scan_setting.src_ip, scan_setting.src_port, scan_setting.dst_ip, target_port);
}

fn build_icmp_echo_packet(scan_setting: &ScanSetting, tmp_packet: &mut [u8], target_ip: IpAddr) {
    // Setup Ethernet header
    let mut eth_header = pnet::packet::ethernet::MutableEthernetPacket::new(&mut tmp_packet[..ethernet::ETHERNET_HEADER_LEN]).unwrap();
    ethernet::build_ethernet_packet(&mut eth_header, scan_setting.src_mac, scan_setting.dst_mac, EtherTypes::Ipv4);
    // Setup IP header
    let mut ip_header = pnet::packet::ipv4::MutableIpv4Packet::new(&mut tmp_packet[ethernet::ETHERNET_HEADER_LEN..(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)]).unwrap();
    match scan_setting.src_ip {
        IpAddr::V4(src_ip) => {
            match target_ip {
                IpAddr::V4(dst_ip) => {
                    ipv4::build_ipv4_packet(&mut ip_header, src_ip, dst_ip, IpNextHeaderProtocols::Icmp);
                },
                IpAddr::V6(_ip) => {},
            }
        },
        IpAddr::V6(_ip) => {},
    }
    // Setup ICMP header
    let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(&mut tmp_packet[(ethernet::ETHERNET_HEADER_LEN + ipv4::IPV4_HEADER_LEN)..]).unwrap();
    icmp::build_icmp_packet(&mut icmp_packet);
}

pub fn send_packets(tx: &mut Box<dyn pnet::datalink::DataLinkSender>, scan_setting: &ScanSetting, stop: &Arc<Mutex<bool>>) {
    match scan_setting.protocol {
        Protocol::Tcp => {
            for port in scan_setting.dst_ports.clone() {
                tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                    build_tcp_syn_packet(scan_setting, packet, port);
                });
                thread::sleep(scan_setting.send_rate);
            }
        },
        Protocol::Udp => {},
        Protocol::Icmp => {
            for ip in scan_setting.dst_ips.clone() {
                tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                    build_icmp_echo_packet(scan_setting, packet, ip);
                });
                thread::sleep(scan_setting.send_rate);
            }
        },
    }
    thread::sleep(scan_setting.wait_time);
    *stop.lock().unwrap() = true;
}
