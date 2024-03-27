use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use netdev::interface::Interface;

pub fn get_interface_by_index(index: u32) -> Option<Interface> {
    for iface in netdev::interface::get_interfaces() {
        if iface.index == index {
            return Some(iface);
        }
    }
    return None;
}

pub fn get_local_ips(if_index: u32) -> HashSet<IpAddr> {
    let interface = get_interface_by_index(if_index).unwrap();
    let mut ips: HashSet<IpAddr> = HashSet::new();
    for ip in interface.ipv4.clone() {
        ips.insert(IpAddr::V4(ip.addr));
    }
    for ip in interface.ipv6.clone() {
        ips.insert(IpAddr::V6(ip.addr));
    }
    // localhost IP addresses
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ips
}
