use std::net::{IpAddr};
use pnet::datalink::{self, MacAddr};

use crate::ipv4;

pub fn get_default_interface_index() -> Option<u32> {
    let local_ip = ipv4::get_local_ipaddr();
    let all_interfaces = datalink::interfaces();
    if let Some(local_ip) = local_ip {
        for iface in all_interfaces{
            for ip in iface.ips{
                match ip.ip() {
                    IpAddr::V4(ipv4) => {
                        if local_ip == ipv4.to_string() {
                            return Some(iface.index)
                        }
                    },
                    IpAddr::V6(ipv6) => {
                        if local_ip == ipv6.to_string() {
                            return Some(iface.index)
                        }
                    },
                }
            }
        }
        return None;
    }else{
        return None;
    }
}

pub fn get_interface_index_by_name(if_name: String) -> Option<u32> {
    for iface in datalink::interfaces() {
        if iface.name == if_name {
            return Some(iface.index)
        }
    }
    return None;
}
