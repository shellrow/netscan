use std::net::IpAddr;
use pnet::datalink;
use pnet::datalink::MacAddr;

pub fn get_interface_index_by_ip(ip_addr: IpAddr) -> Option<u32> {
    for iface in datalink::interfaces() {
        for ip in iface.ips {
            if ip.contains(ip_addr) {
                return Some(iface.index);
            }
        }   
    }
    return None;
}

#[cfg(target_os="windows")]
pub fn get_default_gateway_macaddr() -> MacAddr {
    let default_gateway = default_net::get_default_gateway();
    default_gateway.mac.expect("Failed to get gateway mac").parse::<pnet::datalink::MacAddr>().unwrap()
}

#[cfg(not(target_os="windows"))]
pub fn get_default_gateway_macaddr() -> MacAddr {
    pnet::datalink::MacAddr::zero()
}
