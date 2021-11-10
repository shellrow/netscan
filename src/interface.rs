use std::net::IpAddr;
use pnet_datalink::MacAddr;

#[allow(dead_code)]
pub fn get_interface_index_by_ip(ip_addr: IpAddr) -> Option<u32> {
    for iface in pnet_datalink::interfaces() {
        for ip in iface.ips {
            if ip.ip() == ip_addr {
                return Some(iface.index);
            }
        }   
    }
    return None;
}

#[allow(dead_code)]
#[cfg(target_os="windows")]
pub fn get_default_gateway_macaddr() -> MacAddr {
    let default_gateway = default_net::get_default_gateway();
    default_gateway.mac.expect("Failed to get gateway mac").parse::<pnet::datalink::MacAddr>().unwrap()
}

#[allow(dead_code)]
#[cfg(not(target_os="windows"))]
pub fn get_default_gateway_macaddr() -> MacAddr {
    MacAddr::zero()
}
