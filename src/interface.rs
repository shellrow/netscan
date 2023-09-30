use cross_socket::datalink::MacAddr;
use std::net::IpAddr;

#[cfg(target_os = "windows")]
use cross_socket::datalink::interface::Interface;

#[allow(dead_code)]
pub(crate) fn get_interface_index_by_ip(ip_addr: IpAddr) -> Option<u32> {
    for iface in default_net::get_interfaces() {
        for ip in iface.ipv4 {
            if ip.addr == ip_addr {
                return Some(iface.index);
            }
        }
        for ip in iface.ipv6 {
            if ip.addr == ip_addr {
                return Some(iface.index);
            }
        }
    }
    return None;
}

#[cfg(target_os = "windows")]
pub(crate) fn get_interface_by_index(index: u32) -> Option<Interface> {
    for iface in default_net::get_interfaces() {
        if iface.index == index {
            return Some(iface);
        }
    }
    return None;
}

#[cfg(target_os = "windows")]
pub fn get_default_gateway_macaddr() -> [u8; 6] {
    match default_net::get_default_gateway() {
        Ok(gateway) => gateway.mac_addr.octets(),
        Err(_) => MacAddr::zero().octets(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_default_gateway_macaddr() -> [u8; 6] {
    MacAddr::zero().octets()
}
