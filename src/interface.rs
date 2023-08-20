use pnet::datalink::MacAddr;
use std::net::IpAddr;

#[allow(dead_code)]
pub fn get_interface_index_by_ip(ip_addr: IpAddr) -> Option<u32> {
    for iface in pnet::datalink::interfaces() {
        for ip in iface.ips {
            if ip.ip() == ip_addr {
                return Some(iface.index);
            }
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
