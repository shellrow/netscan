use std::net::{IpAddr, Ipv6Addr};
use xenet::net::interface::Interface;
use xenet::net::mac::MacAddr;

fn is_global_ipv6(ipv6_addr: &Ipv6Addr) -> bool {
    !(ipv6_addr.is_unspecified()
        || ipv6_addr.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ipv6_addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(ipv6_addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ipv6_addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ipv6_addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(ipv6_addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(ipv6_addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(ipv6_addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(ipv6_addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                || matches!(ipv6_addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
            ))
        // Reserved for documentation
        || ((ipv6_addr.segments()[0] == 0x2001) && (ipv6_addr.segments()[1] == 0x2) && (ipv6_addr.segments()[2] == 0))
        // Unique Local Address
        || ((ipv6_addr.segments()[0] & 0xfe00) == 0xfc00)
        // unicast address with link-local scope (`fc00::/7`)
        || ((ipv6_addr.segments()[0] & 0xffc0) == 0xfe80))
}

pub(crate) fn get_interface_by_ip(ip_addr: IpAddr) -> Option<Interface> {
    for iface in xenet::net::interface::get_interfaces() {
        for ip in iface.ipv4.clone() {
            if ip.addr == ip_addr {
                return Some(iface);
            }
        }
        for ip in iface.ipv6.clone() {
            if ip.addr == ip_addr {
                return Some(iface);
            }
        }
    }
    return None;
}

pub(crate) fn get_interface_by_index(index: u32) -> Option<Interface> {
    for iface in xenet::net::interface::get_interfaces() {
        if iface.index == index {
            return Some(iface);
        }
    }
    return None;
}

pub(crate) fn get_interface_by_name(name: String) -> Option<Interface> {
    for iface in xenet::net::interface::get_interfaces() {
        if iface.name == name {
            return Some(iface);
        }
    }
    return None;
}

pub(crate) fn get_interface_ipv4(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv4.clone() {
        return Some(IpAddr::V4(ip.addr));
    }
    return None;
}

pub(crate) fn get_interface_ipv6(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv6.clone() {
        if is_global_ipv6(&ip.addr) {
            return Some(IpAddr::V6(ip.addr));
        }
    }
    return None;
}

pub fn get_default_gateway_macaddr() -> MacAddr {
    match xenet::net::gateway::get_default_gateway() {
        Ok(gateway) => gateway.mac_addr,
        Err(_) => MacAddr::zero(),
    }
}
