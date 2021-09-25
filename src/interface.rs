use pnet::datalink;
use pnet::datalink::MacAddr;

pub fn get_interface_index_by_name(if_name: String) -> Option<u32> {
    for iface in datalink::interfaces() {
        if iface.name == if_name {
            return Some(iface.index)
        }
    }
    return None;
}

#[cfg(target_os="windows")]
pub fn get_default_gateway_macaddr() {
    let default_gateway = default_net::get_default_gateway();
    default_gateway.mac.expect("Failed to get gateway mac").parse::<pnet::datalink::MacAddr>().unwrap()
}

#[cfg(not(target_os="windows"))]
pub fn get_default_gateway_macaddr() -> MacAddr {
    pnet::datalink::MacAddr::zero()
}
