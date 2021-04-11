use pnet::datalink;

pub fn get_interface_index_by_name(if_name: String) -> Option<u32> {
    for iface in datalink::interfaces() {
        if iface.name == if_name {
            return Some(iface.index)
        }
    }
    return None;
}
