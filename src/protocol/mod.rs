#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    ARP,
    NDP,
    ICMP,
    TCP,
    UDP,
}

impl Protocol {
    pub fn from_str(s: &str) -> Option<Protocol> {
        match s.to_lowercase().as_str() {
            "arp" => Some(Protocol::ARP),
            "ndp" => Some(Protocol::NDP),
            "icmp" => Some(Protocol::ICMP),
            "tcp" => Some(Protocol::TCP),
            "udp" => Some(Protocol::UDP),
            _ => None,
        }
    }
    pub fn to_str(&self) -> &str {
        match self {
            Protocol::ARP => "ARP",
            Protocol::NDP => "NDP",
            Protocol::ICMP => "ICMP",
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
        }
    }
}
