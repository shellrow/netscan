pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

pub const ICMP_PACKET_SIZE: usize = 66;

#[cfg(not(target_family="windows"))]
pub const TCP_PACKET_SIZE: usize = 90;

#[cfg(target_family="windows")]
pub const TCP_PACKET_SIZE: usize = 66;

pub const UDP_PACKET_SIZE: usize = 66;
