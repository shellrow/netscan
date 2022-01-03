pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

#[doc(hidden)]
pub const ICMP_PACKET_SIZE: usize = 66;

#[doc(hidden)]
#[cfg(not(target_family="windows"))]
pub const TCP_PACKET_SIZE: usize = 90;

#[doc(hidden)]
#[cfg(target_family="windows")]
pub const TCP_PACKET_SIZE: usize = 66;

#[doc(hidden)]
pub const UDP_PACKET_SIZE: usize = 66;
