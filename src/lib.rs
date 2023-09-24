mod interface;
//mod packet;

pub mod async_io;
pub mod blocking;
pub mod host;
pub mod result;
pub mod scanner;
pub mod setting;

pub use cross_socket::packet;

#[cfg(feature = "service")]
extern crate netscan_service;

#[cfg(feature = "os")]
extern crate netscan_os;

#[cfg(feature = "service")]
pub mod service {
    pub use netscan_service::*;
}

#[cfg(feature = "os")]
pub mod os {
    pub use netscan_os::*;
}
