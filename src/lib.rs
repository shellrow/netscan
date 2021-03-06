mod interface;
mod packet;

pub mod setting;
pub mod result;
pub mod blocking;

#[cfg(feature = "async")]
pub mod async_io;

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
