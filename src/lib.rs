mod interface;
mod packet;

pub mod setting;
pub mod result;
pub mod blocking;

#[cfg(not(target_os="windows"))]
mod async_impl;
#[cfg(not(target_os="windows"))]
pub use async_impl::{HostScanner, PortScanner};
