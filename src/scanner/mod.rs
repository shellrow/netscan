pub mod shared;
pub use self::shared::*;

#[cfg(not(target_os="windows"))]
pub mod unix;
#[cfg(not(target_os="windows"))]
pub use self::unix::*;

#[cfg(target_os="windows")]
pub mod windows;
#[cfg(target_os="windows")]
pub use self::windows::*;
