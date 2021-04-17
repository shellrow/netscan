/// Scan status of current scanner 
#[derive(Clone, Copy)]
pub enum ScanStatus {
    Ready,
    Done,
    Timeout,
    Error,
}