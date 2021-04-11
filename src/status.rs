#[derive(Clone, Copy)]
pub enum ScanStatus {
    Ready,
    Done,
    Timeout,
    Error,
}