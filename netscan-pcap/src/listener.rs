use crate::capture::start_capture;
use crate::PacketCaptureOptions;
use crate::PacketFrame;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

/// Listner
#[derive(Debug)]
pub struct Listner {
    /// Packet capture options
    pub options: PacketCaptureOptions,
    /// Message Sender
    pub tx: Arc<Mutex<Sender<PacketFrame>>>,
    /// Message Receiver
    #[allow(dead_code)]
    pub rx: Arc<Mutex<Receiver<PacketFrame>>>,
    /// Stop handle
    pub stop: Arc<Mutex<bool>>,
}

impl Listner {
    /// Create new Listner
    pub fn new(options: PacketCaptureOptions) -> Listner {
        let (tx, rx) = channel();
        let listener: Listner = Listner {
            options: options,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
            stop: Arc::new(Mutex::new(false)),
        };
        listener
    }

    /// Get progress receiver
    #[allow(dead_code)]
    pub fn get_receiver(&self) -> Arc<Mutex<Receiver<PacketFrame>>> {
        self.rx.clone()
    }

    /// Get stop handle
    pub fn get_stop_handle(&self) -> Arc<Mutex<bool>> {
        self.stop.clone()
    }

    /// Start capture and return captured packets
    pub fn start(&self) -> Vec<PacketFrame> {
        let options = self.options.clone();
        start_capture(options, &self.tx, &self.stop)
    }
}
