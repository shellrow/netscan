use crate::host::Host;
use crate::scan::setting::{HostScanSetting, PortScanSetting};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use super::async_io;
use super::blocking;
use super::result::{ScanResult, ServiceProbeResult};
use super::setting::ServiceProbeSetting;

/// Host Scanner
#[derive(Clone, Debug)]
pub struct HostScanner {
    /// Scan Setting
    pub scan_setting: HostScanSetting,
    /// Sender for progress messaging
    pub tx: Arc<Mutex<Sender<Host>>>,
    /// Receiver for progress messaging
    pub rx: Arc<Mutex<Receiver<Host>>>,
}

impl HostScanner {
    /// Create new HostScanner
    pub fn new(scan_setting: HostScanSetting) -> Self {
        let (tx, rx) = channel();
        Self {
            scan_setting,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        }
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<Host>>> {
        self.rx.clone()
    }
    // Scan hosts
    pub fn scan(&self) -> ScanResult {
        if self.scan_setting.async_scan {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async_io::scan_hosts(self.scan_setting.clone(), &self.tx))
        } else {
            blocking::scan_hosts(self.scan_setting.clone(), &self.tx)
        }
    }
}

/// Port Scanner
#[derive(Clone, Debug)]
pub struct PortScanner {
    /// Scan Setting
    pub scan_setting: PortScanSetting,
    /// Sender for progress messaging
    pub tx: Arc<Mutex<Sender<SocketAddr>>>,
    /// Receiver for progress messaging
    pub rx: Arc<Mutex<Receiver<SocketAddr>>>,
}

impl PortScanner {
    /// Create new PortScanner
    pub fn new(scan_setting: PortScanSetting) -> Self {
        let (tx, rx) = channel();
        Self {
            scan_setting,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        }
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<SocketAddr>>> {
        self.rx.clone()
    }
    /// Scan ports
    pub fn scan(&self) -> ScanResult {
        match self.scan_setting.scan_type {
            crate::scan::setting::PortScanType::TcpSynScan => {
                if self.scan_setting.async_scan {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async_io::scan_ports(self.scan_setting.clone(), &self.tx))
                } else {
                    blocking::scan_ports(self.scan_setting.clone(), &self.tx)
                }
            }
            crate::scan::setting::PortScanType::TcpConnectScan => {
                async_io::run_connect_scan(self.scan_setting.clone(), &self.tx)
            }
        }
    }
}

/// Struct for service detection
#[derive(Clone, Debug)]
pub struct ServiceDetector {
    /// Probe setting for service detection
    pub setting: ServiceProbeSetting,
    /// Sender for progress messaging
    pub tx: Arc<Mutex<Sender<SocketAddr>>>,
    /// Receiver for progress messaging
    pub rx: Arc<Mutex<Receiver<SocketAddr>>>,
}

impl ServiceDetector {
    /// Create new ServiceDetector
    pub fn new(setting: ServiceProbeSetting) -> Self {
        let (tx, rx) = channel();
        Self {
            setting,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        }
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<SocketAddr>>> {
        self.rx.clone()
    }
    /// Run service detection
    pub fn run(&self) -> HashMap<u16, ServiceProbeResult> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(super::service::run_service_probe(&self.setting, &self.tx))
    }
}
