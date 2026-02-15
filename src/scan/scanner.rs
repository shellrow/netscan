use crate::host::Host;
use crate::scan::setting::{HostScanSetting, PortScanSetting};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use tokio::runtime::{Builder, Runtime};

use super::async_io;
use super::blocking;
use super::result::{ScanError, ScanResult, ServiceProbeResult};
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
    fn runtime() -> Runtime {
        Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("failed to initialize tokio runtime")
    }

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
    /// Scan hosts asynchronously.
    pub async fn scan_async(&self) -> ScanResult {
        if self.scan_setting.async_scan {
            async_io::scan_hosts(self.scan_setting.clone(), &self.tx).await
        } else {
            let setting = self.scan_setting.clone();
            let tx = self.tx.clone();
            match tokio::task::spawn_blocking(move || blocking::scan_hosts(setting, &tx)).await {
                Ok(result) => result,
                Err(e) => ScanResult::error(ScanError::RuntimeError(format!(
                    "blocking scan task join error: {}",
                    e
                ))),
            }
        }
    }

    /// Scan hosts using an internal Tokio runtime.
    pub fn scan(&self) -> ScanResult {
        Self::runtime().block_on(self.scan_async())
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
    fn runtime() -> Runtime {
        Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("failed to initialize tokio runtime")
    }

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
    /// Scan ports asynchronously.
    pub async fn scan_async(&self) -> ScanResult {
        match self.scan_setting.scan_type {
            crate::scan::setting::PortScanType::TcpSynScan => {
                if self.scan_setting.async_scan {
                    async_io::scan_ports(self.scan_setting.clone(), &self.tx).await
                } else {
                    let setting = self.scan_setting.clone();
                    let tx = self.tx.clone();
                    match tokio::task::spawn_blocking(move || blocking::scan_ports(setting, &tx))
                        .await
                    {
                        Ok(result) => result,
                        Err(e) => ScanResult::error(ScanError::RuntimeError(format!(
                            "blocking scan task join error: {}",
                            e
                        ))),
                    }
                }
            }
            crate::scan::setting::PortScanType::TcpConnectScan => {
                async_io::run_connect_scan(self.scan_setting.clone(), &self.tx).await
            }
        }
    }

    /// Scan ports using an internal Tokio runtime.
    pub fn scan(&self) -> ScanResult {
        Self::runtime().block_on(self.scan_async())
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
    fn runtime() -> Runtime {
        Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("failed to initialize tokio runtime")
    }

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
    /// Run service detection asynchronously.
    pub async fn run_async(&self) -> HashMap<u16, ServiceProbeResult> {
        super::service::run_service_probe(&self.setting, &self.tx).await
    }

    /// Run service detection using an internal Tokio runtime.
    pub fn run(&self) -> HashMap<u16, ServiceProbeResult> {
        Self::runtime().block_on(self.run_async())
    }
}
