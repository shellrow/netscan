use crate::payload::{PayloadBuilder, PayloadInfo, PayloadType};
use std::{collections::HashMap, time::Duration, net::{IpAddr, Ipv4Addr}};

/// Probe setting for service detection
#[derive(Clone, Debug)]
pub struct ProbeSetting {
    /// Destination IP address
    pub ip_addr: IpAddr,
    /// Destination Host Name
    pub hostname: String,
    /// Target ports for service detection
    pub ports: Vec<u16>,
    /// TCP connect (open) timeout
    pub connect_timeout: Duration,
    /// TCP read timeout
    pub read_timeout: Duration,
    /// SSL/TLS certificate validation when detecting HTTPS services.  
    ///
    /// Default value is false, which means validation is enabled.
    pub accept_invalid_certs: bool,
    /// Payloads for specified ports. 
    /// 
    /// If not set, default null probe will be used. (No payload, just open TCP connection and read response)
    pub payload_map: HashMap<u16, PayloadInfo>,
}

impl ProbeSetting {
    /// Create new ProbeSetting
    pub fn new() -> ProbeSetting {
        ProbeSetting {
            ip_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            hostname: String::new(),
            ports: vec![],
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_secs(5),
            accept_invalid_certs: false,
            payload_map: HashMap::new(),
        }
    }
    pub fn default(ip_addr: IpAddr, hostname: String, ports: Vec<u16>) -> ProbeSetting {
        let mut payload_map: HashMap<u16, PayloadInfo> = HashMap::new();
        let http_head = PayloadBuilder::http_head();
        let https_head = PayloadBuilder::https_head(hostname.clone());
        payload_map.insert(80, PayloadInfo {
            payload: http_head.clone(),
            payload_type: PayloadType::HTTP,
        });
        payload_map.insert(443, PayloadInfo {
            payload: https_head.clone(),
            payload_type: PayloadType::HTTPS,
        });
        payload_map.insert(8080, PayloadInfo {
            payload: http_head,
            payload_type: PayloadType::HTTP,
        });
        payload_map.insert(8443, PayloadInfo {
            payload: https_head,
            payload_type: PayloadType::HTTPS,
        });
        ProbeSetting {
            ip_addr: ip_addr,
            hostname: hostname,
            ports: ports,
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_secs(5),
            accept_invalid_certs: false,
            payload_map: payload_map,
        }
    }
    /// Set Destination IP address
    pub fn with_ip_addr(&mut self, ip_addr: IpAddr) -> &mut Self {
        self.ip_addr = ip_addr;
        self
    }
    /// Set Destination Host Name. If IP address is not set, it will be resolved from the hostname.
    pub fn with_hostname(&mut self, hostname: String) -> &mut Self {
        self.hostname = hostname;
        if self.ip_addr == IpAddr::V4(Ipv4Addr::LOCALHOST) {
            match dns_lookup::lookup_host(&self.hostname) {
                Ok(ips) => {
                    if ips.len() > 0 {
                        self.ip_addr = ips.first().unwrap().clone();
                    }
                }
                Err(_) => {}
            }
        }
        self
    }
    /// Add target port
    pub fn add_port(&mut self, port: u16) {
        self.ports.push(port);
    }
    /// Set connect (open) timeout in milliseconds
    pub fn set_connect_timeout_millis(&mut self, connect_timeout_millis: u64) {
        self.connect_timeout = Duration::from_millis(connect_timeout_millis);
    }
    /// Set TCP read timeout in milliseconds
    pub fn set_read_timeout_millis(&mut self, read_timeout_millis: u64) {
        self.read_timeout = Duration::from_millis(read_timeout_millis);
    }
}

pub struct NoCertificateVerification {}
impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
