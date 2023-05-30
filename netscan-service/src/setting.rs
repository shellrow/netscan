/// List of ports for which more detailed information can be obtained, by service.
///
/// HTTP/HTTPS, etc.
#[derive(Clone, Debug)]
pub struct PortDatabase {
    pub http_ports: Vec<u16>,
    pub https_ports: Vec<u16>,
}

impl PortDatabase {
    pub fn new() -> PortDatabase {
        PortDatabase {
            http_ports: vec![],
            https_ports: vec![],
        }
    }
    pub fn default() -> PortDatabase {
        PortDatabase {
            http_ports: vec![80, 8080],
            https_ports: vec![443, 8443],
        }
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
