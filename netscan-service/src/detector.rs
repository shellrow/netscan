use crate::payload::{PayloadInfo, PayloadType};
use crate::setting::{NoCertificateVerification, ProbeSetting};
use crate::result::{ServiceProbeResult, ServiceProbeError};
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::tcp_service::PORT_SERVICE_MAP;

/// Struct for service detection
#[derive(Clone, Debug)]
pub struct ServiceDetector {
    /// Probe setting for service detection
    pub setting: ProbeSetting,
    /// Result of service detection
    result: HashMap<u16, ServiceProbeResult>,
}

impl ServiceDetector {
    /// Create new ServiceDetector
    pub fn new(setting: ProbeSetting) -> ServiceDetector {
        ServiceDetector {
            setting,
            result: HashMap::new(),
        }
    }
    /// Run service detection and return result
    pub fn detect(&self) -> HashMap<u16, ServiceProbeResult> {
        self.detect_mt()
    }
    pub fn start_detection(&mut self) {
        self.result = self.detect_mt()
    }
    /// Get result of service detection
    pub fn get_result(&self) -> &HashMap<u16, ServiceProbeResult> {
        &self.result
    }
    /// Get result for specified port. Returns None if port is not found.
    pub fn get_result_for_port(&self, port: u16) -> Option<&ServiceProbeResult> {
        self.result.get(&port)
    }
    /// Get result for specified port. Returns None if port is not found.
    fn probe_port(&self, port: u16, payload_info: Option<PayloadInfo>) -> ServiceProbeResult {
        let service_name: String = match PORT_SERVICE_MAP.get(&port) {
            Some(name) => name.to_string(),
            None => String::new(),
        };
        let mut probe_result: ServiceProbeResult = ServiceProbeResult::new(port, service_name, Vec::new());
        let socket_addr: SocketAddr = SocketAddr::new(self.setting.ip_addr, port);
        match TcpStream::connect_timeout(&socket_addr, self.setting.connect_timeout) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(self.setting.read_timeout))
                    .expect("Failed to set read_timeout.");
                let mut reader = BufReader::new(&stream);
                let mut writer = BufWriter::new(&stream);
                if let Some(payload) = payload_info {
                    writer.write_all(&payload.payload).unwrap();
                    writer.flush().unwrap();
                    let mut response: Vec<u8> = Vec::new();
                    reader.read_to_end(&mut response).unwrap();
                    match payload.payload_type {
                        PayloadType::HTTP => {
                            probe_result.service_detail = parse_http_header(&response);
                        },
                        PayloadType::HTTPS => {
                            match send_payload_tls(self.setting.hostname.clone(), port, payload.payload, self.setting.accept_invalid_certs) {
                                Ok(res) => {
                                    probe_result.service_detail = parse_http_header(&res);
                                },
                                Err(e) => {
                                    probe_result.error = Some(ServiceProbeError::TlsError(e));
                                }
                            }
                        },
                        PayloadType::TLS => {
                            match send_payload_tls(self.setting.hostname.clone(), port, payload.payload, self.setting.accept_invalid_certs) {
                                Ok(res) => {
                                    probe_result.service_detail = Some(String::from_utf8(res).unwrap());
                                },
                                Err(e) => {
                                    probe_result.error = Some(ServiceProbeError::TlsError(e));
                                }
                            }
                        },
                        _ => {
                            match String::from_utf8(response.clone()) {
                                Ok(res) => {
                                    probe_result.service_detail = Some(res);
                                },
                                Err(_) => {
                                    probe_result.service_detail = Some(String::from_utf8_lossy(&response).to_string());
                                }
                            }
                        },   
                    }
                    probe_result.response = response;
                }else {
                    // NULL probe
                    let mut response: Vec<u8> = Vec::new();
                    reader.read_to_end(&mut response).unwrap();
                    match String::from_utf8(response.clone()) {
                        Ok(res) => {
                            probe_result.service_detail = Some(res);
                        },
                        Err(_) => {
                            probe_result.service_detail = Some(String::from_utf8_lossy(&response).to_string());
                        }
                    }
                    probe_result.response = response;
                }
            },
            Err(e) => {
                probe_result.error = Some(ServiceProbeError::ConnectionError(e.to_string()));
            }
        }
        probe_result 
    }
    /// Run service detection in parallel and return result
    fn detect_mt(&self) -> HashMap<u16, ServiceProbeResult> {
        let service_map: Arc<Mutex<HashMap<u16, ServiceProbeResult>>> = Arc::new(Mutex::new(HashMap::new()));
        self.setting.clone().ports.into_par_iter().for_each(|port| {
            let probe_result: ServiceProbeResult = self.probe_port(port, self.setting.payload_map.get(&port).cloned());
            service_map.lock().unwrap().insert(port, probe_result);
        });
        let result_map: HashMap<u16, ServiceProbeResult> = service_map.lock().unwrap().clone();
        result_map
    }    
}

/// Send payload using TLS connection and return response
fn send_payload_tls(
    hostname: String,
    port: u16,
    payload: Vec<u8>,
    accept_invalid_certs: bool,
) -> Result<Vec<u8>, String> {
    if hostname.is_empty() {
        return Err(String::from("Error: Invalid host name"));
    }
    let sock_addr: String = format!("{}:{}", hostname, port);
    let mut root_store = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                root_store.add(&rustls::Certificate(cert.0)).unwrap();
            }
        }
        Err(e) => return Err(format!("Error: {}", e.to_string()))
    }

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    if accept_invalid_certs {
        // Create dangerous config
        let mut dangerous_config: rustls::client::DangerousClientConfig =
            rustls::ClientConfig::dangerous(&mut config);
        // Disable certificate verification
        dangerous_config.set_certificate_verifier(Arc::new(NoCertificateVerification {}));
    }

    let mut tls_connection: rustls::ClientConnection =
        rustls::ClientConnection::new(Arc::new(config), hostname.as_str().try_into().unwrap())
            .unwrap();

    let mut stream: TcpStream = match TcpStream::connect(sock_addr.clone()) {
        Ok(s) => s,
        Err(e) => return Err(format!("Error: {}", e.to_string())),
    };
    match stream.set_read_timeout(Some(Duration::from_secs(10))) {
        Ok(_) => {}
        Err(e) => return Err(format!("Error: {}", e.to_string())),
    }
    let mut tls_stream: rustls::Stream<rustls::ClientConnection, TcpStream> =
        rustls::Stream::new(&mut tls_connection, &mut stream);
    match tls_stream.write_all(&payload) {
        Ok(_) => {}
        Err(e) => return Err(format!("Error: {}", e.to_string())),
    }
    let mut res = Vec::new();
    match tls_stream.read_to_end(&mut res) {
        Ok(_) => {}
        Err(e) => return Err(format!("Error: {}", e.to_string())),
    }
    Ok(res)
}

/// Parse HTTP header and return server name
/// 
/// The server name possibly contains version number.
/* fn parse_http_header(response_header: String) -> String {
    let header_fields: Vec<&str> = response_header.split("\r\n").collect();
    if header_fields.len() == 1 {
        return response_header;
    }
    for field in header_fields {
        if field.contains("Server:") {
            return field.trim().to_string();
        }
    }
    String::new()
} */

/// Parse HTTP header and return server name
fn parse_http_header(res_bytes: &Vec<u8>) -> Option<String> {
    let res_string: String = res_bytes.iter().map(|&c| c as char).collect();
    let header_fields: Vec<&str> = res_string.split("\r\n").collect();
    if header_fields.len() == 1 {
        if res_string.contains("Server:") {
            return Some(res_string);
        }else {
            return None;
        }
    }
    for field in header_fields {
        if field.contains("Server:") {
            let server_info: String = field.trim().to_string();
            return Some(server_info);
        }
    }
    None
}

/* fn write_head_request(writer: &mut BufWriter<&TcpStream>, _ip_addr: String) {
    let msg = format!("HEAD / HTTP/1.0\r\n\r\n");
    match writer.write(msg.as_bytes()) {
        Ok(_) => {}
        Err(_) => {}
    }
    writer.flush().unwrap();
} */

/* fn head_request_secure(hostname: String, port: u16, accept_invalid_certs: bool) -> String {
    if hostname.is_empty() {
        return String::from("Error: Invalid host name");
    }
    let sock_addr: String = format!("{}:{}", hostname, port);
    let mut root_store = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                root_store.add(&rustls::Certificate(cert.0)).unwrap();
            }
        }
        Err(e) => return format!("Error: {}", e.to_string()),
    }

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    if accept_invalid_certs {
        // Create dangerous config
        let mut dangerous_config: rustls::client::DangerousClientConfig =
            rustls::ClientConfig::dangerous(&mut config);
        // Disable certificate verification
        dangerous_config.set_certificate_verifier(Arc::new(NoCertificateVerification {}));
    }

    let mut tls_connection: rustls::ClientConnection =
        rustls::ClientConnection::new(Arc::new(config), hostname.as_str().try_into().unwrap())
            .unwrap();

    let mut stream: TcpStream = match TcpStream::connect(sock_addr.clone()) {
        Ok(s) => s,
        Err(e) => return format!("Error: {}", e.to_string()),
    };
    match stream.set_read_timeout(Some(Duration::from_secs(10))) {
        Ok(_) => {}
        Err(e) => return format!("Error: {}", e.to_string()),
    }
    let mut tls_stream: rustls::Stream<rustls::ClientConnection, TcpStream> =
        rustls::Stream::new(&mut tls_connection, &mut stream);
    let message: String = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
        hostname
    );
    match tls_stream.write_all(message.as_bytes()) {
        Ok(_) => {}
        Err(e) => return format!("Error: {}", e.to_string()),
    }
    let mut plaintext = Vec::new();
    match tls_stream.read_to_end(&mut plaintext) {
        Ok(_) => {}
        Err(e) => return format!("Error: {}", e.to_string()),
    }
    let result: String = plaintext.iter().map(|&c| c as char).collect();
    result
} */
