use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::net::{TcpStream,SocketAddr};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::io::prelude::*;
use rayon::prelude::*;
use super::setting::PortDatabase;
use std::net::{IpAddr, Ipv4Addr};

/// Struct for service detection
#[derive(Clone, Debug)]
pub struct ServiceDetector {
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Destination Host Name
    pub dst_name: String,
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
}

impl ServiceDetector {
    /// Create new ServiceDetector
    pub fn new() -> ServiceDetector {
        ServiceDetector{
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_name: String::new(),
            ports: vec![],
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_secs(5),
            accept_invalid_certs: false,
        }
    }
    /// Set Destination IP address
    pub fn set_dst_ip(&mut self, dst_ip: IpAddr){
        self.dst_ip = dst_ip;
        if self.dst_name.is_empty() {
            self.dst_name = dns_lookup::lookup_addr(&self.dst_ip).unwrap_or(String::new());
        }   
    }
    /// Set Destination Host Name
    pub fn set_dst_name(&mut self, host_name: String){
        self.dst_name = host_name;
        if self.dst_ip == IpAddr::V4(Ipv4Addr::LOCALHOST) {
            self.dst_ip = dns_lookup::lookup_host(&self.dst_name).unwrap_or(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).first().unwrap().clone();
        }   
    }
    /// Set target ports
    pub fn set_ports(&mut self, ports: Vec<u16>){
        self.ports = ports;
    }
    /// Add target port
    pub fn add_port(&mut self, port: u16){
        self.ports.push(port);
    }
    /// Set connect (open) timeout
    pub fn set_connect_timeout(&mut self, connect_timeout: Duration){
        self.connect_timeout = connect_timeout;
    }
    /// Set TCP read timeout
    pub fn set_read_timeout(&mut self, read_timeout: Duration){
        self.read_timeout = read_timeout;
    }
    /// Set SSL/TLS certificate validation enable/disable.
    pub fn set_accept_invalid_certs(&mut self, accept_invalid_certs: bool){
        self.accept_invalid_certs = accept_invalid_certs;
    }
    /// Run service detection and return result
    /// 
    /// PortDatabase can be omitted with None (use default list) 
    pub fn detect(&self, port_db: Option<PortDatabase>) -> HashMap<u16, String> {
        detect_service(self, port_db.unwrap_or(PortDatabase::default()))
    }
}

fn detect_service(setting: &ServiceDetector, port_db: PortDatabase) -> HashMap<u16, String> {
    let service_map: Arc<Mutex<HashMap<u16, String>>> = Arc::new(Mutex::new(HashMap::new()));
    setting.clone().ports.into_par_iter().for_each(|port| 
        {
            let sock_addr: SocketAddr = SocketAddr::new(setting.dst_ip, port);
            match TcpStream::connect_timeout(&sock_addr, setting.connect_timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(setting.read_timeout)).expect("Failed to set read timeout.");
                    let mut reader = BufReader::new(&stream);
                    let mut writer = BufWriter::new(&stream);
                    let msg: String = 
                    if port_db.http_ports.contains(&port) {
                        write_head_request(&mut writer, setting.dst_ip.to_string());
                        let header = read_response(&mut reader);
                        parse_header(header)
                    }else if port_db.https_ports.contains(&port) {
                        let header = head_request_secure(setting.dst_name.clone(), port, setting.accept_invalid_certs);
                        parse_header(header)
                    }else{
                        read_response(&mut reader).replace("\r\n", "")
                    };
                    service_map.lock().unwrap().insert(port, msg);
                },
                Err(e) => {
                    service_map.lock().unwrap().insert(port, e.to_string());
                },
            }
        }
    );
    let result_map: HashMap<u16, String> = service_map.lock().unwrap().clone();
    result_map
}

fn read_response(reader: &mut BufReader<&TcpStream>) -> String {
    let mut msg = String::new();
    match reader.read_to_string(&mut msg) {
        Ok(_) => {},
        Err(_) => {},
    }
    msg
}

fn parse_header(response_header: String) -> String {
    let header_fields: Vec<&str>  = response_header.split("\r\n").collect();
    if header_fields.len() == 1 {
        return response_header;
    }
    for field in header_fields {
        if field.contains("Server:") {
            return field.trim().to_string();
        }
    }
    String::new()
}

fn write_head_request(writer: &mut BufWriter<&TcpStream>, _ip_addr:String) {
    let msg = format!("HEAD / HTTP/1.0\r\n\r\n");
    match writer.write(msg.as_bytes()) {
        Ok(_) => {},
        Err(_) => {},
    }
    writer.flush().unwrap();
}

fn head_request_secure(host_name: String, port: u16, _accept_invalid_certs: bool) -> String {
    if host_name.is_empty() {
        return String::from("Error: Invalid host name");
    }
    let sock_addr: String = format!("{}:{}",host_name, port);
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        root_store
            .add(&rustls::Certificate(cert.0))
            .unwrap();
    }
    let config = rustls::ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
    let mut tls_connection: rustls::ClientConnection = rustls::ClientConnection::new(Arc::new(config), host_name.as_str().try_into().unwrap()).unwrap();
    let mut stream: TcpStream = match TcpStream::connect(sock_addr.clone()) {
        Ok(s) => s,
        Err(e) => return format!("Error: {}",e.to_string()),
    };
    match stream.set_read_timeout(Some(Duration::from_secs(10))) {
        Ok(_) => {},
        Err(e) => return format!("Error: {}",e.to_string()),
    }
    let mut tls_stream: rustls::Stream<rustls::ClientConnection, TcpStream> = rustls::Stream::new(&mut tls_connection, &mut stream);
    let message: String = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n", host_name);
    tls_stream.write_all(message.as_bytes()).unwrap();
    let mut plaintext = Vec::new();
    tls_stream.read_to_end(&mut plaintext).unwrap();
    let result: String = plaintext.iter().map(|&c| c as char).collect();
    result
}
