use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::net::{TcpStream,SocketAddr};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use native_tls::TlsConnector;
use std::io::prelude::*;
use rayon::prelude::*;
use super::setting::PortDatabase;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug)]
pub struct ServiceDetector {
    pub dst_ip: IpAddr,
    pub dst_name: String,
    pub open_ports: Vec<u16>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub accept_invalid_certs: bool,
}

impl ServiceDetector {
    pub fn new() -> ServiceDetector {
        ServiceDetector{
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_name: String::new(),
            open_ports: vec![],
            connect_timeout: Duration::from_millis(50),
            read_timeout: Duration::from_secs(5),
            accept_invalid_certs: false,
        }
    }
    pub fn set_dst_ip(&mut self, dst_ip: IpAddr){
        self.dst_ip = dst_ip;
    }
    pub fn set_dst_name(&mut self, host_name: IpAddr){
        self.dst_ip = host_name;
    }
    pub fn set_open_ports(&mut self, open_ports: Vec<u16>){
        self.open_ports = open_ports;
    }
    pub fn add_open_port(&mut self, open_port: u16){
        self.open_ports.push(open_port);
    }
    pub fn set_connect_timeout(&mut self, connect_timeout: Duration){
        self.connect_timeout = connect_timeout;
    }
    pub fn set_read_timeout(&mut self, read_timeout: Duration){
        self.read_timeout = read_timeout;
    }
    pub fn set_accept_invalid_certs(&mut self, accept_invalid_certs: bool){
        self.accept_invalid_certs = accept_invalid_certs;
    }
    pub fn detect(&self, port_db: Option<PortDatabase>) -> HashMap<u16, String> {
        detect_service(self, port_db.unwrap_or(PortDatabase::default()))
    }
}

fn detect_service(setting: &ServiceDetector, port_db: PortDatabase) -> HashMap<u16, String> {
    let service_map: Arc<Mutex<HashMap<u16, String>>> = Arc::new(Mutex::new(HashMap::new()));
    setting.clone().open_ports.into_par_iter().for_each(|port| 
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
                Err(_) => {},
            }
        }
    );
    let result_map: HashMap<u16, String> = service_map.lock().unwrap().clone();
    return result_map;
}

fn read_response(reader: &mut BufReader<&TcpStream>) -> String {
    let mut msg = String::new();
    match reader.read_to_string(&mut msg) {
        Ok(_) => {},
        Err(_) => {},
    }
    return msg;
}

fn parse_header(response_header: String) -> String {
    let header_fields: Vec<&str>  = response_header.split("\r\n").collect();
    if header_fields.len() == 1 {
        return response_header;
    }
    let mut result_vec: Vec<String> = vec![];
    for field in header_fields {
        if field.contains("Server:") || field.contains("Location:") {
            result_vec.push(field.to_string());
        }
    }
    return result_vec.iter().map(|s| s.trim()).collect::<Vec<_>>().join("\t");
}

fn write_head_request(writer: &mut BufWriter<&TcpStream>, _ip_addr:String) {
    let msg = format!("HEAD / HTTP/1.0\r\n\r\n");
    match writer.write(msg.as_bytes()) {
        Ok(_) => {},
        Err(_) => {},
    }
    writer.flush().unwrap();
}

fn head_request_secure(host_name: String, port: u16, accept_invalid_certs: bool) -> String {
    if host_name.is_empty() {
        return String::from("Error: Invalid host name");
    }
    let sock_addr: String = format!("{}:{}",host_name, port);
    let connector = if accept_invalid_certs {
        match TlsConnector::builder().danger_accept_invalid_certs(true).build() {
            Ok(c) => c,
            Err(e) => return format!("Error: {}",e.to_string()),
        }
    }else{
        match TlsConnector::new() {
            Ok(c) => c,
            Err(e) => return format!("Error: {}",e.to_string()),
        }
    };
    let stream = match TcpStream::connect(sock_addr.clone()) {
        Ok(s) => s,
        Err(e) => return format!("Error: {}",e.to_string()),
    };
    match stream.set_read_timeout(Some(Duration::from_secs(10))) {
        Ok(_) => {},
        Err(e) => return format!("Error: {}",e.to_string()),
    }
    let mut stream = match connector.connect(host_name.as_str(), stream) {
        Ok(s) => s,
        Err(e) => return format!("Error: {}",e.to_string()),
    };
    let msg = format!("HEAD / HTTP/1.0\r\n\r\n");
    match stream.write(msg.as_bytes()){
        Ok(_) => {},
        Err(e) => return format!("Error: {}",e.to_string()),
    }
    let mut res = vec![];
    match stream.read_to_end(&mut res){
        Ok(_) => {
            let result = String::from_utf8_lossy(&res);
            return result.to_string();
        },
        Err(e) => return format!("Error: {}",e.to_string()),
    };
}
