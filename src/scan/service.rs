use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::io::{Read, Write};
use async_io::{Async, Timer};
use futures_lite::{AsyncWriteExt, AsyncReadExt};
use futures_lite::future::FutureExt;
use futures::stream::{self, StreamExt};
use nex::socket::tls::socket::rustls;
use nex::socket::tls::TlsClient;
use super::payload::{PayloadInfo, PayloadType};
use super::result::{ServiceProbeError, ServiceProbeResult};
use super::setting::ServiceProbeSetting;
use std::collections::HashMap;
use crate::db::tcp_service::PORT_SERVICE_MAP;

/// Parse HTTP header and return server name
///
/// The server name possibly contains version number.
fn parse_http_header(res_bytes: &Vec<u8>) -> Option<String> {
    let res_string: String = res_bytes.iter().map(|&c| c as char).collect();
    let header_fields: Vec<&str> = res_string.split("\r\n").collect();
    if header_fields.len() == 1 {
        if res_string.contains("Server:") {
            return Some(res_string);
        } else {
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

/// Read to end and return response as Vec<u8>
/// This ignore io::Error on read_to_end because it is expected when reading response.
/// If no response is received, and io::Error is occurred, return Err.
async fn read_response_timeout(tcp_stream: &mut Async<TcpStream>, timeout: Duration) -> std::io::Result<Vec<u8>> {
    let mut io_error: std::io::Error =
        std::io::Error::new(std::io::ErrorKind::Other, "No response");
    let mut response: Vec<u8> = Vec::new();
    match tcp_stream.read_to_end(&mut response).or(async {
        Timer::after(timeout).await;
        Err(std::io::ErrorKind::TimedOut.into())
    }).await {
        Ok(_) => {}
        Err(e) => {
            io_error = e;
        }
    }
    if response.len() == 0 {
        return Err(io_error);
    } else {
        Ok(response)
    }
}

pub async fn async_tcp_connect_timeout(
    addr: &SocketAddr,
    timeout: Duration,
) -> std::io::Result<Async::<TcpStream>> {
    let stream = Async::<TcpStream>::connect(*addr)
        .or(async {
            Timer::after(timeout).await;
            Err(std::io::ErrorKind::TimedOut.into())
        })
        .await?;
    Ok(stream)
}

async fn probe_port(ip_addr:IpAddr, hostname: String, port: u16, payload_info: Option<PayloadInfo>, timeout: Duration) -> ServiceProbeResult {
    let service_name: String = match PORT_SERVICE_MAP.get(&port) {
        Some(name) => name.to_string(),
        None => String::new(),
    };
    let socket_addr: SocketAddr = SocketAddr::new(ip_addr, port);
    let mut tcp_stream = async_tcp_connect_timeout(&socket_addr, timeout).await.unwrap();
    match tcp_stream.write_with(|inner| inner.set_read_timeout(Some(timeout))).await {
        Ok(_) => {},
        Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ConnectionError(e.to_string()))
    }
    if let Some(payload) = payload_info {
        match payload.payload_type {
            PayloadType::Http => {
                match tcp_stream.write_all(&payload.payload).await {
                    Ok(_) => {
                        match tcp_stream.flush().await {
                            Ok(_) => {},
                            Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::WriteError(e.to_string()))
                        }
                        match read_response_timeout(&mut tcp_stream, timeout).await {
                            Ok(res) => {
                                let mut result = ServiceProbeResult::new(port, service_name, res.clone());
                                result.service_detail = parse_http_header(&res);
                                return result;
                            },
                            Err(e) => {
                                return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ReadError(e.to_string()))
                            }
                        }
                    },
                    Err(e) => {
                        return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::WriteError(e.to_string()))
                    }
                }
            },
            PayloadType::Https => {
                let native_certs = nex::socket::tls::certs::get_native_certs().unwrap();
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(native_certs)
                    .with_no_client_auth();
                let tcp_stream_inner = match tcp_stream.into_inner() {
                    Ok(tcp_stream_inner) => tcp_stream_inner,
                    Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ConnectionError(e.to_string()))
                };
                match tcp_stream_inner.set_nonblocking(false) {
                    Ok(_) => {},
                    Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ConnectionError(e.to_string()))
                }
                let mut tls_client = match TlsClient::new(hostname.to_string(), tcp_stream_inner, config) {
                    Ok(tls_client) => tls_client,
                    Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ConnectionError(e.to_string()))
                };
                match tls_client.write_all(&payload.payload) {
                    Ok(_) => {
                        match tls_client.flush() {
                            Ok(_) => {},
                            Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::WriteError(e.to_string()))
                        }
                        let mut buf: Vec<u8> = Vec::new();
                        match tls_client.read_to_end(&mut buf) {
                            Ok(_) => {
                                let mut result = ServiceProbeResult::new(port, service_name, buf.clone());
                                result.service_detail = parse_http_header(&buf);
                                return result;
                            },
                            Err(e) => {
                                return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ReadError(e.to_string()))
                            }
                        }
                    }
                    Err(e) => {
                        return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::WriteError(e.to_string()))
                    }
                }
            },
            PayloadType::Common => {
                match tcp_stream.write_all(&payload.payload).await {
                    Ok(_) => {
                        match tcp_stream.flush().await {
                            Ok(_) => {},
                            Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::WriteError(e.to_string()))
                        }
                        match read_response_timeout(&mut tcp_stream, timeout).await {
                            Ok(res) => {
                                let mut result = ServiceProbeResult::new(port, service_name, res.clone());
                                result.service_detail = Some(String::from_utf8(res).unwrap_or(String::new()).replace("\r\n", ""));
                                return result;
                            },
                            Err(e) => {
                                return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ReadError(e.to_string()))
                            }
                        }
                    },
                    Err(e) => {
                        return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::WriteError(e.to_string()))
                    }
                }
            },
            PayloadType::CommonTls => {
                let native_certs = nex::socket::tls::certs::get_native_certs().unwrap();
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(native_certs)
                    .with_no_client_auth();
                let tcp_stream_inner = match tcp_stream.into_inner() {
                    Ok(tcp_stream_inner) => tcp_stream_inner,
                    Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ConnectionError(e.to_string()))
                };
                match tcp_stream_inner.set_nonblocking(false) {
                    Ok(_) => {},
                    Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ConnectionError(e.to_string()))
                }
                let mut tls_client = match TlsClient::new(hostname.to_string(), tcp_stream_inner, config) {
                    Ok(tls_client) => tls_client,
                    Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ConnectionError(e.to_string()))
                };
                match tls_client.write_all(&payload.payload) {
                    Ok(_) => {
                        match tls_client.flush() {
                            Ok(_) => {},
                            Err(e) => return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::WriteError(e.to_string()))
                        }
                        let mut buf: Vec<u8> = Vec::new();
                        match tls_client.read_to_end(&mut buf) {
                            Ok(_) => {
                                let mut result = ServiceProbeResult::new(port, service_name, buf.clone());
                                result.service_detail = Some(String::from_utf8(buf).unwrap_or(String::new()).to_string());
                                return result;
                            },
                            Err(e) => {
                                return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ReadError(e.to_string()))
                            }
                        }
                    }
                    Err(e) => {
                        return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::WriteError(e.to_string()))
                    }
                }
            },
            PayloadType::Null => {
                match read_response_timeout(&mut tcp_stream, timeout).await {
                    Ok(res) => {
                        let mut result = ServiceProbeResult::new(port, service_name, res.clone());                        
                        result.service_detail = Some(String::from_utf8(res).unwrap_or(String::new()).replace("\r\n", ""));
                        return result;
                    },
                    Err(e) => {
                        return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ReadError(e.to_string()))
                    }
                }
            },
        }
    }else{
        match read_response_timeout(&mut tcp_stream, timeout).await {
            Ok(res) => {
                let mut result = ServiceProbeResult::new(port, service_name, res.clone());
                result.service_detail = Some(String::from_utf8(res).unwrap_or(String::new()).replace("\r\n", ""));
                return result;
            },
            Err(e) => {
                return ServiceProbeResult::with_error(port, service_name, ServiceProbeError::ReadError(e.to_string()))
            }
        }
    }
}

pub async fn run_service_probe(setting: &ServiceProbeSetting, ptx: &Arc<Mutex<Sender<SocketAddr>>>) -> HashMap<u16, ServiceProbeResult> {
    let service_map: Arc<Mutex<HashMap<u16, ServiceProbeResult>>> =
            Arc::new(Mutex::new(HashMap::new()));
    let fut_port = stream::iter(setting.clone().ports).for_each_concurrent(
        setting.concurrent_limit,
        |port| {
            let c_service_map: Arc<Mutex<HashMap<u16, ServiceProbeResult>>> =
                Arc::clone(&service_map);
            async move {
                let ip_addr = setting.ip_addr;
                let hostname = setting.hostname.clone();
                let probe_result: ServiceProbeResult = probe_port(ip_addr, hostname, port, setting.payload_map.get(&port).cloned(), setting.read_timeout).await;
                c_service_map.lock().unwrap().insert(port, probe_result);
                match ptx.lock() {
                    Ok(lr) => match lr.send(SocketAddr::new(ip_addr, port)) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
            }
        },
    );
    fut_port.await;
    let result_map: HashMap<u16, ServiceProbeResult> = service_map.lock().unwrap().clone();
    result_map
}
