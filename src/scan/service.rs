use super::payload::{PayloadInfo, PayloadType};
use super::result::{ServiceProbeError, ServiceProbeResult};
use super::setting::ServiceProbeSetting;
use crate::db::tcp_service::PORT_SERVICE_MAP;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Parse HTTP header and return server name
///
/// The server name possibly contains version number.
fn parse_http_header(res_bytes: &[u8]) -> Option<String> {
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
async fn read_response_timeout<T: AsyncRead + Unpin>(
    stream: &mut T,
    timeout_duration: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    const MAX_RESPONSE_BYTES: usize = 16384;

    loop {
        match tokio::time::timeout(timeout_duration, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() >= MAX_RESPONSE_BYTES {
                    break;
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
    }

    if response.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "No response",
        ))
    } else {
        Ok(response)
    }
}

async fn probe_port(
    ip_addr: IpAddr,
    hostname: String,
    port: u16,
    payload_info: Option<PayloadInfo>,
    connect_timeout: Duration,
    read_timeout: Duration,
    tls_connector: Option<TlsConnector>,
) -> ServiceProbeResult {
    let service_name: String = match PORT_SERVICE_MAP.get(&port) {
        Some(name) => name.to_string(),
        None => String::new(),
    };
    let socket_addr: SocketAddr = SocketAddr::new(ip_addr, port);
    let mut tcp_stream =
        match tokio::time::timeout(connect_timeout, TcpStream::connect(socket_addr)).await {
            Ok(connect_result) => match connect_result {
                Ok(tcp_stream) => tcp_stream,
                Err(e) => {
                    return ServiceProbeResult::with_error(
                        port,
                        service_name,
                        ServiceProbeError::ConnectionError(e.to_string()),
                    )
                }
            },
            Err(elapsed) => {
                return ServiceProbeResult::with_error(
                    port,
                    service_name,
                    ServiceProbeError::ConnectionError(elapsed.to_string()),
                )
            }
        };
    if let Some(payload) = payload_info {
        match payload.payload_type {
            PayloadType::Http => match tcp_stream.write_all(&payload.payload).await {
                Ok(_) => {
                    match tcp_stream.flush().await {
                        Ok(_) => {}
                        Err(e) => {
                            return ServiceProbeResult::with_error(
                                port,
                                service_name,
                                ServiceProbeError::WriteError(e.to_string()),
                            )
                        }
                    }
                    match read_response_timeout(&mut tcp_stream, read_timeout).await {
                        Ok(res) => {
                            let mut result =
                                ServiceProbeResult::new(port, service_name, res.clone());
                            result.service_detail = parse_http_header(&res);
                            return result;
                        }
                        Err(e) => {
                            return ServiceProbeResult::with_error(
                                port,
                                service_name,
                                ServiceProbeError::ReadError(e.to_string()),
                            )
                        }
                    }
                }
                Err(e) => {
                    return ServiceProbeResult::with_error(
                        port,
                        service_name,
                        ServiceProbeError::WriteError(e.to_string()),
                    )
                }
            },
            PayloadType::Https => {
                let Some(tls_connector) = tls_connector.clone() else {
                    return ServiceProbeResult::with_error(
                        port,
                        service_name,
                        ServiceProbeError::TlsError("TLS connector is not available".to_string()),
                    );
                };
                let name = match rustls_pki_types::ServerName::try_from(hostname) {
                    Ok(name) => name,
                    Err(e) => {
                        return ServiceProbeResult::with_error(
                            port,
                            service_name,
                            ServiceProbeError::ConnectionError(e.to_string()),
                        )
                    }
                };
                let mut tls_stream = match tokio::time::timeout(
                    connect_timeout,
                    tls_connector.connect(name, tcp_stream),
                )
                .await
                {
                    Ok(connect_result) => match connect_result {
                        Ok(tls_stream) => tls_stream,
                        Err(e) => {
                            return ServiceProbeResult::with_error(
                                port,
                                service_name,
                                ServiceProbeError::ConnectionError(e.to_string()),
                            )
                        }
                    },
                    Err(elapsed) => {
                        return ServiceProbeResult::with_error(
                            port,
                            service_name,
                            ServiceProbeError::ConnectionError(elapsed.to_string()),
                        )
                    }
                };
                match tls_stream.write_all(&payload.payload).await {
                    Ok(_) => {
                        match tls_stream.flush().await {
                            Ok(_) => {}
                            Err(e) => {
                                return ServiceProbeResult::with_error(
                                    port,
                                    service_name,
                                    ServiceProbeError::WriteError(e.to_string()),
                                )
                            }
                        }
                        match read_response_timeout(&mut tls_stream, read_timeout).await {
                            Ok(buf) => {
                                let mut result =
                                    ServiceProbeResult::new(port, service_name, buf.clone());
                                result.service_detail = parse_http_header(&buf);
                                return result;
                            }
                            Err(e) => {
                                return ServiceProbeResult::with_error(
                                    port,
                                    service_name,
                                    ServiceProbeError::ReadError(e.to_string()),
                                )
                            }
                        }
                    }
                    Err(e) => {
                        return ServiceProbeResult::with_error(
                            port,
                            service_name,
                            ServiceProbeError::WriteError(e.to_string()),
                        )
                    }
                }
            }
            PayloadType::Common => match tcp_stream.write_all(&payload.payload).await {
                Ok(_) => {
                    match tcp_stream.flush().await {
                        Ok(_) => {}
                        Err(e) => {
                            return ServiceProbeResult::with_error(
                                port,
                                service_name,
                                ServiceProbeError::WriteError(e.to_string()),
                            )
                        }
                    }
                    match read_response_timeout(&mut tcp_stream, read_timeout).await {
                        Ok(res) => {
                            let mut result =
                                ServiceProbeResult::new(port, service_name, res.clone());
                            result.service_detail = Some(
                                String::from_utf8(res)
                                    .unwrap_or(String::new())
                                    .replace("\r\n", ""),
                            );
                            return result;
                        }
                        Err(e) => {
                            return ServiceProbeResult::with_error(
                                port,
                                service_name,
                                ServiceProbeError::ReadError(e.to_string()),
                            )
                        }
                    }
                }
                Err(e) => {
                    return ServiceProbeResult::with_error(
                        port,
                        service_name,
                        ServiceProbeError::WriteError(e.to_string()),
                    )
                }
            },
            PayloadType::CommonTls => {
                let Some(tls_connector) = tls_connector.clone() else {
                    return ServiceProbeResult::with_error(
                        port,
                        service_name,
                        ServiceProbeError::TlsError("TLS connector is not available".to_string()),
                    );
                };
                let name = match rustls_pki_types::ServerName::try_from(hostname) {
                    Ok(name) => name,
                    Err(e) => {
                        return ServiceProbeResult::with_error(
                            port,
                            service_name,
                            ServiceProbeError::ConnectionError(e.to_string()),
                        )
                    }
                };
                let mut tls_stream = match tokio::time::timeout(
                    connect_timeout,
                    tls_connector.connect(name, tcp_stream),
                )
                .await
                {
                    Ok(connect_result) => match connect_result {
                        Ok(tls_stream) => tls_stream,
                        Err(e) => {
                            return ServiceProbeResult::with_error(
                                port,
                                service_name,
                                ServiceProbeError::ConnectionError(e.to_string()),
                            )
                        }
                    },
                    Err(elapsed) => {
                        return ServiceProbeResult::with_error(
                            port,
                            service_name,
                            ServiceProbeError::ConnectionError(elapsed.to_string()),
                        )
                    }
                };
                match tls_stream.write_all(&payload.payload).await {
                    Ok(_) => {
                        match tls_stream.flush().await {
                            Ok(_) => {}
                            Err(e) => {
                                return ServiceProbeResult::with_error(
                                    port,
                                    service_name,
                                    ServiceProbeError::WriteError(e.to_string()),
                                )
                            }
                        }
                        match read_response_timeout(&mut tls_stream, read_timeout).await {
                            Ok(buf) => {
                                let mut result =
                                    ServiceProbeResult::new(port, service_name, buf.clone());
                                result.service_detail = Some(
                                    String::from_utf8(buf).unwrap_or(String::new()).to_string(),
                                );
                                return result;
                            }
                            Err(e) => {
                                return ServiceProbeResult::with_error(
                                    port,
                                    service_name,
                                    ServiceProbeError::ReadError(e.to_string()),
                                )
                            }
                        }
                    }
                    Err(e) => {
                        return ServiceProbeResult::with_error(
                            port,
                            service_name,
                            ServiceProbeError::WriteError(e.to_string()),
                        )
                    }
                }
            }
            PayloadType::Null => match read_response_timeout(&mut tcp_stream, read_timeout).await {
                Ok(res) => {
                    let mut result = ServiceProbeResult::new(port, service_name, res.clone());
                    result.service_detail = Some(
                        String::from_utf8(res)
                            .unwrap_or(String::new())
                            .replace("\r\n", ""),
                    );
                    return result;
                }
                Err(e) => {
                    return ServiceProbeResult::with_error(
                        port,
                        service_name,
                        ServiceProbeError::ReadError(e.to_string()),
                    )
                }
            },
        }
    } else {
        match read_response_timeout(&mut tcp_stream, read_timeout).await {
            Ok(res) => {
                let mut result = ServiceProbeResult::new(port, service_name, res.clone());
                result.service_detail = Some(
                    String::from_utf8(res)
                        .unwrap_or(String::new())
                        .replace("\r\n", ""),
                );
                return result;
            }
            Err(e) => {
                return ServiceProbeResult::with_error(
                    port,
                    service_name,
                    ServiceProbeError::ReadError(e.to_string()),
                )
            }
        }
    }
}

pub async fn run_service_probe(
    setting: &ServiceProbeSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> HashMap<u16, ServiceProbeResult> {
    let tls_connector: Option<TlsConnector> = match crate::tls::cert::get_native_certs() {
        Ok(native_certs) => {
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(native_certs)
                .with_no_client_auth();
            Some(TlsConnector::from(Arc::new(config)))
        }
        Err(_) => None,
    };
    let service_map: Arc<Mutex<HashMap<u16, ServiceProbeResult>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let fut_port =
        stream::iter(setting.clone().ports).for_each_concurrent(setting.concurrent_limit, |port| {
            let c_service_map: Arc<Mutex<HashMap<u16, ServiceProbeResult>>> =
                Arc::clone(&service_map);
            let tls_connector = tls_connector.clone();
            async move {
                let ip_addr = setting.ip_addr;
                let hostname = setting.hostname.clone();
                let probe_result: ServiceProbeResult = probe_port(
                    ip_addr,
                    hostname,
                    port,
                    setting.payload_map.get(&port).cloned(),
                    setting.connect_timeout,
                    setting.read_timeout,
                    tls_connector,
                )
                .await;
                c_service_map.lock().unwrap().insert(port, probe_result);
                match ptx.lock() {
                    Ok(lr) => match lr.send(SocketAddr::new(ip_addr, port)) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
            }
        });
    fut_port.await;
    let result_map: HashMap<u16, ServiceProbeResult> = service_map.lock().unwrap().clone();
    result_map
}
