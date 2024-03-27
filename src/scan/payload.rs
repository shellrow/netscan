/// Payloads for service detection
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadType {
    /// No payload. Just open TCP connection and read response.
    Null,
    /// HTTP request
    Http,
    /// HTTPS request
    Https,
    /// Common payload. Write payload and read response.
    Common,
    /// Common payload for TLS. Write payload and read response with TLS.
    CommonTls,
}

/// Payload information for service detection
#[derive(Clone, Debug, PartialEq)]
pub struct PayloadInfo {
    pub payload: Vec<u8>,
    pub payload_type: PayloadType,
}

/// Payload builder for service detection
#[derive(Clone, Debug)]
pub struct PayloadBuilder {
    payload_info: PayloadInfo,
}

impl PayloadBuilder {
    /// Create new PayloadBuilder
    pub fn new() -> Self {
        PayloadBuilder {
            payload_info: PayloadInfo {
                payload: vec![],
                payload_type: PayloadType::Common,
            },
        }
    }
    /// Create new PayloadBuilder for TLS
    pub fn new_tls() -> Self {
        PayloadBuilder {
            payload_info: PayloadInfo {
                payload: vec![],
                payload_type: PayloadType::CommonTls,
            },
        }
    }
    /// Add byte to payload
    pub fn add_byte(&mut self, byte: u8) -> &mut Self {
        self.payload_info.payload.push(byte);
        self
    }
    /// Add bytes to payload
    pub fn add_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.payload_info.payload.extend_from_slice(bytes);
        self
    }
    /// Add bytes (from string) to payload
    pub fn add_str(&mut self, s: &str) -> &mut Self {
        self.payload_info.payload.extend_from_slice(s.as_bytes());
        self
    }
    /// Enable/Diable TLS
    pub fn set_tls(&mut self, tls_enabled: bool) -> &mut Self {
        if tls_enabled {
            self.payload_info.payload_type = PayloadType::CommonTls;
        } else {
            self.payload_info.payload_type = PayloadType::Common;
        }
        self
    }
    /// Return payload as Vec<u8>
    pub fn bytes(self) -> Vec<u8> {
        self.payload_info.payload
    }
    /// Return payload as PayloadInfo
    pub fn payload(self) -> PayloadInfo {
        self.payload_info
    }
    /* pub fn null() -> PayloadInfo {
        PayloadInfo {
            payload: vec![0x00],
            payload_type: PayloadType::Null,
        }
    } */
    /// Create a new PayloadInfo with a generic line
    pub fn generic_line() -> PayloadInfo {
        PayloadInfo {
            payload: "\r\n\r\n".as_bytes().to_vec(),
            payload_type: PayloadType::Common,
        }
    }
    /// Create a new PayloadInfo with a generic line for TLS
    pub fn generic_line_tls() -> PayloadInfo {
        PayloadInfo {
            payload: "\r\n\r\n".as_bytes().to_vec(),
            payload_type: PayloadType::CommonTls,
        }
    }
    /// Create a new PayloadInfo with a hello message
    pub fn hello() -> PayloadInfo {
        PayloadInfo {
            payload: "EHLO\r\n".as_bytes().to_vec(),
            payload_type: PayloadType::Common,
        }
    }
    /// Create a new PayloadInfo with a hello message for TLS
    pub fn hello_tls() -> PayloadInfo {
        PayloadInfo {
            payload: "EHLO\r\n".as_bytes().to_vec(),
            payload_type: PayloadType::CommonTls,
        }
    }
    /// Create a new PayloadInfo with a HTTP head request
    pub fn http_head() -> PayloadInfo {
        PayloadInfo {
            payload: "HEAD / HTTP/1.0\r\n\r\n".as_bytes().to_vec(),
            payload_type: PayloadType::Http,
        }
    }
    /// Create a new PayloadInfo with a HTTPS head request
    pub fn https_head(hostname: &str) -> PayloadInfo {
        let req: String = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            hostname
        );
        PayloadInfo {
            payload: req.into_bytes(),
            payload_type: PayloadType::Https,
        }
    }
    /// Create a new PayloadInfo with a HTTP get request
    pub fn http_get(path: &str) -> PayloadInfo {
        let req = format!("GET {} HTTP/1.1\r\nHost: example.com\r\n\r\n", path);
        PayloadInfo {
            payload: req.into_bytes(),
            payload_type: PayloadType::Http,
        }
    }
    /// Create a new PayloadInfo with a HTTPS get request
    pub fn https_get(path: &str, hostname: &str) -> PayloadInfo {
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            path, hostname
        );
        PayloadInfo {
            payload: req.into_bytes(),
            payload_type: PayloadType::Https,
        }
    }
    /* pub fn ftp_user(username: &str) -> PayloadInfo {
        let req = format!("USER {}\r\n", username);
        PayloadInfo {
            payload: req.into_bytes(),
            payload_type: PayloadType::Common,
        }
    } */
    /* pub fn smtp_ehlo() -> PayloadInfo {
        PayloadInfo {
            payload: "EHLO example.com\r\n".as_bytes().to_vec(),
            payload_type: PayloadType::Common,
        }
    } */
    /* pub fn tls_1_1_session_request() -> PayloadInfo {
        PayloadInfo {
            payload: vec![
                0x16, 0x03, 0x02, // Content Type: Handshake (22), Version: TLS 1.1 (0x0302)
                0x00, 0x01, 0xfc, 0x01, 0x00, 0x00, 0xf8, // Length: 1 byte, Handshake Type: Session Request (0x00)
            ],
            payload_type: PayloadType::CommonTls,
        }
    } */
    /* pub fn tls_1_2_session_request() -> PayloadInfo {
        PayloadInfo {
            payload: vec![
                0x16, 0x03, 0x03, // Content Type: Handshake (22), Version: TLS 1.2 (0x0303)
                0x00, 0x01, 0xfc, 0x01, 0x00, 0x00, 0xf8, // Length: 1 byte, Handshake Type: Session Request (0x00)
            ],
            payload_type: PayloadType::CommonTls,
        }
    } */
    /* pub fn tls_1_3_session_request() -> PayloadInfo {
        PayloadInfo {
            payload: vec![
                0x16, 0x03, 0x04, // Content Type: Handshake (22), Version: TLS 1.3 (0x0304)
                0x00, 0x01, 0xfc, 0x01, 0x00, 0x00, 0xf8, // Length: 1 byte, Handshake Type: Session Request (0x00)
            ],
            payload_type: PayloadType::CommonTls,
        }
    } */
    /* pub fn ssh_public_key_request(username: &str) -> PayloadInfo {
        let payload = format!("{}\0ssh-connection\0\0\0\0\0\0\0\0\0\0\0\0\0\0", username);
        PayloadInfo {
            payload: payload.as_bytes().to_vec(),
            payload_type: PayloadType::Common,
        }
    } */
}
