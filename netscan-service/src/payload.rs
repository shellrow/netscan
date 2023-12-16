#[derive(Clone, Debug)]
pub enum PayloadType {
    NULL,
    LINE,
    TLS,
    HTTP,
    HTTPS,
    FTP,
    SMTP
}

#[derive(Clone, Debug)]
pub struct PayloadInfo {
    pub payload: Vec<u8>,
    pub payload_type: PayloadType,
}

pub struct PayloadBuilder {
    payload: Vec<u8>,
}

impl PayloadBuilder {
    pub fn new() -> Self {
        PayloadBuilder { payload: Vec::new() }
    }

    pub fn add_byte(&mut self, byte: u8) -> &mut Self {
        self.payload.push(byte);
        self
    }

    pub fn add_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.payload.extend_from_slice(bytes);
        self
    }

    pub fn add_str(&mut self, s: &str) -> &mut Self {
        self.payload.extend_from_slice(s.as_bytes());
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.payload
    }

    pub fn null() -> Vec<u8> {
        vec![0x00]
    }

    pub fn newline() -> Vec<u8> {
        "\r\n".as_bytes().to_vec()
    }

    pub fn http_head() -> Vec<u8> {
        let req = format!("HEAD / HTTP/1.0\r\n\r\n");
        req.into_bytes()
    }

    pub fn https_head(hostname: String) -> Vec<u8> {
        let req: String = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            hostname
        );
        req.into_bytes()
    }

    pub fn http_get(path: &str) -> Vec<u8> {
        let req = format!("GET {} HTTP/1.1\r\nHost: example.com\r\n\r\n", path);
        req.into_bytes()
    }
    
    pub fn https_get(path: &str, hostname: &str) -> Vec<u8> {
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            path, hostname
        );
        req.into_bytes()
    }

    pub fn ftp_anonymous() -> Vec<u8> {
        "USER anonymous\r\n".as_bytes().to_vec()
    }

    pub fn smtp_ehlo() -> Vec<u8> {
        "EHLO example.com\r\n".as_bytes().to_vec()
    }
}