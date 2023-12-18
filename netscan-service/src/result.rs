/// Result of a service probe
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceProbeResult {
    pub port: u16,
    pub service_name: String,
    pub service_detail: Option<String>,
    pub response: Vec<u8>,
    pub error: Option<ServiceProbeError>,
}

impl ServiceProbeResult {
    /// Create a new successful probe result
    pub fn new(port: u16, service_name: String, response: Vec<u8>) -> Self {
        ServiceProbeResult {
            port,
            service_name,
            service_detail: None,
            response,
            error: None,
        }
    }

    /// Create a new probe result with an error
    pub fn with_error(port: u16, service_name: String, error: ServiceProbeError) -> Self {
        ServiceProbeResult {
            port,
            service_name,
            service_detail: None,
            response: Vec::new(),
            error: Some(error),
        }
    }

    /// Check if the result contains an error
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get a reference to the contained error, if any
    pub fn error(&self) -> Option<&ServiceProbeError> {
        self.error.as_ref()
    }

    /// Extract the error, consuming the result
    pub fn into_error(self) -> Option<ServiceProbeError> {
        self.error
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ServiceProbeError {
    ConnectionError(String),
    WriteError(String),
    ReadError(String),
    TlsError(String),
    CustomError(String),
}
