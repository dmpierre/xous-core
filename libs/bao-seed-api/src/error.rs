//! Client-side errors for the bao-seed API.

use alloc::string::String;

use bao_seed_common::BaoSeedError;

extern crate alloc;

#[derive(Debug, Clone)]
pub enum ApiError {
    /// Could not connect to the bao-seed service.
    ConnectionFailed(String),
    /// Service returned a typed `BaoSeedError`.
    Service(BaoSeedError),
    /// Serialization or memory-message setup failed.
    SerializationFailed(String),
    /// Generic IPC failure (xous syscall).
    Ipc(String),
    /// Response payload was malformed or had unexpected shape.
    InvalidResponse(String),
}

impl core::fmt::Display for ApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApiError::ConnectionFailed(s) => write!(f, "connection failed: {}", s),
            ApiError::Service(e) => write!(f, "bao-seed: {}", e),
            ApiError::SerializationFailed(s) => write!(f, "serialization: {}", s),
            ApiError::Ipc(s) => write!(f, "ipc: {}", s),
            ApiError::InvalidResponse(s) => write!(f, "invalid response: {}", s),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ApiError {}

impl From<BaoSeedError> for ApiError {
    fn from(e: BaoSeedError) -> Self {
        ApiError::Service(e)
    }
}
