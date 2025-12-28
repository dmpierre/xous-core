//! API-level error types for the client library.
//!
//! These errors wrap both IPC-level failures and service-level errors,
//! providing a unified error type for client code.

use alloc::string::String;
use core::fmt;

use ethapp_common::EthAppError;

/// Errors that can occur when using the ethapp API client.
#[derive(Debug, Clone)]
pub enum ApiError {
    /// Failed to connect to the ethapp service.
    ConnectionFailed(String),

    /// Service returned an error.
    ServiceError(EthAppError),

    /// Failed to serialize request data.
    SerializationFailed(String),

    /// Failed to deserialize response data.
    DeserializationFailed(String),

    /// IPC operation failed.
    IpcFailed(String),

    /// Request timed out.
    Timeout,

    /// Invalid response from service.
    InvalidResponse(String),

    /// Service is not available.
    ServiceUnavailable,
}

impl ApiError {
    /// Returns true if this error indicates the user rejected the operation.
    #[inline]
    pub fn is_user_rejection(&self) -> bool {
        matches!(
            self,
            ApiError::ServiceError(EthAppError::RejectedByUser)
        )
    }

    /// Returns true if this is a security-related error.
    #[inline]
    pub fn is_security_error(&self) -> bool {
        match self {
            ApiError::ServiceError(e) => e.is_security_error(),
            _ => false,
        }
    }

    /// Returns the underlying service error, if any.
    pub fn service_error(&self) -> Option<EthAppError> {
        match self {
            ApiError::ServiceError(e) => Some(*e),
            _ => None,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            ApiError::ServiceError(e) => write!(f, "Service error: {}", e),
            ApiError::SerializationFailed(msg) => write!(f, "Serialization failed: {}", msg),
            ApiError::DeserializationFailed(msg) => write!(f, "Deserialization failed: {}", msg),
            ApiError::IpcFailed(msg) => write!(f, "IPC failed: {}", msg),
            ApiError::Timeout => write!(f, "Request timed out"),
            ApiError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            ApiError::ServiceUnavailable => write!(f, "Service unavailable"),
        }
    }
}

impl From<EthAppError> for ApiError {
    fn from(e: EthAppError) -> Self {
        ApiError::ServiceError(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
