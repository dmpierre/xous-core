//! Error types for the Zcash hardware wallet service.

use core::fmt;
use num_derive::{FromPrimitive, ToPrimitive};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize, FromPrimitive, ToPrimitive,
)]
#[repr(u32)]
pub enum ZcashAppError {
    Success = 0x00,
    RejectedByUser = 0x01,
    InvalidOpcode = 0x02,
    InvalidParameter = 0x03,
    InvalidData = 0x04,
    UnsupportedOperation = 0x05,
    InternalError = 0x06,
    CryptoError = 0x07,
    NoSeed = 0x08,
    InvalidPczt = 0x09,
    SerializationError = 0x0A,
    StorageError = 0x0B,
    UiError = 0x0C,
    /// Host-supplied sighash disagrees with the sighash recomputed locally
    /// from the PCZT. Defense-in-depth: a compromised or buggy host that
    /// disagrees with the device's view of the transaction must fail loudly.
    SighashMismatch = 0x0D,
}

impl ZcashAppError {
    #[inline]
    pub fn code(self) -> u32 {
        self as u32
    }
}

impl Default for ZcashAppError {
    fn default() -> Self {
        ZcashAppError::Success
    }
}

impl fmt::Display for ZcashAppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZcashAppError::Success => write!(f, "Success"),
            ZcashAppError::RejectedByUser => write!(f, "Rejected by user"),
            ZcashAppError::InvalidOpcode => write!(f, "Invalid opcode"),
            ZcashAppError::InvalidParameter => write!(f, "Invalid parameter"),
            ZcashAppError::InvalidData => write!(f, "Invalid data"),
            ZcashAppError::UnsupportedOperation => write!(f, "Unsupported operation"),
            ZcashAppError::InternalError => write!(f, "Internal error"),
            ZcashAppError::CryptoError => write!(f, "Crypto error"),
            ZcashAppError::NoSeed => write!(f, "No seed loaded"),
            ZcashAppError::InvalidPczt => write!(f, "Invalid PCZT"),
            ZcashAppError::SerializationError => write!(f, "Serialization error"),
            ZcashAppError::StorageError => write!(f, "Storage error"),
            ZcashAppError::UiError => write!(f, "UI error"),
            ZcashAppError::SighashMismatch => write!(f, "Sighash mismatch"),
        }
    }
}
