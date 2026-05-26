//! Error type for bao-seed IPC responses.

use num_derive::{FromPrimitive, ToPrimitive};

/// Errors that can be returned from bao-seed operations.
///
/// Encoded as `u32` for transport over `xous::Message::Scalar` paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum BaoSeedError {
    /// Operation succeeded. Reserved for the rare cases where an
    /// "error" slot also needs to carry the OK signal (e.g. scalar
    /// returns that pack status + data).
    Ok = 0,

    /// No seed is currently loaded; operation requires one.
    NoSeed = 1,

    /// A seed is already loaded; operation requires no seed
    /// (e.g. Import or Generate without first Wipe).
    SeedAlreadyLoaded = 2,

    /// Provided mnemonic failed BIP-39 word/checksum validation.
    InvalidMnemonic = 3,

    /// Provided word count is not 12, 15, 18, 21, or 24.
    InvalidMnemonicLength = 4,

    /// Hardware TRNG failure (entropy source unavailable).
    TrngError = 5,

    /// Persistent storage operation failed.
    StorageError = 6,

    /// Memory message could not be decoded.
    InvalidRequest = 7,

    /// Internal crypto error (PBKDF2, HMAC, etc.).
    CryptoError = 8,

    /// Generic catch-all for currently-unenumerated faults.
    Internal = 9,
}

impl core::fmt::Display for BaoSeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            BaoSeedError::Ok => "ok",
            BaoSeedError::NoSeed => "no seed loaded",
            BaoSeedError::SeedAlreadyLoaded => "seed already loaded",
            BaoSeedError::InvalidMnemonic => "invalid mnemonic",
            BaoSeedError::InvalidMnemonicLength => "invalid mnemonic length",
            BaoSeedError::TrngError => "trng error",
            BaoSeedError::StorageError => "storage error",
            BaoSeedError::InvalidRequest => "invalid request",
            BaoSeedError::CryptoError => "crypto error",
            BaoSeedError::Internal => "internal error",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BaoSeedError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use num_traits::{FromPrimitive, ToPrimitive};

    #[test]
    fn error_roundtrips_through_u32() {
        for &e in &[
            BaoSeedError::Ok,
            BaoSeedError::NoSeed,
            BaoSeedError::SeedAlreadyLoaded,
            BaoSeedError::InvalidMnemonic,
            BaoSeedError::InvalidMnemonicLength,
            BaoSeedError::TrngError,
            BaoSeedError::StorageError,
            BaoSeedError::InvalidRequest,
            BaoSeedError::CryptoError,
            BaoSeedError::Internal,
        ] {
            let n = e.to_u32().unwrap();
            let back = BaoSeedError::from_u32(n).unwrap();
            assert_eq!(e, back);
        }
    }

    #[test]
    fn display_is_non_empty() {
        // Cheap smoke test: every variant must produce a non-empty string.
        for &e in &[BaoSeedError::Ok, BaoSeedError::NoSeed, BaoSeedError::Internal] {
            assert!(!format!("{}", e).is_empty());
        }
    }
}
