//! Client library for the bao-seed Xous service.
//!
//! PR 1 contains lifecycle opcodes only. Signing and derivation APIs
//! land in PR 2 (secp256k1 + ethapp migration) and PR 3 (Orchard +
//! zcashapp migration).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod client;
pub mod error;

pub use client::BaoSeedClient;
pub use error::ApiError;

// Re-export commonly used types so callers don't need to depend on
// bao-seed-common directly.
pub use bao_seed_common::{
    BaoSeedError, BaoSeedOp, CompressedPubkey, Fingerprint, GenerateRequest, GenerateResponse,
    ImportRequest, ImportResponse, MnemonicWords, OrchardActionInput, OrchardFvkBytes,
    OrchardFvkRequest, OrchardSignRequest, OrchardSignResponse, Secp256k1PubkeyRequest,
    Secp256k1SignRequest, Secp256k1Signature, StatusResponse, HARDENED, PROTOCOL_VERSION,
    SERVER_NAME, VALID_WORD_COUNTS,
};
