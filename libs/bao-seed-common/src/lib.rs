//! Shared types for the bao-seed Xous service.
//!
//! bao-seed is the device's seed vault: it owns the BIP-39 seed bytes
//! and exposes a typed IPC API for derivation and signing (Pattern A —
//! sign-inside-vault, like Ledger BOLOS and KeyOS gui-app-seed-vault).
//!
//! This crate defines only types that cross the IPC boundary. The
//! `Seed` newtype and any derived private-key material live inside
//! the service and never appear here.
//!
//! ## Boundary discipline
//!
//! Things that MAY cross the boundary, by design:
//!
//! - Mnemonic words at generation time (one-time export so the user
//!   can write them down) and at import time (one-time entry).
//! - Fingerprints / pubkey-derived identifiers.
//! - Signatures (PR 2+).
//!
//! Things that MUST NEVER cross the boundary:
//!
//! - Raw seed bytes.
//! - Derived private keys.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod error;
pub mod opcodes;
pub mod types;

pub use error::*;
pub use opcodes::*;
pub use types::*;

/// Xous nameserver registration string for the bao-seed service.
pub const SERVER_NAME: &str = "_bao_seed_";

/// Protocol version exposed by `Status` responses.
///
/// Bump on any backwards-incompatible IPC change.
pub const PROTOCOL_VERSION: u32 = 1;
