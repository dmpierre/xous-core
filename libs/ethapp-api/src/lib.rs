//! Client library for the Xous Ethereum App service.
//!
//! This crate provides a type-safe API for other Xous processes to interact
//! with the ethapp service via message-passing IPC.
//!
//! # Example
//!
//! ```ignore
//! use ethapp_api::EthAppClient;
//! use ethapp_common::{Bip32Path, SignTransactionRequest};
//!
//! let client = EthAppClient::new()?;
//!
//! // Get address for derivation path
//! let path = Bip32Path::ethereum(0, 0, 0);
//! let address = client.get_address(&path)?;
//!
//! // Sign a transaction
//! let request = SignTransactionRequest {
//!     path,
//!     tx_data: rlp_encoded_tx,
//! };
//! let signature = client.sign_transaction(&request)?;
//! ```
//!
//! # Security
//!
//! - All requests go through the secure ethapp service
//! - Keys never leave the service process
//! - User confirmation is required for signing operations
//!
//! # Thread Safety
//!
//! `EthAppClient` maintains a connection ID and is not `Send`/`Sync`.
//! Each thread should create its own client instance.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod client;
mod error;

pub use client::EthAppClient;
pub use error::ApiError;

// Re-export common types for convenience
pub use ethapp_common::{
    AppConfiguration, Bip32Path, ChunkFlags, ChunkHeader, DomainInfo, EthAddress, EthAppError,
    EthAppOp, Hash256, MethodInfo, NftInfo, PublicKeyResponse, Selector, Signature,
    SignEip712HashedRequest, SignEip712MessageRequest, SignPersonalMessageRequest,
    SignTransactionRequest, ClearSignTransactionRequest, TokenInfo, TransactionType,
    ProvideTokenInfoRequest, ProvideNftInfoRequest, ProvideDomainNameRequest,
    ProvideMethodInfoRequest,
};
