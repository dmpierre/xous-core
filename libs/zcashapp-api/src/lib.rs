//! Client API for the Zcash hardware wallet service.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

mod client;

pub use client::ZcashAppClient;
pub use zcashapp_common::{ZcashAppError, ZcashAppOp};
