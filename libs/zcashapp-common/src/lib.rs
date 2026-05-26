//! Common types and opcodes for the Zcash hardware wallet service.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

mod error;
mod opcodes;

pub use error::ZcashAppError;
pub use opcodes::ZcashAppOp;

/// Server name for xous-names registration.
pub const SERVER_NAME: &str = "zcashapp.zcash";

/// Protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum serial frame payload size (bytes).
///
/// Must accommodate the largest PCZT we expect to handle, plus the 4-byte
/// account field and 32-byte sighash that precede the PCZT bytes.
/// A typical 2-action Orchard PCZT is ~12 KB; allow up to 64 KB to cover
/// multi-action transactions and future growth.  The wire protocol uses a
/// u16 length field, so 65 535 is the absolute ceiling.
pub const MAX_FRAME_SIZE: usize = 65535;

/// Serial frame data for IPC between usb-bao1x and zcashapp.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct SerialFrameData {
    pub data: alloc::vec::Vec<u8>,
}
