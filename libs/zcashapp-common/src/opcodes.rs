//! Opcodes for the Zcash hardware wallet service.

use num_derive::{FromPrimitive, ToPrimitive};

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum ZcashAppOp {
    // === Configuration (0x90-0x91) ===

    /// Get service configuration and version.
    GetConfig = 0x90,

    /// Initialize or import a seed for ZIP-32 key derivation.
    InitSeed = 0x91,

    // === Key Management (0x92-0x93) ===

    /// Get an Orchard unified address.
    GetOrchardAddress = 0x92,

    /// Export the Orchard full viewing key (for wallet sync).
    GetOrchardFVK = 0x93,

    // === Transaction Signing (0x94-0x95) ===

    /// Sign a PCZT (Partially Created Zcash Transaction).
    SignPczt = 0x94,

    /// Query PCZT signing status (for chunked transfers).
    GetPcztStatus = 0x95,

    // === Seed Management (0xA0-0xA2) ===

    /// Generate a new BIP39 mnemonic.
    GenerateMnemonic = 0xA0,

    /// Import a BIP39 mnemonic phrase.
    ImportMnemonic = 0xA1,

    /// Clear the seed from memory.
    ClearSeed = 0xA2,

    // === Serial Transport (0x70) ===

    /// Process a raw serial frame from the host CLI.
    SerialFrame = 0x70,

    // === Internal (0xF0-0xFF) ===

    /// Ping for health check.
    Ping = 0xFF,
}
