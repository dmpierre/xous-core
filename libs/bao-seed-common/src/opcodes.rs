//! Message opcodes for the bao-seed Xous service.
//!
//! Each opcode corresponds to one operation on the seed vault.
//!
//! Layout reserves blocks of 16 IDs per concern so future curves
//! (secp256k1, Pallas, Ed25519, …) and management ops (PIN, passphrase,
//! multi-seed) can be added without renumbering.

use num_derive::{FromPrimitive, ToPrimitive};

/// Operation codes for bao-seed service messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum BaoSeedOp {
    // === Lifecycle (0x01–0x0F) ===

    /// Get protocol/version info plus seed presence.
    /// Returns: `StatusResponse` via memory message.
    Status = 0x01,

    /// Cheap presence check.
    /// Returns: scalar `(error_code, has_seed)` where has_seed is 0 or 1.
    HasSeed = 0x02,

    /// Generate a new seed from hardware TRNG.
    /// Input: `GenerateRequest` via memory message.
    /// Returns: `GenerateResponse` via memory message (mnemonic words,
    /// fingerprint). Mnemonic is one-time export — caller is
    /// responsible for showing it to the user and then dropping it.
    Generate = 0x03,

    /// Import an existing BIP-39 mnemonic.
    /// Input: `ImportRequest` via memory message.
    /// Returns: `ImportResponse` via memory message (fingerprint).
    Import = 0x04,

    /// Wipe the current seed from RAM and persistent storage.
    /// Returns: scalar `(error_code, 0)`.
    Wipe = 0x05,

    /// Compute the ZIP-32 SeedFingerprint (32 bytes) over the loaded
    /// seed. This is the canonical identifier Zcash companion wallets
    /// use to match keys to a wallet — distinct from the 4-byte vault
    /// fingerprint in `StatusResponse`. Coin-agnostic but named after
    /// the ZIP-32 spec where it's defined.
    /// Input: empty memory message (placeholder).
    /// Output: `LifecycleResult<Zip32SeedFingerprintBytes>`.
    Zip32SeedFingerprint = 0x06,

    /// Import a raw 64-byte master seed, bypassing BIP-39 derivation.
    /// Used by callers that already hold the derived seed (encrypted-
    /// import / dev injection). Refuses if a seed is already loaded.
    /// Input: `ImportSeedBytesRequest` via memory message.
    /// Output: `LifecycleResult<ImportResponse>` (same fingerprint
    /// shape as the mnemonic Import).
    ImportSeedBytes = 0x07,

    // === secp256k1 (0x10–0x1F) — PR 2 ===

    /// Get the compressed public key for a BIP-32 path.
    /// Input: `Secp256k1PubkeyRequest`. Output: `LifecycleResult<CompressedPubkey>`.
    Secp256k1GetPubkey = 0x10,

    /// Sign a 32-byte hash with the key at a BIP-32 path.
    /// Input: `Secp256k1SignRequest`. Output: `LifecycleResult<Secp256k1Signature>`.
    Secp256k1Sign = 0x11,

    // === Orchard / Pallas (0x20–0x2F) — PR 3 ===

    /// Get the 96-byte Orchard FullViewingKey for (coin_type, account).
    /// Input: `OrchardFvkRequest`. Output: `LifecycleResult<OrchardFvkBytes>`.
    OrchardGetFvk = 0x20,

    /// Sign a batch of Orchard actions with the spend-auth key for
    /// (coin_type, account). Each action provides its alpha scalar and
    /// expected rk; bao-seed signs only the actions whose derived rk
    /// matches, returning `None` for the rest.
    /// Input: `OrchardSignRequest`. Output: `LifecycleResult<OrchardSignResponse>`.
    OrchardSign = 0x21,

    // === Management (0x80–0x8F) — future ===
    //
    // PIN, passphrase, multi-seed, BIP-85 child seeds, etc.

    /// Sentinel for "disconnect" sent by the client on drop.
    /// Not a real opcode; opcode 0 is reserved.
    Disconnect = 0x00,
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{FromPrimitive, ToPrimitive};

    const ALL_OPS: &[BaoSeedOp] = &[
        BaoSeedOp::Status,
        BaoSeedOp::HasSeed,
        BaoSeedOp::Generate,
        BaoSeedOp::Import,
        BaoSeedOp::Wipe,
        BaoSeedOp::Zip32SeedFingerprint,
        BaoSeedOp::ImportSeedBytes,
        BaoSeedOp::Secp256k1GetPubkey,
        BaoSeedOp::Secp256k1Sign,
        BaoSeedOp::OrchardGetFvk,
        BaoSeedOp::OrchardSign,
    ];

    #[test]
    fn opcodes_roundtrip_through_u32() {
        for &op in ALL_OPS {
            let n = op.to_u32().unwrap();
            let back = BaoSeedOp::from_u32(n).unwrap();
            assert_eq!(op, back);
        }
    }

    #[test]
    fn opcodes_are_distinct() {
        // Cheap protection against accidental duplicate IDs.
        let ids: alloc::vec::Vec<u32> = ALL_OPS.iter().map(|op| op.to_u32().unwrap()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len(), "opcode IDs are not distinct");
    }
}
