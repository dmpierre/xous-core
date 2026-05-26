//! Request and response types crossing the bao-seed IPC boundary.
//!
//! Discipline: NO secret material in this file. The closest thing is
//! `MnemonicWords`, which is only exchanged during one-time
//! Generate-and-show or Import-from-user flows; it is zeroized on
//! drop and callers MUST not retain it.

use alloc::string::String;
use alloc::vec::Vec;
use rkyv::{Archive, Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::BaoSeedError;
use crate::PROTOCOL_VERSION;

// ---- Fingerprint ------------------------------------------------------------

/// 4-byte fingerprint identifying a seed.
///
/// The exact construction is bao-seed-internal (per BIP-32 root xpub
/// hash or equivalent). Callers should treat this as an opaque
/// 32-bit tag.
pub type Fingerprint = [u8; 4];

/// 32-byte ZIP-32 SeedFingerprint (BLAKE2b-256 of the seed with the
/// "Zcash_HD_Seed_FP" personalization). Canonical identifier Zcash
/// companion wallets use to match keys to a wallet. Defined in
/// ZIP-32 but coin-agnostic at this layer.
pub type Zip32SeedFingerprintBytes = [u8; 32];

// ---- Mnemonic ---------------------------------------------------------------

/// BIP-39 word counts we support.
pub const VALID_WORD_COUNTS: &[usize] = &[12, 15, 18, 21, 24];

/// Mnemonic words crossing the IPC boundary.
///
/// Zeroized on drop. Callers MUST treat this as secret material and
/// not retain copies. Used only at generation (vault → caller, one-time
/// export so the user can write them down) and at import (caller →
/// vault, one-time entry).
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MnemonicWords(pub Vec<String>);

impl MnemonicWords {
    /// Build from a `Vec<String>`, validating the word count.
    pub fn new(words: Vec<String>) -> Result<Self, BaoSeedError> {
        if !VALID_WORD_COUNTS.contains(&words.len()) {
            return Err(BaoSeedError::InvalidMnemonicLength);
        }
        Ok(Self(words))
    }

    /// Borrow the inner slice. Callers MUST NOT retain.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Word count.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if zero words (never valid in practice).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---- Generate ---------------------------------------------------------------

/// Request to generate a new seed.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct GenerateRequest {
    /// Number of mnemonic words to produce. Must be in `VALID_WORD_COUNTS`.
    pub word_count: u8,
}

impl Default for GenerateRequest {
    fn default() -> Self {
        Self { word_count: 24 }
    }
}

/// Response from `Generate`.
///
/// `words` is a one-time export. Callers must show it to the user and
/// then drop it. There is no replay — the seed is now stored; the
/// only way to recover the mnemonic is from the user's written-down
/// copy.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct GenerateResponse {
    pub words: MnemonicWords,
    pub fingerprint: Fingerprint,
}

// ---- Import -----------------------------------------------------------------

/// Request to import an existing BIP-39 mnemonic.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct ImportRequest {
    pub words: MnemonicWords,
}

/// Response from `Import`.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct ImportResponse {
    pub fingerprint: Fingerprint,
}

/// Request to import a raw 64-byte master seed (post-BIP-39, or
/// produced by encrypted-import / dev injection flows).
///
/// Zeroized on drop. This skips the BIP-39 PBKDF2 step — callers
/// already hold the derived seed.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ImportSeedBytesRequest {
    pub seed: [u8; 64],
}

// ---- Status -----------------------------------------------------------------

/// Wrapper for memory-message responses that may carry either a typed
/// success payload or a `BaoSeedError` code.
///
/// Used by `Generate` and `Import` to keep the response shape uniform
/// across success and failure.
#[derive(Clone, Debug, Archive, Serialize, Deserialize)]
pub enum LifecycleResult<T> {
    Ok(T),
    /// Carries `BaoSeedError as u32`.
    Err(u32),
}

// ---- secp256k1 ----------------------------------------------------------

/// BIP-32 hardened-index marker (bit 31). A path component with this
/// bit set indicates a hardened derivation step.
pub const HARDENED: u32 = 0x80000000;

/// Compressed SEC1 secp256k1 public key (0x02 / 0x03 prefix + 32 bytes).
pub type CompressedPubkey = [u8; 33];

/// ECDSA signature over secp256k1 with Ethereum-style recovery byte.
///
/// `recovery_id` is 0 or 1; Ethereum's `v` is then computed by the
/// caller (legacy: `v = 27 + recovery_id` or `35 + chain_id*2 +
/// recovery_id` for EIP-155; typed txs use `recovery_id` directly).
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct Secp256k1Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

/// Request to derive the compressed pubkey for a BIP-32 path.
///
/// `path` is the standard BIP-32 component list — each `u32` is either
/// an index (low 31 bits) or hardened (bit 31 set). For example, the
/// Ethereum default account is `[44 | HARDENED, 60 | HARDENED,
/// 0 | HARDENED, 0, 0]`.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct Secp256k1PubkeyRequest {
    pub path: alloc::vec::Vec<u32>,
}

/// Request to sign a 32-byte digest with the key at a BIP-32 path.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct Secp256k1SignRequest {
    pub path: alloc::vec::Vec<u32>,
    pub hash: [u8; 32],
}

// ---- Orchard / Pallas (Zcash) ----------------------------------------------

/// Serialized 96-byte Orchard FullViewingKey.
pub type OrchardFvkBytes = [u8; 96];

/// Per-action input for Orchard signing: the random scalar (alpha) and
/// the expected randomized verification key (rk).
///
/// bao-seed signs only when the rk derived from `(ask.randomize(alpha))`
/// matches `rk` — otherwise the action is not from this wallet and a
/// `None` is returned at that index.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct OrchardActionInput {
    pub alpha: [u8; 32],
    pub rk: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct OrchardFvkRequest {
    pub coin_type: u32,
    pub account: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct OrchardSignRequest {
    pub coin_type: u32,
    pub account: u32,
    pub sighash: [u8; 32],
    pub actions: alloc::vec::Vec<OrchardActionInput>,
}

/// One Vec entry per request action. `None` ⇒ the action's rk didn't
/// match the derived rk for this wallet, so we did not sign it.
pub type OrchardSignResponse = alloc::vec::Vec<Option<[u8; 64]>>;

// ---- Status / lifecycle ----------------------------------------------------

/// Status query response (no input parameters).
#[derive(Clone, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct StatusResponse {
    pub protocol_version: u32,
    pub has_seed: bool,
    pub fingerprint: Option<Fingerprint>,
}

impl StatusResponse {
    pub fn empty() -> Self {
        Self { protocol_version: PROTOCOL_VERSION, has_seed: false, fingerprint: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_words_rejects_bad_counts() {
        for bad in &[0usize, 1, 11, 13, 14, 16, 17, 23, 25, 100] {
            let v: Vec<String> = (0..*bad).map(|_| String::from("word")).collect();
            assert!(
                MnemonicWords::new(v).is_err(),
                "{} words should be rejected",
                bad
            );
        }
    }

    #[test]
    fn mnemonic_words_accepts_valid_counts() {
        for good in VALID_WORD_COUNTS {
            let v: Vec<String> = (0..*good).map(|_| String::from("word")).collect();
            let m = MnemonicWords::new(v).expect("should accept valid count");
            assert_eq!(m.len(), *good);
        }
    }

    #[test]
    fn generate_request_default_is_24_words() {
        let r = GenerateRequest::default();
        assert_eq!(r.word_count, 24);
        assert!(VALID_WORD_COUNTS.contains(&(r.word_count as usize)));
    }

    #[test]
    fn status_empty_has_no_seed() {
        let s = StatusResponse::empty();
        assert!(!s.has_seed);
        assert!(s.fingerprint.is_none());
        assert_eq!(s.protocol_version, PROTOCOL_VERSION);
    }
}
