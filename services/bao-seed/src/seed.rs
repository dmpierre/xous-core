//! Seed module — BIP-39 derivation and the `Seed` newtype.
//!
//! The `Seed` type and the 64-byte BIP-39 derived bytes NEVER leave
//! this service. Everything in this module is internal to bao-seed.
//!
//! ## Operations
//!
//! - `seed_from_mnemonic(mnemonic_bytes) -> Seed`
//!   PBKDF2-HMAC-SHA512, 2048 rounds, salt = "mnemonic" (BIP-39 with
//!   empty passphrase). Matches the existing ethapp and zcashapp
//!   implementations bit-for-bit; backed by the `pbkdf2` crate.
//!
//! - `generate_mnemonic(entropy) -> (MnemonicWords, Seed)`
//!   Converts 16/20/24/28/32 bytes of caller-provided entropy into a
//!   BIP-39 mnemonic and derives the seed in one shot. The entropy
//!   buffer is zeroized on success.
//!
//! - `fingerprint(seed) -> Fingerprint`
//!   Stable 4-byte vault-internal identifier (SHA-256(seed)[..4]).
//!   NOT the BIP-32 root fingerprint — coin apps that want the
//!   BIP-32 fingerprint compute it from a pubkey returned by
//!   `Secp256k1GetPubkey` (PR 2).

use alloc::string::String;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use bao_seed_common::{BaoSeedError, Fingerprint, MnemonicWords};

extern crate alloc;

/// The 64-byte BIP-39-derived seed.
///
/// Internal to bao-seed. Zeroized on drop. Never crosses the IPC
/// boundary.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 64]);

impl Seed {
    /// Build from a 64-byte array.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(*bytes)
    }

    /// Build from a slice, validating length.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Borrow the inner bytes. Caller MUST NOT clone or retain.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Derive a 64-byte BIP-39 seed from a mnemonic via PBKDF2-HMAC-SHA512.
///
/// Matches BIP-39 exactly with an empty passphrase: salt = "mnemonic",
/// 2048 iterations, SHA-512 PRF, 64-byte output.
pub fn seed_from_mnemonic(mnemonic: &[u8]) -> Seed {
    use hmac::Hmac;
    use sha2::Sha512;

    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(mnemonic, b"mnemonic", 2048, &mut seed)
        .expect("PBKDF2 output length is valid");
    let out = Seed(seed);
    seed.zeroize();
    out
}

/// Convert caller-provided entropy into BIP-39 mnemonic + derived seed.
///
/// Valid entropy lengths produce the corresponding word counts:
/// 16→12, 20→15, 24→18, 28→21, 32→24.
///
/// The entropy buffer is zeroized after use (success path).
pub fn generate_mnemonic(
    entropy: &mut [u8],
) -> Result<(MnemonicWords, Seed), BaoSeedError> {
    let entropy_vec = entropy.to_vec();
    let words: Vec<String> = bip39_utils::bytes_to_bip39(&entropy_vec)
        .map_err(|_| BaoSeedError::CryptoError)?;
    let mnemonic_str = words.join(" ");
    let seed = seed_from_mnemonic(mnemonic_str.as_bytes());
    entropy.zeroize();
    let mw = MnemonicWords::new(words)?;
    Ok((mw, seed))
}

/// Compute the vault-internal 4-byte fingerprint for a seed.
///
/// Construction: first 4 bytes of SHA-256(seed). Stable, deterministic.
/// NOT the BIP-32 root fingerprint.
pub fn fingerprint(seed: &Seed) -> Fingerprint {
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    let out = h.finalize();
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&out[..4]);
    fp
}

/// Compute the 32-byte ZIP-32 SeedFingerprint over the seed bytes.
///
/// This is the canonical identifier used by Zcash companion wallets to
/// match keys to a wallet (vs. the cheap 4-byte vault fingerprint
/// above). It's a BLAKE2b-256 hash with the ZIP-32 personalization
/// "Zcash_HD_Seed_FP" — coin-agnostic, but defined in ZIP-32 (a Zcash
/// HD-key spec) so we name it accordingly.
///
/// Returns `None` if the seed length is outside ZIP-32's accepted
/// range (32..=252 bytes); our `Seed` is always 64 bytes so this
/// never trips at runtime, but the API mirrors `zip32`'s upstream.
pub fn zip32_seed_fingerprint(seed: &Seed) -> Option<[u8; 32]> {
    zip32::fingerprint::SeedFingerprint::from_seed(seed.as_bytes())
        .map(|fp| fp.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// BIP-39 canonical vector: empty passphrase, 12 words of zero entropy.
    ///
    /// mnemonic: "abandon abandon abandon abandon abandon abandon
    ///            abandon abandon abandon abandon abandon about"
    ///
    /// Widely cross-checked; also matches the legacy
    /// `ethapp::crypto::get_dev_seed` hardcoded vector.
    #[test]
    fn vector_abandon_x11_about() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about";
        let expected: [u8; 64] = hex!(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70"
            "811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c4"
            "3daea6690f20ad3d8d48b2d2ce9e38e4"
        );
        let seed = seed_from_mnemonic(mnemonic.as_bytes());
        assert_eq!(seed.as_bytes(), &expected);
    }

    /// BIP-39 canonical vector: empty passphrase, 24 words of zero entropy.
    ///
    /// mnemonic: "abandon" × 23 + "art".
    /// Cross-checked against the zcashapp test for the same vector
    /// (`services/zcashapp/src/crypto.rs`, which pins against
    /// independent BIP39 impls including tiny-bip39 and the bip39 crate).
    #[test]
    fn vector_abandon_x23_art() {
        let mnemonic =
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon art";
        let expected: [u8; 64] = hex!(
            "408b285c123836004f4b8842c89324c1f01382450c0d439a"
            "f345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043"
            "db8ada1e243c4a0eafb290d399480840"
        );
        let seed = seed_from_mnemonic(mnemonic.as_bytes());
        assert_eq!(seed.as_bytes(), &expected);
    }

    /// BIP-39 entropy→mnemonic (12 words, 0x00…00 entropy).
    /// Source: Trezor python-mnemonic vectors.json.
    #[test]
    fn entropy_to_mnemonic_12_words_zero() {
        let entropy = [0u8; 16];
        let (words, _seed) = generate_mnemonic(&mut entropy.to_vec()).expect("generate ok");
        let joined = words.as_slice().join(" ");
        assert_eq!(
            joined,
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
        );
    }

    /// BIP-39 entropy→mnemonic (24 words, 0x00…00 entropy).
    #[test]
    fn entropy_to_mnemonic_24_words_zero() {
        let entropy = [0u8; 32];
        let (words, _seed) = generate_mnemonic(&mut entropy.to_vec()).expect("generate ok");
        let joined = words.as_slice().join(" ");
        assert_eq!(
            joined,
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon art"
        );
    }

    /// Trezor vectors.json entry: entropy 0x7f7f…7f (16 bytes).
    /// Validates that non-zero entropy maps to the documented mnemonic.
    #[test]
    fn entropy_to_mnemonic_trezor_vector_7f() {
        let mut entropy = [0x7fu8; 16].to_vec();
        let (words, _) = generate_mnemonic(&mut entropy).expect("generate ok");
        assert_eq!(
            words.as_slice().join(" "),
            "legal winner thank year wave sausage worth useful \
             legal winner thank yellow"
        );
    }

    /// Generate zeroizes the entropy buffer on the success path.
    #[test]
    fn generate_mnemonic_zeroizes_entropy() {
        let mut entropy = [0x5au8; 32].to_vec();
        let original = entropy.clone();
        let _ = generate_mnemonic(&mut entropy).expect("generate ok");
        assert_ne!(entropy, original, "entropy must be wiped after generate");
        assert!(entropy.iter().all(|&b| b == 0), "entropy must be zeroized");
    }

    /// Invalid entropy length is rejected with CryptoError.
    #[test]
    fn invalid_entropy_length_rejected() {
        for &bad_len in &[0usize, 1, 8, 15, 17, 19, 23, 33, 64] {
            let mut entropy = alloc::vec![0u8; bad_len];
            assert!(
                generate_mnemonic(&mut entropy).is_err(),
                "len {} should reject",
                bad_len
            );
        }
    }

    /// Fingerprint is deterministic for the same seed.
    #[test]
    fn fingerprint_is_deterministic() {
        let seed = seed_from_mnemonic(
            b"abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon about",
        );
        let f1 = fingerprint(&seed);
        let f2 = fingerprint(&seed);
        assert_eq!(f1, f2);
    }

    /// Different seeds produce different fingerprints (with high probability).
    #[test]
    fn fingerprint_differs_across_seeds() {
        let s1 = seed_from_mnemonic(
            b"abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon about",
        );
        let s2 = seed_from_mnemonic(
            b"abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon art",
        );
        assert_ne!(fingerprint(&s1), fingerprint(&s2));
    }

    /// Sanity: Seed::from_slice rejects wrong-length input.
    #[test]
    fn seed_from_slice_rejects_bad_length() {
        assert!(Seed::from_slice(&[0u8; 32]).is_none());
        assert!(Seed::from_slice(&[0u8; 63]).is_none());
        assert!(Seed::from_slice(&[0u8; 65]).is_none());
        assert!(Seed::from_slice(&[0u8; 64]).is_some());
    }
}
