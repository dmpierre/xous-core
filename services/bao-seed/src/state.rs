//! Service state and the lifecycle state machine.
//!
//! `ServiceState<P>` is generic over `Platform` so unit tests can
//! inject deterministic entropy and in-memory storage.
//!
//! ## State machine
//!
//! ```text
//!         ┌─────────────────────────┐
//!         │      Empty              │
//!         │  imported_seed = None   │
//!         └─────────────────────────┘
//!                │            ▲
//!     Generate / │            │ Wipe
//!     Import     │            │
//!                ▼            │
//!         ┌─────────────────────────┐
//!         │      Loaded             │
//!         │  imported_seed = Some   │
//!         └─────────────────────────┘
//! ```
//!
//! Generate and Import both transition Empty → Loaded. They are
//! rejected when state is Loaded (caller must explicitly Wipe first).
//! Wipe transitions Loaded → Empty (idempotent — also OK from Empty).

use alloc::vec::Vec;

use bao_seed_common::{
    BaoSeedError, CompressedPubkey, Fingerprint, GenerateResponse, ImportResponse, MnemonicWords,
    OrchardActionInput, OrchardFvkBytes, OrchardSignResponse, Secp256k1Signature, StatusResponse,
    Zip32SeedFingerprintBytes, PROTOCOL_VERSION,
};

use crate::orchard as orchard_internal;
use crate::platform::Platform;
use crate::secp256k1;
use crate::seed::{fingerprint, generate_mnemonic, seed_from_mnemonic, zip32_seed_fingerprint, Seed};

extern crate alloc;

/// Bytes of entropy required for a given mnemonic word count.
fn entropy_bytes_for_word_count(word_count: u8) -> Result<usize, BaoSeedError> {
    match word_count {
        12 => Ok(16),
        15 => Ok(20),
        18 => Ok(24),
        21 => Ok(28),
        24 => Ok(32),
        _ => Err(BaoSeedError::InvalidMnemonicLength),
    }
}

/// Service state.
pub struct ServiceState<P: Platform> {
    platform: P,
    imported_seed: Option<Seed>,
}

impl<P: Platform> ServiceState<P> {
    /// Build a fresh state. The platform's persistent storage is NOT
    /// consulted; call `load_persisted_seed` separately at boot if
    /// desired.
    pub fn new(platform: P) -> Self {
        Self { platform, imported_seed: None }
    }

    /// Attempt to load a seed previously persisted via `store_seed`.
    /// On boot, services typically call this to restore the seed across
    /// power cycles.
    pub fn load_persisted_seed(&mut self) -> Result<bool, BaoSeedError> {
        if self.imported_seed.is_some() {
            return Ok(true);
        }
        match self.platform.load_seed()? {
            Some(bytes) => {
                let s = Seed::from_slice(&bytes).ok_or(BaoSeedError::StorageError)?;
                self.imported_seed = Some(s);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Cheap presence check.
    pub fn has_seed(&self) -> bool {
        self.imported_seed.is_some()
    }

    /// Get the current fingerprint, if a seed is loaded.
    pub fn current_fingerprint(&self) -> Option<Fingerprint> {
        self.imported_seed.as_ref().map(fingerprint)
    }

    /// Compute the 32-byte ZIP-32 SeedFingerprint over the loaded seed.
    ///
    /// Returns `NoSeed` if no seed is loaded, or `CryptoError` if the
    /// underlying `zip32` library rejects the seed length (won't happen
    /// at runtime — `Seed` is always 64 bytes — but we surface it as
    /// an error rather than panicking).
    pub fn zip32_seed_fingerprint(&self) -> Result<Zip32SeedFingerprintBytes, BaoSeedError> {
        let seed = self.imported_seed.as_ref().ok_or(BaoSeedError::NoSeed)?;
        zip32_seed_fingerprint(seed).ok_or(BaoSeedError::CryptoError)
    }

    /// Status response (lifecycle / IPC reply).
    pub fn status(&self) -> StatusResponse {
        StatusResponse {
            protocol_version: PROTOCOL_VERSION,
            has_seed: self.has_seed(),
            fingerprint: self.current_fingerprint(),
        }
    }

    /// Generate a new seed from hardware TRNG.
    ///
    /// Refuses if a seed is already loaded — caller must Wipe first.
    pub fn generate(&mut self, word_count: u8) -> Result<GenerateResponse, BaoSeedError> {
        if self.imported_seed.is_some() {
            return Err(BaoSeedError::SeedAlreadyLoaded);
        }
        let entropy_len = entropy_bytes_for_word_count(word_count)?;
        let mut entropy = alloc::vec![0u8; entropy_len];
        self.platform.fill_random(&mut entropy)?;
        let (words, seed) = generate_mnemonic(&mut entropy)?;
        let fp = fingerprint(&seed);
        self.platform.store_seed(seed.as_bytes())?;
        self.imported_seed = Some(seed);
        Ok(GenerateResponse { words, fingerprint: fp })
    }

    /// Import an existing BIP-39 mnemonic.
    ///
    /// Refuses if a seed is already loaded.
    pub fn import(&mut self, words: MnemonicWords) -> Result<ImportResponse, BaoSeedError> {
        if self.imported_seed.is_some() {
            return Err(BaoSeedError::SeedAlreadyLoaded);
        }
        // Validate against the BIP-39 wordlist + checksum by round-tripping
        // through bip39_utils::bip39_to_bytes. Returns an error if a word
        // isn't in the list or the checksum is wrong.
        let words_vec: Vec<alloc::string::String> = words.as_slice().to_vec();
        bip39_utils::bip39_to_bytes(&words_vec).map_err(|_| BaoSeedError::InvalidMnemonic)?;

        let mnemonic_str = words.as_slice().join(" ");
        let seed = seed_from_mnemonic(mnemonic_str.as_bytes());
        let fp = fingerprint(&seed);
        self.platform.store_seed(seed.as_bytes())?;
        self.imported_seed = Some(seed);
        Ok(ImportResponse { fingerprint: fp })
    }

    /// Import a raw 64-byte master seed, bypassing BIP-39 derivation.
    ///
    /// Used by callers that already hold the derived seed (encrypted-
    /// import flow, dev-mode seed injection). Refuses if a seed is
    /// already loaded.
    pub fn import_seed_bytes(
        &mut self,
        seed_bytes: &[u8; 64],
    ) -> Result<ImportResponse, BaoSeedError> {
        if self.imported_seed.is_some() {
            return Err(BaoSeedError::SeedAlreadyLoaded);
        }
        let seed = Seed::from_bytes(seed_bytes);
        let fp = fingerprint(&seed);
        self.platform.store_seed(seed.as_bytes())?;
        self.imported_seed = Some(seed);
        Ok(ImportResponse { fingerprint: fp })
    }

    /// Wipe the seed from RAM and persistent storage.
    ///
    /// Idempotent — safe to call when no seed is loaded.
    pub fn wipe(&mut self) -> Result<(), BaoSeedError> {
        self.imported_seed = None;
        self.platform.delete_seed()
    }

    // -----------------------------------------------------------------
    // secp256k1
    // -----------------------------------------------------------------

    /// Derive the compressed secp256k1 pubkey at `path`. Requires a seed.
    pub fn secp256k1_get_pubkey(&self, path: &[u32]) -> Result<CompressedPubkey, BaoSeedError> {
        let seed = self.imported_seed.as_ref().ok_or(BaoSeedError::NoSeed)?;
        secp256k1::derive_compressed_pubkey(seed, path)
    }

    /// Sign a 32-byte digest at `path`. Requires a seed.
    pub fn secp256k1_sign(
        &self,
        path: &[u32],
        hash: &[u8; 32],
    ) -> Result<Secp256k1Signature, BaoSeedError> {
        let seed = self.imported_seed.as_ref().ok_or(BaoSeedError::NoSeed)?;
        secp256k1::sign_hash(seed, path, hash)
    }

    // -----------------------------------------------------------------
    // Orchard / Pallas
    // -----------------------------------------------------------------

    /// Derive the 96-byte Orchard FullViewingKey for (coin_type, account).
    pub fn orchard_get_fvk(
        &self,
        coin_type: u32,
        account: u32,
    ) -> Result<OrchardFvkBytes, BaoSeedError> {
        let seed = self.imported_seed.as_ref().ok_or(BaoSeedError::NoSeed)?;
        orchard_internal::derive_fvk_bytes(seed, coin_type, account)
    }

    /// Sign a batch of Orchard actions under (coin_type, account).
    /// Needs entropy from the platform for RedPallas signing.
    pub fn orchard_sign(
        &mut self,
        coin_type: u32,
        account: u32,
        sighash: &[u8; 32],
        actions: &[OrchardActionInput],
    ) -> Result<OrchardSignResponse, BaoSeedError> {
        // Borrow seed and platform separately so the RNG can call back
        // into `fill_random` while seed remains borrowed.
        let seed = self
            .imported_seed
            .as_ref()
            .ok_or(BaoSeedError::NoSeed)?
            .clone();
        let rng = PlatformRng::new(&mut self.platform);
        orchard_internal::sign_actions(&seed, coin_type, account, sighash, actions, rng)
    }
}

/// Adapter so the orchard module can pull randomness through the
/// `Platform` trait. Each `next_u32` / `fill_bytes` call dips into
/// `platform.fill_random`.
struct PlatformRng<'a, P: Platform> {
    platform: &'a mut P,
}

impl<'a, P: Platform> PlatformRng<'a, P> {
    fn new(platform: &'a mut P) -> Self {
        Self { platform }
    }
}

impl<'a, P: Platform> rand_core::RngCore for PlatformRng<'a, P> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        let _ = self.platform.fill_random(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        let _ = self.platform.fill_random(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = self.platform.fill_random(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        // Map platform TRNG failure to a non-zero error code per
        // rand_core's contract. The orchard/reddsa signing code uses
        // `fill_bytes` (which panics on failure) so this is mostly
        // belt-and-suspenders.
        self.platform.fill_random(dest).map_err(|_| {
            // SAFETY: 0xBA0_5EED is a non-zero u32 (rand_core::Error
            // requires NonZeroU32).
            let nz = core::num::NonZeroU32::new(0xBA0_5EED).expect("nonzero");
            rand_core::Error::from(nz)
        })
    }
}

impl<'a, P: Platform> rand_core::CryptoRng for PlatformRng<'a, P> {}

impl<P: Platform> ServiceState<P> {

    /// Borrow the platform (test/debug only — production code routes
    /// through the platform via state methods).
    #[cfg(test)]
    pub(crate) fn platform_ref(&self) -> &P {
        &self.platform
    }
} // end second impl block (the public API methods)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockPlatform;
    use bao_seed_common::HARDENED;

    fn mock_with_entropy(entropy: Vec<u8>) -> ServiceState<MockPlatform> {
        ServiceState::new(MockPlatform::new(entropy))
    }

    // --- Initial state ----------------------------------------------------

    #[test]
    fn initial_state_has_no_seed() {
        let s = mock_with_entropy(alloc::vec![0u8; 32]);
        assert!(!s.has_seed());
        assert!(s.current_fingerprint().is_none());
    }

    #[test]
    fn status_on_empty_reflects_no_seed() {
        let s = mock_with_entropy(alloc::vec![0u8; 32]);
        let st = s.status();
        assert_eq!(st.protocol_version, PROTOCOL_VERSION);
        assert!(!st.has_seed);
        assert!(st.fingerprint.is_none());
    }

    // --- Generate ----------------------------------------------------------

    #[test]
    fn generate_default_24_words() {
        let mut s = mock_with_entropy(alloc::vec![0xa5u8; 32]);
        let resp = s.generate(24).expect("generate ok");
        assert_eq!(resp.words.len(), 24);
        assert!(s.has_seed());
        assert_eq!(s.current_fingerprint(), Some(resp.fingerprint));
    }

    #[test]
    fn generate_12_words() {
        let mut s = mock_with_entropy(alloc::vec![0x42u8; 32]);
        let resp = s.generate(12).expect("generate ok");
        assert_eq!(resp.words.len(), 12);
        assert!(s.has_seed());
    }

    #[test]
    fn generate_rejects_invalid_word_count() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        for &bad in &[0u8, 1, 11, 13, 22, 25, 100] {
            let err = s.generate(bad).expect_err("should reject");
            assert_eq!(err, BaoSeedError::InvalidMnemonicLength);
        }
        assert!(!s.has_seed(), "rejected generate must not mutate state");
    }

    #[test]
    fn generate_when_seed_loaded_returns_already_loaded() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 64]);
        s.generate(24).expect("first generate ok");
        let err = s.generate(24).expect_err("second generate must fail");
        assert_eq!(err, BaoSeedError::SeedAlreadyLoaded);
    }

    #[test]
    fn generate_propagates_trng_failure() {
        let mut p = MockPlatform::new(alloc::vec![0u8; 32]);
        p.trng_fail = true;
        let mut s = ServiceState::new(p);
        let err = s.generate(24).expect_err("trng fail must propagate");
        assert_eq!(err, BaoSeedError::TrngError);
        assert!(!s.has_seed());
    }

    #[test]
    fn generate_persists_seed_to_platform() {
        let mut s = mock_with_entropy(alloc::vec![0x11u8; 32]);
        s.generate(24).expect("generate ok");
        assert!(s.platform_ref().stored().is_some());
        assert_eq!(s.platform_ref().stored().unwrap().len(), 64);
    }

    // --- Import ------------------------------------------------------------

    #[test]
    fn import_valid_12_word_mnemonic() {
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let resp = s.import(words).expect("import ok");
        assert!(s.has_seed());
        assert_eq!(s.current_fingerprint(), Some(resp.fingerprint));
    }

    #[test]
    fn import_valid_24_word_mnemonic() {
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon art"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        s.import(words).expect("import ok");
        assert!(s.has_seed());
    }

    #[test]
    fn import_rejects_invalid_checksum() {
        // Swap final word so checksum fails: change "about" → "abandon"
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let err = s.import(words).expect_err("bad checksum must fail");
        assert_eq!(err, BaoSeedError::InvalidMnemonic);
        assert!(!s.has_seed());
    }

    #[test]
    fn import_rejects_unknown_word() {
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon notaword"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let err = s.import(words).expect_err("unknown word must fail");
        assert_eq!(err, BaoSeedError::InvalidMnemonic);
    }

    #[test]
    fn import_when_seed_loaded_returns_already_loaded() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 64]);
        s.generate(24).expect("first generate ok");
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        let err = s.import(words).expect_err("import on loaded must fail");
        assert_eq!(err, BaoSeedError::SeedAlreadyLoaded);
    }

    // --- Wipe --------------------------------------------------------------

    #[test]
    fn wipe_clears_in_memory_and_persistent() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        s.generate(24).expect("generate ok");
        assert!(s.has_seed());
        assert!(s.platform_ref().stored().is_some());
        s.wipe().expect("wipe ok");
        assert!(!s.has_seed());
        assert!(s.platform_ref().stored().is_none());
    }

    #[test]
    fn wipe_is_idempotent() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        s.wipe().expect("wipe on empty ok");
        s.wipe().expect("second wipe ok");
        assert!(!s.has_seed());
    }

    #[test]
    fn generate_after_wipe_works() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 64]);
        s.generate(24).expect("first generate ok");
        s.wipe().expect("wipe ok");
        s.generate(24).expect("second generate ok");
        assert!(s.has_seed());
    }

    // --- Persistence -------------------------------------------------------

    #[test]
    fn load_persisted_seed_restores_session() {
        // Build a mock with a "stored" seed simulating a previous session.
        let seed_bytes = alloc::vec![0x77u8; 64];
        let platform = MockPlatform::with_stored_seed(seed_bytes.clone());
        let mut s = ServiceState::new(platform);
        assert!(!s.has_seed());
        let loaded = s.load_persisted_seed().expect("load ok");
        assert!(loaded);
        assert!(s.has_seed());
    }

    #[test]
    fn load_persisted_seed_no_op_when_already_loaded() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 64]);
        s.generate(24).expect("generate ok");
        let fp1 = s.current_fingerprint();
        let loaded = s.load_persisted_seed().expect("load ok");
        assert!(loaded);
        let fp2 = s.current_fingerprint();
        assert_eq!(fp1, fp2, "load when loaded must not mutate state");
    }

    #[test]
    fn load_persisted_seed_when_empty_returns_false() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let loaded = s.load_persisted_seed().expect("load ok");
        assert!(!loaded);
        assert!(!s.has_seed());
    }

    // --- secp256k1 ------------------------------------------------------

    #[test]
    fn secp256k1_pubkey_requires_seed() {
        let s = mock_with_entropy(alloc::vec![0u8; 32]);
        let err = s.secp256k1_get_pubkey(&[]).unwrap_err();
        assert_eq!(err, BaoSeedError::NoSeed);
    }

    #[test]
    fn secp256k1_sign_requires_seed() {
        let s = mock_with_entropy(alloc::vec![0u8; 32]);
        let err = s.secp256k1_sign(&[], &[0u8; 32]).unwrap_err();
        assert_eq!(err, BaoSeedError::NoSeed);
    }

    #[test]
    fn secp256k1_pubkey_after_import_is_deterministic() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        s.import(words).unwrap();
        let path = alloc::vec![44 | HARDENED, 60 | HARDENED, 0 | HARDENED, 0u32, 0u32];
        let pk1 = s.secp256k1_get_pubkey(&path).unwrap();
        let pk2 = s.secp256k1_get_pubkey(&path).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn secp256k1_sign_returns_consistent_signature() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        s.import(words).unwrap();
        let path = alloc::vec![44 | HARDENED, 60 | HARDENED, 0 | HARDENED, 0u32, 0u32];
        let hash = [0x42u8; 32];
        // ECDSA with deterministic k (RFC 6979 — k256 default) produces
        // the same signature every time.
        let sig1 = s.secp256k1_sign(&path, &hash).unwrap();
        let sig2 = s.secp256k1_sign(&path, &hash).unwrap();
        assert_eq!(sig1, sig2);
    }

    // --- ZIP-32 SeedFingerprint -------------------------------------------

    #[test]
    fn zip32_seed_fingerprint_on_empty_state_is_no_seed() {
        let s = mock_with_entropy(alloc::vec![0u8; 32]);
        assert_eq!(s.zip32_seed_fingerprint(), Err(BaoSeedError::NoSeed));
    }

    #[test]
    fn zip32_seed_fingerprint_deterministic_for_abandon_x11_about() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        s.import(words).unwrap();
        let fp1 = s.zip32_seed_fingerprint().unwrap();
        let fp2 = s.zip32_seed_fingerprint().unwrap();
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
        assert_ne!(fp1, [0u8; 32], "fingerprint must not be all zeros");
    }

    #[test]
    fn zip32_seed_fingerprint_differs_from_vault_fingerprint() {
        // Sanity-check that ZIP-32 fingerprint (32 bytes) is distinct
        // from the vault's 4-byte SHA-256 prefix — they are different
        // constructions for different purposes.
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        s.import(words).unwrap();
        let zip32_fp = s.zip32_seed_fingerprint().unwrap();
        let vault_fp = s.current_fingerprint().unwrap();
        assert_ne!(&zip32_fp[..4], &vault_fp[..]);
    }

    // --- ImportSeedBytes --------------------------------------------------

    #[test]
    fn import_seed_bytes_sets_state_loaded() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let seed = [0x42u8; 64];
        let resp = s.import_seed_bytes(&seed).expect("import ok");
        assert!(s.has_seed());
        assert_eq!(s.current_fingerprint(), Some(resp.fingerprint));
    }

    #[test]
    fn import_seed_bytes_refuses_overwrite() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let seed = [0x42u8; 64];
        s.import_seed_bytes(&seed).expect("first import ok");
        let err = s.import_seed_bytes(&[0x11u8; 64]).unwrap_err();
        assert!(matches!(err, BaoSeedError::SeedAlreadyLoaded));
    }

    #[test]
    fn import_seed_bytes_then_wipe_clears_state() {
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        let seed = [0x42u8; 64];
        s.import_seed_bytes(&seed).expect("import ok");
        assert!(s.has_seed());
        s.wipe().expect("wipe ok");
        assert!(!s.has_seed());
    }

    #[test]
    fn import_seed_bytes_then_mnemonic_import_refused() {
        // Either path locks out the other — sanity check on
        // SeedAlreadyLoaded semantics across the two import variants.
        let mut s = mock_with_entropy(alloc::vec![0u8; 32]);
        s.import_seed_bytes(&[0x42u8; 64]).expect("import ok");
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        let err = s.import(words).unwrap_err();
        assert!(matches!(err, BaoSeedError::SeedAlreadyLoaded));
    }
}
