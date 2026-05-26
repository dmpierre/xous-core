//! Platform abstraction for bao-seed.
//!
//! Provides two things to `ServiceState`:
//! - Hardware entropy (TRNG) for `Generate`
//! - Persistent storage for the seed (across reboots)
//!
//! There are three implementations:
//! - `XousPlatform` — real device (TRNG + PDDB), gated on `cfg(target_os = "xous")`.
//! - `HostPlatform` — host builds (getrandom + in-memory storage), used for
//!   unit tests and the non-Xous target.
//! - `MockPlatform` — test fixture with deterministic entropy and in-memory
//!   storage; exposed as `#[cfg(test)]` for state-machine tests.

use alloc::vec::Vec;

use bao_seed_common::BaoSeedError;

extern crate alloc;

/// Persistent-storage key bao-seed uses for the seed bytes.
///
/// Intentionally distinct from the legacy `eth_seed` / `zec_seed` PDDB
/// keys so the bao-seed transition does not collide with existing data.
pub const PDDB_KEY_SEED: &str = "bao_seed:v1:seed";

/// Platform-abstraction trait.
///
/// `ServiceState` is generic over `P: Platform`, so unit tests can
/// inject a deterministic mock.
pub trait Platform {
    /// Fill `buf` with cryptographically-random bytes.
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), BaoSeedError>;

    /// Store seed bytes to persistent storage.
    ///
    /// On Xous this writes to PDDB. On host/test, store to memory.
    fn store_seed(&mut self, bytes: &[u8]) -> Result<(), BaoSeedError>;

    /// Load seed bytes from persistent storage, if any.
    fn load_seed(&self) -> Result<Option<Vec<u8>>, BaoSeedError>;

    /// Delete seed from persistent storage. Idempotent.
    fn delete_seed(&mut self) -> Result<(), BaoSeedError>;
}

// ---- Host / test implementation --------------------------------------------

/// Host-side platform. Uses `getrandom` for entropy and a heap-allocated
/// vector for "persistent" storage (which is in-process memory only —
/// nothing actually persists across runs on the host).
#[cfg(not(target_os = "xous"))]
pub struct HostPlatform {
    stored_seed: Option<Vec<u8>>,
}

#[cfg(not(target_os = "xous"))]
impl HostPlatform {
    pub fn new() -> Self {
        Self { stored_seed: None }
    }
}

#[cfg(not(target_os = "xous"))]
impl Default for HostPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "xous"))]
impl Platform for HostPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), BaoSeedError> {
        getrandom::getrandom(buf).map_err(|_| BaoSeedError::TrngError)
    }

    fn store_seed(&mut self, bytes: &[u8]) -> Result<(), BaoSeedError> {
        self.stored_seed = Some(bytes.to_vec());
        Ok(())
    }

    fn load_seed(&self) -> Result<Option<Vec<u8>>, BaoSeedError> {
        Ok(self.stored_seed.clone())
    }

    fn delete_seed(&mut self) -> Result<(), BaoSeedError> {
        self.stored_seed = None;
        Ok(())
    }
}

// ---- Xous (device) implementation -----------------------------------------

#[cfg(target_os = "xous")]
pub struct XousPlatform {
    trng: trng::Trng,
}

#[cfg(target_os = "xous")]
impl XousPlatform {
    pub fn new() -> Result<Self, BaoSeedError> {
        let xns = xous_names::XousNames::new().map_err(|_| BaoSeedError::Internal)?;
        let trng = trng::Trng::new(&xns).map_err(|_| BaoSeedError::TrngError)?;
        Ok(Self { trng })
    }
}

#[cfg(target_os = "xous")]
impl Platform for XousPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), BaoSeedError> {
        // `RngCore::fill_bytes` is infallible — internal panics on
        // unrecoverable TRNG errors. Matches the pattern in zcashapp.
        use rand_core::RngCore;
        self.trng.fill_bytes(buf);
        Ok(())
    }

    // PDDB-backed persistence is wired up on flash-equipped boards
    // (baosec) in a follow-up. dabao has no external SPI flash, so on
    // this target we silently no-op — the in-memory `ServiceState` is
    // the source of truth and a reboot clears the seed. Matches the
    // existing ethapp/zcashapp behavior on dabao.
    fn store_seed(&mut self, _bytes: &[u8]) -> Result<(), BaoSeedError> {
        Ok(())
    }

    fn load_seed(&self) -> Result<Option<Vec<u8>>, BaoSeedError> {
        Ok(None)
    }

    fn delete_seed(&mut self) -> Result<(), BaoSeedError> {
        Ok(())
    }
}

// ---- Test mock --------------------------------------------------------------

#[cfg(test)]
pub mod mock {
    use super::*;

    /// Deterministic platform for state-machine tests.
    ///
    /// Entropy is pulled from a configurable byte vector (rotating /
    /// recycling if shorter than requested). Storage is in-memory.
    pub struct MockPlatform {
        entropy_pool: Vec<u8>,
        entropy_cursor: usize,
        stored_seed: Option<Vec<u8>>,
        pub trng_fail: bool,
        pub storage_fail: bool,
    }

    impl MockPlatform {
        /// Build a mock with the given entropy pool.
        pub fn new(entropy_pool: Vec<u8>) -> Self {
            Self {
                entropy_pool,
                entropy_cursor: 0,
                stored_seed: None,
                trng_fail: false,
                storage_fail: false,
            }
        }

        /// Build a mock pre-loaded with a "stored" seed from previous session.
        pub fn with_stored_seed(seed_bytes: Vec<u8>) -> Self {
            let mut p = Self::new(alloc::vec![0u8; 32]);
            p.stored_seed = Some(seed_bytes);
            p
        }

        pub fn stored(&self) -> Option<&Vec<u8>> {
            self.stored_seed.as_ref()
        }
    }

    impl Platform for MockPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), BaoSeedError> {
            if self.trng_fail {
                return Err(BaoSeedError::TrngError);
            }
            if self.entropy_pool.is_empty() {
                return Err(BaoSeedError::TrngError);
            }
            for b in buf.iter_mut() {
                *b = self.entropy_pool[self.entropy_cursor % self.entropy_pool.len()];
                self.entropy_cursor += 1;
            }
            Ok(())
        }

        fn store_seed(&mut self, bytes: &[u8]) -> Result<(), BaoSeedError> {
            if self.storage_fail {
                return Err(BaoSeedError::StorageError);
            }
            self.stored_seed = Some(bytes.to_vec());
            Ok(())
        }

        fn load_seed(&self) -> Result<Option<Vec<u8>>, BaoSeedError> {
            Ok(self.stored_seed.clone())
        }

        fn delete_seed(&mut self) -> Result<(), BaoSeedError> {
            self.stored_seed = None;
            Ok(())
        }
    }
}
