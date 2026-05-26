//! Service state management for zcashapp.

use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use zcashapp_common::ZcashAppError;

/// RNG wrapper that uses the platform TRNG on Xous, OsRng on host.
pub struct PlatformRng {
    #[cfg(target_os = "xous")]
    trng: trng::Trng,
}

impl RngCore for PlatformRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        #[cfg(target_os = "xous")]
        {
            self.trng.fill_bytes(dest);
        }
        #[cfg(not(target_os = "xous"))]
        {
            rand_core::OsRng.fill_bytes(dest);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for PlatformRng {}

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use crate::platform::XousPlatform;

pub struct ServiceState {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    pub platform: XousPlatform,

    /// Host-only legacy in-memory seed.
    ///
    /// Real-target builds (xous / hosted-dabao) delegate all seed
    /// storage to bao-seed via `bao_seed_client`. This field only
    /// exists for the host-test path, where bao-seed's IPC isn't
    /// available and tests derive keys directly from `crypto::*`.
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    pub imported_seed: Option<crate::crypto::Seed>,

    /// Lazy connection to the bao-seed Xous service. zcashapp sends
    /// PCZT-derived (alpha, rk) tuples + sighash; bao-seed signs
    /// internally and returns raw 64-byte RedPallas signatures.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    pub bao_seed_client: Option<bao_seed_api::BaoSeedClient>,
}

impl ServiceState {
    pub fn new() -> Self {
        Self {
            #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
            platform: XousPlatform::new(),
            #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
            imported_seed: None,
            #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
            bao_seed_client: None,
        }
    }

    /// Lazily connect to bao-seed and return a borrow of the client.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    pub fn bao_seed(&mut self) -> Result<&bao_seed_api::BaoSeedClient, ZcashAppError> {
        if self.bao_seed_client.is_none() {
            match bao_seed_api::BaoSeedClient::new() {
                Ok(c) => self.bao_seed_client = Some(c),
                Err(e) => {
                    log::error!("zcashapp: cannot connect to bao-seed: {:?}", e);
                    return Err(ZcashAppError::InternalError);
                }
            }
        }
        Ok(self.bao_seed_client.as_ref().unwrap())
    }

    pub fn init_platform(&mut self) -> Result<(), ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            self.platform.init()?;
        }
        Ok(())
    }

    /// Check if a seed is available.
    ///
    /// Real-target builds consult bao-seed (the authoritative store).
    /// Host-test builds check the in-memory legacy field / PDDB stub.
    pub fn has_seed(&mut self) -> bool {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            match self.bao_seed() {
                Ok(client) => client.has_seed().unwrap_or(false),
                Err(_) => false,
            }
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            self.imported_seed.is_some() || self.load_seed().is_some()
        }
    }

    /// Fill buffer with random bytes from hardware TRNG.
    pub fn rng_fill_bytes(&self, buf: &mut [u8]) -> Result<(), ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            use crate::platform::Platform;
            return self.platform.rng_fill_bytes(buf);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            // For tests: fill with deterministic bytes (not for production!)
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i & 0xFF) as u8;
            }
            Ok(())
        }
    }

    /// Store seed to persistent storage (best-effort, no-op without PDDB).
    pub fn store_seed(&self, seed_bytes: &[u8]) {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            use crate::platform::Platform;
            let _ = self
                .platform
                .store_value(crate::platform::PDDB_KEY_SEED, seed_bytes);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            let _ = seed_bytes;
        }
    }

    /// Load seed from persistent storage, if available.
    pub fn load_seed(&self) -> Option<Vec<u8>> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            use crate::platform::Platform;
            if let Ok(Some(bytes)) = self.platform.load_value(crate::platform::PDDB_KEY_SEED) {
                return Some(bytes);
            }
        }
        None
    }

    /// Delete seed from persistent storage.
    pub fn delete_seed(&self) {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            use crate::platform::Platform;
            let _ = self
                .platform
                .delete_value(crate::platform::PDDB_KEY_SEED);
        }
    }

    /// Get a platform RNG suitable for cryptographic operations.
    pub fn rng(&self) -> PlatformRng {
        #[cfg(target_os = "xous")]
        {
            let xns = xous_names::XousNames::new().unwrap();
            let trng = trng::Trng::new(&xns).unwrap();
            PlatformRng { trng }
        }
        #[cfg(not(target_os = "xous"))]
        {
            PlatformRng {}
        }
    }

    /// Ask the user to confirm an action on the trusted display.
    #[allow(dead_code)]
    pub fn confirm_action(&self, title: &str, message: &str) -> Result<bool, ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            use crate::platform::Platform;
            return self.platform.confirm_action(title, message);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            let _ = (title, message);
            // In test builds, auto-approve
            Ok(true)
        }
    }

    /// Show a transaction review screen with field list, return user decision.
    pub fn show_transaction_review(
        &self,
        fields: &[(&str, &str)],
        action: &str,
    ) -> Result<bool, ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            use crate::platform::Platform;
            return self.platform.show_transaction_review(fields, action);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            let _ = (fields, action);
            // In test builds, auto-approve
            Ok(true)
        }
    }

    /// Show an info/status message on the display.
    pub fn show_info(&self, success: bool, message: &str) {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            use crate::platform::Platform;
            self.platform.show_info(success, message);
            return;
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            let _ = (success, message);
        }
    }
}

impl Default for ServiceState {
    fn default() -> Self {
        Self::new()
    }
}
