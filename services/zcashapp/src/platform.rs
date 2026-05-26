//! Platform abstraction layer — same pattern as ethapp.
//!
//! Provides unified access to TRNG, GAM, and PDDB.

use alloc::vec::Vec;
use zcashapp_common::ZcashAppError;

#[allow(dead_code)]
pub const PDDB_DICT: &str = "zcashapp.zcash";
#[allow(dead_code)]
pub const PDDB_KEY_SEED: &str = "master_seed";

#[allow(dead_code)]
pub trait Platform {
    fn rng_fill_bytes(&self, buf: &mut [u8]) -> Result<(), ZcashAppError>;
    fn confirm_action(&self, title: &str, message: &str) -> Result<bool, ZcashAppError>;
    fn show_transaction_review(
        &self,
        fields: &[(&str, &str)],
        action: &str,
    ) -> Result<bool, ZcashAppError>;
    fn show_info(&self, success: bool, message: &str);
    fn store_value(&self, key: &str, value: &[u8]) -> Result<(), ZcashAppError>;
    fn load_value(&self, key: &str) -> Result<Option<Vec<u8>>, ZcashAppError>;
    fn delete_value(&self, key: &str) -> Result<(), ZcashAppError>;
}

// Xous platform implementation — mirrors ethapp/src/platform.rs
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub struct XousPlatform {
    #[cfg(target_os = "xous")]
    trng: Option<trng::Trng>,
    #[cfg(feature = "pddb")]
    pddb: Option<pddb::Pddb>,
    #[cfg(not(target_os = "xous"))]
    _initialized: bool,
}

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
impl XousPlatform {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "xous")]
            trng: None,
            #[cfg(feature = "pddb")]
            pddb: None,
            #[cfg(not(target_os = "xous"))]
            _initialized: false,
        }
    }

    pub fn init(&mut self) -> Result<(), ZcashAppError> {
        #[cfg(target_os = "xous")]
        {
            let xns = xous_names::XousNames::new()
                .map_err(|_| ZcashAppError::InternalError)?;
            let trng = trng::Trng::new(&xns)
                .map_err(|_| ZcashAppError::InternalError)?;
            self.trng = Some(trng);
        }
        log::info!("zcashapp platform: Initialized");
        Ok(())
    }
}

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
impl Platform for XousPlatform {
    fn rng_fill_bytes(&self, buf: &mut [u8]) -> Result<(), ZcashAppError> {
        #[cfg(target_os = "xous")]
        {
            use rand_core::RngCore;
            let trng = self.trng.as_ref().ok_or(ZcashAppError::InternalError)?;
            let trng_ptr = trng as *const trng::Trng as *mut trng::Trng;
            unsafe { (*trng_ptr).fill_bytes(buf); }
            Ok(())
        }

        #[cfg(not(target_os = "xous"))]
        {
            getrandom::getrandom(buf).map_err(|_| ZcashAppError::CryptoError)
        }
    }

    fn confirm_action(&self, _title: &str, _message: &str) -> Result<bool, ZcashAppError> {
        #[cfg(feature = "autoapprove")]
        { return Ok(true); }

        #[cfg(not(feature = "autoapprove"))]
        {
            log::info!("zcashapp: Would show confirmation for '{}': {}", _title, _message);
            Err(ZcashAppError::UiError)
        }
    }

    fn show_transaction_review(
        &self, fields: &[(&str, &str)], action: &str,
    ) -> Result<bool, ZcashAppError> {
        #[cfg(feature = "autoapprove")]
        {
            log::info!("zcashapp: Auto-approving: {}", action);
            for (tag, value) in fields { log::info!("  {}: {}", tag, value); }
            return Ok(true);
        }

        #[cfg(not(feature = "autoapprove"))]
        {
            let _ = (fields, action);
            log::info!("zcashapp: Would show review for '{}'", action);
            Err(ZcashAppError::UiError)
        }
    }

    fn show_info(&self, success: bool, message: &str) {
        if success { log::info!("zcashapp: SUCCESS - {}", message); }
        else { log::info!("zcashapp: FAILURE - {}", message); }
    }

    fn store_value(&self, key: &str, value: &[u8]) -> Result<(), ZcashAppError> {
        #[cfg(feature = "pddb")]
        {
            let pddb = self.pddb.as_ref().ok_or(ZcashAppError::StorageError)?;
            let mut handle = pddb.get(PDDB_DICT, key, None, true, true, Some(value.len()), None::<fn()>)
                .map_err(|_| ZcashAppError::StorageError)?;
            use std::io::Write;
            handle.write_all(value).map_err(|_| ZcashAppError::StorageError)?;
            pddb.sync().map_err(|_| ZcashAppError::StorageError)?;
            Ok(())
        }
        #[cfg(not(feature = "pddb"))]
        {
            log::info!("zcashapp: Would store {} bytes to '{}'", value.len(), key);
            #[cfg(feature = "dev-mode")] { Ok(()) }
            #[cfg(not(feature = "dev-mode"))] { Err(ZcashAppError::StorageError) }
        }
    }

    fn load_value(&self, _key: &str) -> Result<Option<Vec<u8>>, ZcashAppError> {
        #[cfg(feature = "pddb")]
        {
            let pddb = match self.pddb.as_ref() { Some(p) => p, None => return Ok(None) };
            match pddb.get(PDDB_DICT, key, None, false, false, None, None::<fn()>) {
                Ok(mut handle) => {
                    use std::io::Read;
                    let mut data = Vec::new();
                    handle.read_to_end(&mut data).map_err(|_| ZcashAppError::StorageError)?;
                    Ok(Some(data))
                }
                Err(_) => Ok(None),
            }
        }
        #[cfg(not(feature = "pddb"))]
        { Ok(None) }
    }

    fn delete_value(&self, _key: &str) -> Result<(), ZcashAppError> {
        #[cfg(feature = "pddb")]
        {
            let pddb = match self.pddb.as_ref() { Some(p) => p, None => return Ok(()) };
            pddb.delete_key(PDDB_DICT, key, None).map_err(|_| ZcashAppError::StorageError)?;
            pddb.sync().map_err(|_| ZcashAppError::StorageError)?;
        }
        Ok(())
    }
}

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
impl Default for XousPlatform {
    fn default() -> Self { Self::new() }
}
