//! Opcode handlers for the bao-seed service.
//!
//! Each handler converts an IPC message into a `ServiceState` call and
//! writes the response back. Mirrors the cfg(target_os = "xous") pattern
//! from `ethapp/src/handlers.rs` — Xous and hosted-dabao builds use
//! `xous::MessageEnvelope` / `xous_ipc::Buffer`; pure host builds expose
//! direct function entry points used by unit tests.

use bao_seed_common::{
    BaoSeedError, GenerateRequest, GenerateResponse, ImportRequest, ImportResponse,
    ImportSeedBytesRequest,
};

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
use bao_seed_common::StatusResponse;

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use bao_seed_common::{
    CompressedPubkey, LifecycleResult, OrchardFvkBytes, OrchardFvkRequest, OrchardSignRequest,
    OrchardSignResponse, Secp256k1PubkeyRequest, Secp256k1SignRequest, Secp256k1Signature,
    Zip32SeedFingerprintBytes,
};

use crate::platform::Platform;
use crate::state::ServiceState;

extern crate alloc;

// =============================================================================
// Helpers — scalar replies
// =============================================================================

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use num_traits::ToPrimitive;

/// Return a 2-value blocking-scalar response: (error_code, payload).
///
/// Errors encode the `BaoSeedError` as `error_code`; success uses
/// `BaoSeedError::Ok` (0).
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
fn return_scalar2(msg: xous::MessageEnvelope, error: BaoSeedError, payload: usize) {
    let code = error.to_u32().unwrap_or(BaoSeedError::Internal as u32) as usize;
    let _ = xous::return_scalar2(msg.sender, code, payload);
}

/// Return a 1-value blocking-scalar response: error_code.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
fn return_scalar1(msg: xous::MessageEnvelope, error: BaoSeedError) {
    let code = error.to_u32().unwrap_or(BaoSeedError::Internal as u32) as usize;
    let _ = xous::return_scalar(msg.sender, code);
}

// =============================================================================
// Xous / hosted-dabao handlers (IPC-driven)
// =============================================================================

/// Handle `Status` — memory message, returns `StatusResponse`.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_status<P: Platform>(state: &ServiceState<P>, mut msg: xous::MessageEnvelope) {
    use xous_ipc::Buffer;
    let resp = state.status();
    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: Status expects memory message");
                return;
            }
        }
    };
    let _ = buffer.replace(resp);
}

/// Handle `HasSeed` — blocking scalar, returns (err_code, has_seed).
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_has_seed<P: Platform>(state: &ServiceState<P>, msg: xous::MessageEnvelope) {
    let has = if state.has_seed() { 1 } else { 0 };
    return_scalar2(msg, BaoSeedError::Ok, has);
}

/// Handle `Wipe` — blocking scalar, returns err_code.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_wipe<P: Platform>(state: &mut ServiceState<P>, msg: xous::MessageEnvelope) {
    match state.wipe() {
        Ok(()) => return_scalar1(msg, BaoSeedError::Ok),
        Err(e) => return_scalar1(msg, e),
    }
}

/// Handle `Zip32SeedFingerprint` — empty memory message in,
/// `LifecycleResult<Zip32SeedFingerprintBytes>` out.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_zip32_seed_fingerprint<P: Platform>(
    state: &ServiceState<P>,
    mut msg: xous::MessageEnvelope,
) {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: Zip32SeedFingerprint expects memory message");
                return;
            }
        }
    };

    let result: LifecycleResult<Zip32SeedFingerprintBytes> = match state.zip32_seed_fingerprint() {
        Ok(fp) => LifecycleResult::Ok(fp),
        Err(e) => LifecycleResult::Err(e as u32),
    };
    let _ = buffer.replace(result);
}

/// Handle `Generate` — memory message; GenerateRequest in, GenerateResponse out.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_generate<P: Platform>(
    state: &mut ServiceState<P>,
    mut msg: xous::MessageEnvelope,
) {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: Generate expects memory message");
                return;
            }
        }
    };

    let request: GenerateRequest = match buffer.to_original() {
        Ok(r) => r,
        Err(_) => {
            let result: LifecycleResult<GenerateResponse> =
                LifecycleResult::Err(BaoSeedError::InvalidRequest as u32);
            let _ = buffer.replace(result);
            return;
        }
    };

    let result: LifecycleResult<GenerateResponse> = match state.generate(request.word_count) {
        Ok(r) => LifecycleResult::Ok(r),
        Err(e) => LifecycleResult::Err(e as u32),
    };
    let _ = buffer.replace(result);
}

/// Handle `Import` — memory message; ImportRequest in, ImportResponse out.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_import<P: Platform>(
    state: &mut ServiceState<P>,
    mut msg: xous::MessageEnvelope,
) {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: Import expects memory message");
                return;
            }
        }
    };

    let request: ImportRequest = match buffer.to_original() {
        Ok(r) => r,
        Err(_) => {
            let result: LifecycleResult<ImportResponse> =
                LifecycleResult::Err(BaoSeedError::InvalidRequest as u32);
            let _ = buffer.replace(result);
            return;
        }
    };

    let result: LifecycleResult<ImportResponse> = match state.import(request.words) {
        Ok(r) => LifecycleResult::Ok(r),
        Err(e) => LifecycleResult::Err(e as u32),
    };
    let _ = buffer.replace(result);
}

/// Handle `ImportSeedBytes` — raw 64-byte seed import (skips BIP-39).
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_import_seed_bytes<P: Platform>(
    state: &mut ServiceState<P>,
    mut msg: xous::MessageEnvelope,
) {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: ImportSeedBytes expects memory message");
                return;
            }
        }
    };

    let request: ImportSeedBytesRequest = match buffer.to_original() {
        Ok(r) => r,
        Err(_) => {
            let result: LifecycleResult<ImportResponse> =
                LifecycleResult::Err(BaoSeedError::InvalidRequest as u32);
            let _ = buffer.replace(result);
            return;
        }
    };

    let result: LifecycleResult<ImportResponse> = match state.import_seed_bytes(&request.seed) {
        Ok(r) => LifecycleResult::Ok(r),
        Err(e) => LifecycleResult::Err(e as u32),
    };
    let _ = buffer.replace(result);
}

/// Handle `Secp256k1GetPubkey` — memory message.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_secp256k1_get_pubkey<P: Platform>(
    state: &ServiceState<P>,
    mut msg: xous::MessageEnvelope,
) {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: Secp256k1GetPubkey expects memory message");
                return;
            }
        }
    };
    let req: Secp256k1PubkeyRequest = match buffer.to_original() {
        Ok(r) => r,
        Err(_) => {
            let result: LifecycleResult<CompressedPubkey> =
                LifecycleResult::Err(BaoSeedError::InvalidRequest as u32);
            let _ = buffer.replace(result);
            return;
        }
    };
    let result: LifecycleResult<CompressedPubkey> = match state.secp256k1_get_pubkey(&req.path) {
        Ok(pk) => LifecycleResult::Ok(pk),
        Err(e) => LifecycleResult::Err(e as u32),
    };
    let _ = buffer.replace(result);
}

/// Handle `Secp256k1Sign` — memory message.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_secp256k1_sign<P: Platform>(
    state: &ServiceState<P>,
    mut msg: xous::MessageEnvelope,
) {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: Secp256k1Sign expects memory message");
                return;
            }
        }
    };
    let req: Secp256k1SignRequest = match buffer.to_original() {
        Ok(r) => r,
        Err(_) => {
            let result: LifecycleResult<Secp256k1Signature> =
                LifecycleResult::Err(BaoSeedError::InvalidRequest as u32);
            let _ = buffer.replace(result);
            return;
        }
    };
    let result: LifecycleResult<Secp256k1Signature> = match state.secp256k1_sign(&req.path, &req.hash) {
        Ok(sig) => LifecycleResult::Ok(sig),
        Err(e) => LifecycleResult::Err(e as u32),
    };
    let _ = buffer.replace(result);
}

/// Handle `OrchardGetFvk` — memory message.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_orchard_get_fvk<P: Platform>(
    state: &ServiceState<P>,
    mut msg: xous::MessageEnvelope,
) {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: OrchardGetFvk expects memory message");
                return;
            }
        }
    };
    let req: OrchardFvkRequest = match buffer.to_original() {
        Ok(r) => r,
        Err(_) => {
            let result: LifecycleResult<OrchardFvkBytes> =
                LifecycleResult::Err(BaoSeedError::InvalidRequest as u32);
            let _ = buffer.replace(result);
            return;
        }
    };
    let result: LifecycleResult<OrchardFvkBytes> = match state.orchard_get_fvk(req.coin_type, req.account) {
        Ok(fvk) => LifecycleResult::Ok(fvk),
        Err(e) => LifecycleResult::Err(e as u32),
    };
    let _ = buffer.replace(result);
}

/// Handle `OrchardSign` — memory message.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
pub fn handle_orchard_sign<P: Platform>(
    state: &mut ServiceState<P>,
    mut msg: xous::MessageEnvelope,
) {
    use xous_ipc::Buffer;

    let mut buffer = unsafe {
        match msg.body.memory_message_mut() {
            Some(m) => Buffer::from_memory_message_mut(m),
            None => {
                log::warn!("bao-seed: OrchardSign expects memory message");
                return;
            }
        }
    };
    let req: OrchardSignRequest = match buffer.to_original() {
        Ok(r) => r,
        Err(_) => {
            let result: LifecycleResult<OrchardSignResponse> =
                LifecycleResult::Err(BaoSeedError::InvalidRequest as u32);
            let _ = buffer.replace(result);
            return;
        }
    };
    let result: LifecycleResult<OrchardSignResponse> =
        match state.orchard_sign(req.coin_type, req.account, &req.sighash, &req.actions) {
            Ok(sigs) => LifecycleResult::Ok(sigs),
            Err(e) => LifecycleResult::Err(e as u32),
        };
    let _ = buffer.replace(result);
}

// =============================================================================
// Host-only direct entry points (used by integration tests)
// =============================================================================

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_status<P: Platform>(state: &ServiceState<P>) -> StatusResponse {
    state.status()
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_has_seed<P: Platform>(state: &ServiceState<P>) -> bool {
    state.has_seed()
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_wipe<P: Platform>(state: &mut ServiceState<P>) -> Result<(), BaoSeedError> {
    state.wipe()
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_generate<P: Platform>(
    state: &mut ServiceState<P>,
    request: GenerateRequest,
) -> Result<GenerateResponse, BaoSeedError> {
    state.generate(request.word_count)
}

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub fn handle_import<P: Platform>(
    state: &mut ServiceState<P>,
    request: ImportRequest,
) -> Result<ImportResponse, BaoSeedError> {
    state.import(request.words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockPlatform;
    use bao_seed_common::{MnemonicWords, PROTOCOL_VERSION};

    fn fresh_state() -> ServiceState<MockPlatform> {
        ServiceState::new(MockPlatform::new(alloc::vec![0xaau8; 64]))
    }

    #[test]
    fn status_handler_empty_state() {
        let s = fresh_state();
        let st = handle_status(&s);
        assert_eq!(st.protocol_version, PROTOCOL_VERSION);
        assert!(!st.has_seed);
        assert!(st.fingerprint.is_none());
    }

    #[test]
    fn has_seed_handler_reflects_state() {
        let mut s = fresh_state();
        assert!(!handle_has_seed(&s));
        let _ = handle_generate(&mut s, GenerateRequest::default()).unwrap();
        assert!(handle_has_seed(&s));
    }

    #[test]
    fn generate_handler_creates_seed() {
        let mut s = fresh_state();
        let req = GenerateRequest { word_count: 24 };
        let resp = handle_generate(&mut s, req).unwrap();
        assert_eq!(resp.words.len(), 24);
        assert!(handle_has_seed(&s));
    }

    #[test]
    fn generate_handler_rejects_bad_word_count() {
        let mut s = fresh_state();
        let req = GenerateRequest { word_count: 13 };
        let err = handle_generate(&mut s, req).unwrap_err();
        assert_eq!(err, BaoSeedError::InvalidMnemonicLength);
    }

    #[test]
    fn import_handler_round_trip_then_wipe() {
        let mut s = fresh_state();
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        let req = ImportRequest { words };
        let _ = handle_import(&mut s, req).unwrap();
        assert!(handle_has_seed(&s));
        handle_wipe(&mut s).unwrap();
        assert!(!handle_has_seed(&s));
    }

    #[test]
    fn import_handler_rejects_invalid_mnemonic() {
        let mut s = fresh_state();
        let words = MnemonicWords::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon"
                .split_whitespace()
                .map(alloc::string::String::from)
                .collect(),
        )
        .unwrap();
        let req = ImportRequest { words };
        let err = handle_import(&mut s, req).unwrap_err();
        assert_eq!(err, BaoSeedError::InvalidMnemonic);
    }
}
