//! Opcode handlers for zcashapp.
//!
//! Each handler takes a mutable reference to ServiceState and returns
//! a result. Handlers are called from both the serial dispatcher and
//! the Xous IPC message loop.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
use crate::crypto;
use crate::signing;
use crate::state::ServiceState;
use crate::zip244;
use zcashapp_common::ZcashAppError;

/// Map a `bao-seed-api` ApiError onto a `ZcashAppError`. `NoSeed`
/// gets its own variant; other failures fold into CryptoError.
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
fn map_bao_seed_err(e: bao_seed_api::ApiError) -> ZcashAppError {
    match e {
        bao_seed_api::ApiError::Service(bao_seed_api::BaoSeedError::NoSeed) => {
            ZcashAppError::NoSeed
        }
        _ => ZcashAppError::CryptoError,
    }
}

// --- Seed management (delegated to bao-seed) ---

/// Generate a 24-word BIP39 mnemonic via bao-seed. Mnemonic crosses the
/// boundary for one-time display only — the seed never does.
pub fn process_generate_mnemonic(state: &mut ServiceState) -> Result<Vec<String>, ZcashAppError> {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    {
        let client = state.bao_seed()?;
        let _ = client.wipe();
        let resp = client.generate(24).map_err(|_| ZcashAppError::InternalError)?;
        let words: Vec<String> = resp.words.as_slice().to_vec();
        log::info!("zcashapp: Generated new mnemonic via bao-seed");
        Ok(words)
    }
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    {
        // Host-only test path: keep the legacy in-process derivation.
        let mut entropy = [0u8; 32];
        state.rng_fill_bytes(&mut entropy)?;
        let (words, seed) = crypto::generate_mnemonic(&mut entropy)?;
        state.imported_seed = Some(seed);
        Ok(words)
    }
}

/// Import a BIP39 mnemonic — push to bao-seed.
pub fn process_import_mnemonic(
    state: &mut ServiceState,
    mnemonic_bytes: &[u8],
) -> Result<(), ZcashAppError> {
    let mnemonic_str =
        core::str::from_utf8(mnemonic_bytes).map_err(|_| ZcashAppError::InvalidData)?;
    let words: Vec<String> = mnemonic_str.split_whitespace().map(String::from).collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        log::warn!("zcashapp: invalid mnemonic word count: {}", words.len());
        return Err(ZcashAppError::InvalidData);
    }

    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    {
        let mw = bao_seed_common::MnemonicWords::new(words)
            .map_err(|_| ZcashAppError::InvalidData)?;
        let client = state.bao_seed()?;
        let _ = client.wipe();
        client.import(mw).map_err(|_| ZcashAppError::InternalError)?;
        log::info!("zcashapp: Imported mnemonic into bao-seed");
        Ok(())
    }
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    {
        let seed = crypto::seed_from_mnemonic(mnemonic_bytes);
        state.imported_seed = Some(seed);
        Ok(())
    }
}

/// Clear the seed (delegates to bao-seed).
pub fn process_clear_seed(state: &mut ServiceState) -> Result<(), ZcashAppError> {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    {
        state.bao_seed()?
            .wipe()
            .map_err(|_| ZcashAppError::InternalError)?;
    }
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    {
        state.imported_seed = None;
    }
    log::info!("zcashapp: Seed cleared (via bao-seed)");
    Ok(())
}

// --- Key derivation ---

/// Get the seed, checking runtime cache first, then PDDB, then dev-mode fallback.
///
/// Host-only: real-target signing paths derive keys via bao-seed and
/// never call this. Retained for host-test code that exercises
/// `crypto::*` directly without spinning up an IPC service.
#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
pub(crate) fn get_seed(state: &ServiceState) -> Result<crypto::Seed, ZcashAppError> {
    // 1. Runtime cache
    if let Some(seed) = &state.imported_seed {
        return Ok(seed.clone());
    }

    // 2. Persistent storage
    if let Some(bytes) = state.load_seed() {
        if let Some(seed) = crypto::Seed::from_slice(&bytes) {
            return Ok(seed);
        }
    }

    // 3. Dev-mode fallback
    #[cfg(feature = "dev-mode")]
    {
        return Ok(crypto::get_dev_seed());
    }

    #[cfg(not(feature = "dev-mode"))]
    Err(ZcashAppError::NoSeed)
}

/// Get the coin type based on build configuration.
/// Mainnet=133 / testnet=1 per SLIP-44 / ZIP-32.
pub(crate) fn coin_type() -> u32 {
    #[cfg(feature = "testnet")]
    { 1 }
    #[cfg(not(feature = "testnet"))]
    { 133 }
}

/// Derive an Orchard address and return its 43-byte raw encoding.
///
/// The FVK is fetched from bao-seed; the address is computed locally
/// from the FVK (no secret material is touched in zcashapp).
pub fn process_get_address(state: &mut ServiceState, account: u32) -> Result<[u8; 43], ZcashAppError> {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    {
        let fvk_bytes = state.bao_seed()?
            .orchard_get_fvk(coin_type(), account)
            .map_err(map_bao_seed_err)?;
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes)
            .ok_or(ZcashAppError::CryptoError)?;
        let addr = fvk.address_at(0u32, orchard::keys::Scope::External);
        Ok(addr.to_raw_address_bytes())
    }
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    {
        let seed = get_seed(state)?;
        let addr = crypto::derive_orchard_address(&seed, coin_type(), account)?;
        Ok(crypto::address_to_raw_bytes(&addr))
    }
}

/// Derive an Orchard FullViewingKey and return its 96-byte encoding.
pub fn process_get_fvk(state: &mut ServiceState, account: u32) -> Result<[u8; 96], ZcashAppError> {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    {
        state.bao_seed()?
            .orchard_get_fvk(coin_type(), account)
            .map_err(map_bao_seed_err)
    }
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    {
        let seed = get_seed(state)?;
        let sk = crypto::derive_spending_key(&seed, coin_type(), account)?;
        let fvk = crypto::derive_fvk(&sk);
        Ok(crypto::fvk_to_bytes(&fvk))
    }
}

// --- PCZT signing (Phase 2) ---

/// Sign a PCZT: parse, display for review, sign Orchard spends, return signed bytes.
///
/// `account` selects which ZIP-32 account's spending key to use.
/// `sighash` is the 32-byte shielded sighash claimed by the companion wallet.
/// The device recomputes it locally from the parsed PCZT and rejects the
/// request with `ZcashAppError::SighashMismatch` if the two disagree —
/// the companion-supplied value is treated only as a sanity check; signatures
/// are produced with the device's locally-computed sighash.
pub fn process_sign_pczt(
    state: &mut ServiceState,
    pczt_bytes: &[u8],
    sighash: &[u8; 32],
    account: u32,
) -> Result<Vec<u8>, ZcashAppError> {
    log::info!("zcashapp: sign_pczt start, {} bytes", pczt_bytes.len());

    // Signing now routes through bao-seed (Pattern A — sign-inside-
    // vault). zcashapp parses the PCZT, computes the sighash, extracts
    // each Orchard action's (alpha, rk) pair, and sends them to bao-
    // seed; bao-seed returns raw spend-auth signatures. The spending
    // key never leaves the vault.

    // 1. Parse the PCZT, then immediately box it so subsequent moves
    //    through the signing pipeline (`parse → Signer::new → sign_orchard_with
    //    → Redactor → serialize`) operate on a heap-resident struct.
    //    The pczt 0.6 `Pczt` struct is small (~hundreds of bytes inline),
    //    but the parsed orchard sub-structure that flows through the
    //    low-level signer's `clone() → into_parsed → closure → serialize_from`
    //    contains by-value temporaries (`TransmittedNoteCiphertext` is
    //    692 bytes inline) that compound on the stack. Boxing the
    //    `Pczt` consolidates those moves to pointer-sized heap shuffles
    //    until we deliberately consume the box for the signing call.
    let pczt: Box<pczt::Pczt> = Box::new(signing::parse_pczt(pczt_bytes)?);
    log::info!("zcashapp: sign_pczt parsed PCZT");

    // (Removed: parse → serialize roundtrip diagnostic block from
    // commit 68c4bf40964. It served its purpose — confirming
    // parse + serialize are RV32-correct via OP_PCZT_DIAG / 0x96 — but
    // is suspected of itself being the trigger for the action[1].
    // enc_ciphertext corruption that fires in the production sign
    // path. The diag block clones the parsed Pczt (heap-allocates a
    // duplicate, including all the 580-byte enc_ciphertext Vecs),
    // serializes the clone, and drops both. The pattern of allocate-
    // big-then-free-and-immediately-allocate-big-again right before
    // the sign+redact+serialize call is plausibly leaving the heap
    // in a fragmented state on Xous + RV32 that the subsequent
    // operations land into pathologically. The OP_PCZT_DIAG_*
    // opcodes (0x96–0x99) cover everything this block was doing,
    // without contaminating the sign hot path.)

    // 2. Recompute the shielded sighash locally and verify it against the
    //    host's claim. This is defense-in-depth: a buggy or compromised
    //    companion wallet that disagrees with the device's view of the
    //    transaction must fail loudly. Even if the host's claim were
    //    correct, we always sign with the *local* value below.
    let local_sighash = zip244::compute_shielded_sighash(&pczt)?;
    if &local_sighash != sighash {
        log::warn!(
            "zcashapp: sighash mismatch — host_claim={} local={}",
            hex::encode(sighash),
            hex::encode(local_sighash),
        );
        return Err(ZcashAppError::SighashMismatch);
    }
    log::info!("zcashapp: sighash verified locally");

    // 3. Extract display info for user review
    let info = signing::extract_display_info(&pczt)?;
    log::info!(
        "zcashapp: PCZT review — {} actions, total output {} zatoshi",
        info.num_actions,
        info.total_output,
    );

    // 4. Show transaction details for user confirmation
    let review_fields = signing::format_review_fields(&info);
    let field_refs: Vec<(&str, &str)> = review_fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let approved = state.show_transaction_review(&field_refs, "Sign Zcash Transaction")?;
    if !approved {
        log::info!("zcashapp: User rejected PCZT signing");
        return Err(ZcashAppError::RejectedByUser);
    }

    // 5. Sign Orchard actions with the locally-computed sighash. The
    //    host-supplied value was a hint only; we deliberately do NOT use
    //    it here — even though we already proved equality above, future
    //    code paths (e.g. logging, side channels) should treat the host's
    //    bytes as untrusted.
    //
    //    Compute the raw spend-auth signatures (one per action,
    //    `None` for dummies / other-key actions). The wire response
    //    is the raw bytes, NOT a postcard-serialized PCZT — the
    //    1950-byte device-side serialize path is where the 512-byte-
    //    stride corruption lives on RV32, regardless of allocator.
    //    See `signing::compute_signatures` and
    //    `zcashapp_multi_recv_corruption.md`.
    log::info!("zcashapp: sign_pczt signing via bao-seed…");
    let actions = signing::extract_action_inputs_for_bao_seed(&pczt);
    let sigs = state.bao_seed()?
        .orchard_sign(coin_type(), account, local_sighash, actions)
        .map_err(map_bao_seed_err)?;
    log::info!("zcashapp: sign_pczt done, {} sigs", sigs.len());

    // Wire format: [n_actions: u8] [(has_sig: u8, sig: [u8; 64]) * n_actions]
    // Total = 1 + 65 * n_actions bytes. For a typical 2-action bundle: 131 bytes.
    // The leading STATUS_OK byte is prepended by `serial::process_serial_command`.
    let mut out = Vec::with_capacity(1 + sigs.len() * 65);
    out.push(sigs.len() as u8);
    for sig_opt in &sigs {
        match sig_opt {
            Some(sig) => {
                out.push(1u8);
                out.extend_from_slice(sig);
            }
            None => {
                out.push(0u8);
                out.extend_from_slice(&[0u8; 64]);
            }
        }
    }

    state.show_info(true, "Transaction signed");
    Ok(out)
}
