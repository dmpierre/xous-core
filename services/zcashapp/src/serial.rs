//! Serial frame protocol handler for zcashapp (0xE8 magic byte).
//!
//! Wire format (same framing as ethapp's 0xE7, different magic byte):
//!   Request:  [0xE8] [length: u16 LE] [opcode: u8] [payload...]
//!   Response: [0xE8] [length: u16 LE] [status: u8] [payload...]

use alloc::vec;
use alloc::vec::Vec;

use crate::state::ServiceState;

/// Magic byte identifying zcashapp frames.
#[allow(dead_code)]
pub const MAGIC: u8 = 0xE8;

// --- Status codes ---
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR_REJECTED: u8 = 0x01;
pub const STATUS_ERR_INVALID_OPCODE: u8 = 0x02;
pub const STATUS_ERR_INVALID_PARAM: u8 = 0x03;
pub const STATUS_ERR_INVALID_DATA: u8 = 0x04;
pub const STATUS_ERR_UNSUPPORTED: u8 = 0x05;
pub const STATUS_ERR_INTERNAL: u8 = 0x06;
pub const STATUS_ERR_CRYPTO: u8 = 0x07;
pub const STATUS_ERR_NO_SEED: u8 = 0x08;
/// Host-supplied sighash disagrees with the device's locally-computed
/// ZIP-244 digest. See `crate::zip244::compute_shielded_sighash`.
pub const STATUS_ERR_SIGHASH_MISMATCH: u8 = 0x0D;

// --- Serial opcodes (match ZcashAppOp but as u8 for wire) ---
pub const OP_PING: u8 = 0xFF;
pub const OP_GET_CONFIG: u8 = 0x90;
#[allow(dead_code)]
pub const OP_INIT_SEED: u8 = 0x91;
pub const OP_GET_ORCHARD_ADDRESS: u8 = 0x92;
pub const OP_GET_ORCHARD_FVK: u8 = 0x93;
pub const OP_SIGN_PCZT: u8 = 0x94;
pub const OP_GET_PCZT_STATUS: u8 = 0x95;
/// One-shot diagnostic: parse a PCZT, run a parse→serialize roundtrip,
/// return the result so the host can localise corruption without
/// needing the (single-endpoint) serial console for `log::info!`
/// output. See handler in `process_serial_command` for the response
/// layout.
pub const OP_PCZT_DIAG: u8 = 0x96;
/// Diagnostic: parse a PCZT, apply the firmware's exact redactor
/// closure (no signing), serialize, and re-parse — return the
/// re-parsed action bytes so the host can compare against the input
/// and localise whether the corruption fires in the redact step.
pub const OP_PCZT_DIAG_REDACT: u8 = 0x97;
/// Diagnostic: parse a PCZT, run the production signer wrapper with a
/// NOOP closure (no `action.sign` calls — just enters and exits
/// `sign_orchard_with`), call `finish()`, then redact + serialize +
/// reparse. Used to determine whether the corruption is in the
/// `Signer` wrapper itself (entry/exit) vs. in the `action.sign`
/// mutation called inside the closure.
pub const OP_PCZT_DIAG_SIGN_NOOP: u8 = 0x98;
/// Diagnostic: bisect inside the sign-orchard closure, running a
/// configurable subset of primitives (alpha read / randomize / VK::from
/// / compare / rsk.sign / apply_signature / Action::sign). Used after
/// the workaround landed and we discovered some inputs (e.g. those
/// with a memo) still produce corruption — the bug is in a primitive
/// shared between Action::sign and apply_signature, not in the
/// compare-vs-verify branch alone.
///
/// Payload: [account: u32 LE][mode: u8][pczt: ...]
pub const OP_PCZT_DIAG_SIGN_PRIMITIVE: u8 = 0x99;

/// Return the 32-byte ZIP-32 seed fingerprint for the device's seed.
/// Lets the host record an `Imported { Spending { derivation } }`
/// account purpose (with `Zip32Derivation { seed_fingerprint, account_index }`)
/// instead of plain `ViewOnly`, mirroring zcash-devtool's behaviour.
/// Does not expose the seed itself; the fingerprint is one-way.
pub const OP_GET_SEED_FINGERPRINT: u8 = 0x9A;

/// Return the firmware build identifier (captured at compile time from
/// `git describe --always --dirty --tags`, with `ZCASHAPP_VERSION` env
/// override). Lets the host confirm what's actually flashed on the
/// device — useful when reasoning about whether a behaviour change
/// reflects a code change or just heap-state noise. Response payload is
/// the UTF-8 version string with no length prefix; the transport's
/// frame length delimits it.
pub const OP_GET_FIRMWARE_VERSION: u8 = 0x9B;

// --- Seed management opcodes ---
pub const OP_GENERATE_MNEMONIC: u8 = 0xA0;
pub const OP_IMPORT_MNEMONIC: u8 = 0xA1;
pub const OP_CLEAR_SEED: u8 = 0xA2;

/// Process a complete serial frame and return a response payload.
pub fn process_serial_command(state: &mut ServiceState, opcode: u8, payload: &[u8]) -> Vec<u8> {
    match opcode {
        OP_PING => {
            let mut r = vec![STATUS_OK];
            r.extend_from_slice(b"pong");
            r
        }

        OP_GET_FIRMWARE_VERSION => {
            let mut r = vec![STATUS_OK];
            r.extend_from_slice(env!("ZCASHAPP_VERSION").as_bytes());
            r
        }

        OP_GET_CONFIG => {
            let mut out = vec![STATUS_OK];
            // Protocol version (u32 LE)
            out.extend_from_slice(&zcashapp_common::PROTOCOL_VERSION.to_le_bytes());
            // Has seed (u8)
            out.push(if state.has_seed() { 1 } else { 0 });
            // Network (u8): 0 = mainnet, 1 = testnet
            #[cfg(feature = "testnet")]
            out.push(1);
            #[cfg(not(feature = "testnet"))]
            out.push(0);
            out
        }

        OP_GENERATE_MNEMONIC => match crate::handlers::process_generate_mnemonic(state) {
            Ok(words) => {
                #[allow(unused_mut)]
                let mut out = vec![STATUS_OK];
                #[cfg(feature = "dev-mode")]
                {
                    let mnemonic_str = words.join(" ");
                    out.extend_from_slice(mnemonic_str.as_bytes());
                }
                #[cfg(not(feature = "dev-mode"))]
                {
                    let _ = words;
                }
                out
            }
            Err(e) => vec![error_to_status(&e)],
        },

        OP_IMPORT_MNEMONIC => {
            if payload.is_empty() {
                return vec![STATUS_ERR_INVALID_DATA];
            }
            match crate::handlers::process_import_mnemonic(state, payload) {
                Ok(()) => vec![STATUS_OK],
                Err(e) => vec![error_to_status(&e)],
            }
        }

        OP_CLEAR_SEED => match crate::handlers::process_clear_seed(state) {
            Ok(()) => vec![STATUS_OK],
            Err(e) => vec![error_to_status(&e)],
        },

        OP_GET_ORCHARD_ADDRESS => {
            // Payload: [account: u32 LE] (optional, defaults to 0)
            let account = if payload.len() >= 4 {
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            } else {
                0
            };
            match crate::handlers::process_get_address(state, account) {
                Ok(addr_bytes) => {
                    let mut out = vec![STATUS_OK];
                    out.extend_from_slice(&addr_bytes);
                    out
                }
                Err(e) => vec![error_to_status(&e)],
            }
        }

        OP_GET_ORCHARD_FVK => {
            // Payload: [account: u32 LE] (optional, defaults to 0)
            let account = if payload.len() >= 4 {
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            } else {
                0
            };
            match crate::handlers::process_get_fvk(state, account) {
                Ok(fvk_bytes) => {
                    let mut out = vec![STATUS_OK];
                    out.extend_from_slice(&fvk_bytes);
                    out
                }
                Err(e) => vec![error_to_status(&e)],
            }
        }

        OP_SIGN_PCZT => {
            // Payload: [account: u32 LE (4)] [sighash: 32 bytes] [pczt_bytes...]
            if payload.len() < 37 {
                return vec![STATUS_ERR_INVALID_DATA];
            }
            let account =
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let sighash: [u8; 32] = payload[4..36].try_into().unwrap();
            let pczt_bytes = &payload[36..];
            match crate::handlers::process_sign_pczt(state, pczt_bytes, &sighash, account) {
                Ok(signed_bytes) => {
                    let mut out = vec![STATUS_OK];
                    out.extend_from_slice(&signed_bytes);
                    out
                }
                Err(e) => vec![error_to_status(&e)],
            }
        }

        OP_GET_SEED_FINGERPRINT => {
            // Delegate to bao-seed — the seed never leaves the vault.
            #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
            {
                let client = match state.bao_seed() {
                    Ok(c) => c,
                    Err(e) => return vec![error_to_status(&e)],
                };
                match client.zip32_seed_fingerprint() {
                    Ok(fp) => {
                        let mut out = vec![STATUS_OK];
                        out.extend_from_slice(&fp);
                        out
                    }
                    Err(bao_seed_api::ApiError::Service(bao_seed_api::BaoSeedError::NoSeed)) => {
                        vec![STATUS_ERR_NO_SEED]
                    }
                    Err(_) => vec![STATUS_ERR_INTERNAL],
                }
            }
            #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
            {
                let seed = match crate::handlers::get_seed(state) {
                    Ok(s) => s,
                    Err(e) => return vec![error_to_status(&e)],
                };
                let fp = match zip32::fingerprint::SeedFingerprint::from_seed(seed.as_bytes()) {
                    Some(f) => f,
                    None => return vec![STATUS_ERR_CRYPTO],
                };
                let mut out = vec![STATUS_OK];
                out.extend_from_slice(&fp.to_bytes());
                out
            }
        }

        OP_GET_PCZT_STATUS => {
            // Status query — currently signing is synchronous, so just report idle/ready
            let mut out = vec![STATUS_OK];
            out.push(if state.has_seed() { 0x01 } else { 0x00 }); // ready flag
            out
        }

        OP_PCZT_DIAG => {
            // Diagnostic-only opcode — does NOT touch the seed.
            //
            // Response layout (all fixed offsets so the host can decode):
            //   [STATUS_OK]                                           // 1 byte
            //   [parse_ok: u8]                                        // 1 byte
            //   [action_count: u8]                                    // 1 byte
            //   [reserialized_len: u32 LE]                            // 4 bytes
            //   [identical: u8]                                       // 1 byte
            //   [diff_offset: u32 LE]                                 // 4 bytes  (0xFFFFFFFF if identical)
            //   [for action 0: enc_head[16], enc_tail[16],
            //                  cv_net[32], nullifier[32]]             // 96 bytes
            //   [for action 1: same]                                  // 96 bytes
            // Total: 12 + 192 = 204 bytes when parse OK and >=2 actions.
            //
            // If parse fails, response is just [STATUS_OK, 0, 0, 0,0,0,0, 0, 0xff,0xff,0xff,0xff].
            use pczt::Pczt;
            let mut out = Vec::with_capacity(1 + 11 + 192);
            out.push(STATUS_OK);

            match Pczt::parse(payload) {
                Ok(parsed) => {
                    out.push(1); // parse_ok
                    let actions = parsed.orchard().actions();
                    let action_count = actions.len() as u8;
                    out.push(action_count);

                    // Run the parse->serialize roundtrip on a clone.
                    let cloned = parsed.clone();
                    let reserialized = cloned.serialize();
                    out.extend_from_slice(&(reserialized.len() as u32).to_le_bytes());

                    let identical = reserialized.as_slice() == payload;
                    out.push(if identical { 1 } else { 0 });
                    let diff_offset: u32 = if identical {
                        0xFFFF_FFFF
                    } else {
                        let mut idx = 0u32;
                        for (i, (a, b)) in payload.iter().zip(reserialized.iter()).enumerate() {
                            if a != b {
                                idx = i as u32;
                                break;
                            }
                        }
                        // If they're prefix-equal but lengths differ, point
                        // at the shorter length (where the divergence
                        // effectively starts).
                        if idx == 0 && reserialized.len() != payload.len() {
                            idx = core::cmp::min(payload.len(), reserialized.len()) as u32;
                        }
                        idx
                    };
                    out.extend_from_slice(&diff_offset.to_le_bytes());

                    // Per-action sample bytes (up to 2 actions).
                    let take = core::cmp::min(2, actions.len());
                    for action in &actions[..take] {
                        let enc = action.output().enc_ciphertext();
                        let head_n = core::cmp::min(16, enc.len());
                        let tail_off = enc.len().saturating_sub(16);
                        // enc head 16
                        let mut head16 = [0u8; 16];
                        head16[..head_n].copy_from_slice(&enc[..head_n]);
                        out.extend_from_slice(&head16);
                        // enc tail 16
                        let mut tail16 = [0u8; 16];
                        let tail_slice = &enc[tail_off..];
                        let copy_n = core::cmp::min(16, tail_slice.len());
                        tail16[..copy_n].copy_from_slice(&tail_slice[..copy_n]);
                        out.extend_from_slice(&tail16);
                        // cv_net 32
                        let cv = action.cv_net();
                        let mut cv32 = [0u8; 32];
                        let cv_n = core::cmp::min(32, cv.len());
                        cv32[..cv_n].copy_from_slice(&cv[..cv_n]);
                        out.extend_from_slice(&cv32);
                        // nullifier 32
                        let nf = action.spend().nullifier();
                        let mut nf32 = [0u8; 32];
                        let nf_n = core::cmp::min(32, nf.len());
                        nf32[..nf_n].copy_from_slice(&nf[..nf_n]);
                        out.extend_from_slice(&nf32);
                    }
                }
                Err(_) => {
                    // [STATUS_OK, parse_ok=0, action_count=0, len=0, identical=0, diff_offset=0xffffffff]
                    out.push(0); // parse_ok
                    out.push(0); // action_count
                    out.extend_from_slice(&0u32.to_le_bytes());
                    out.push(0); // identical
                    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
                }
            }
            out
        }

        // Diagnostic opcodes 0x98/0x99 — these drove the multi-recv
        // corruption bisection (see memory: zcashapp_multi_recv_corruption.md,
        // resolved via Path 2b). They derive the Orchard spending key
        // locally from the seed, which post-bao-seed migration would
        // require leaking seed bytes back through IPC. The bug they
        // diagnose is fixed in production; on real-target builds they
        // fall through to STATUS_ERR_INVALID_OPCODE.
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        OP_PCZT_DIAG_SIGN_PRIMITIVE => {
            // Payload: [account: u32 LE][mode: u8][pczt: ...]
            //
            // Modes (cumulative — each mode adds one operation past the
            // previous):
            //   0 NOOP     — parse + Signer::new + sign_orchard_with(no-op) + finish + redact + ser + reparse
            //   1 ALPHA    — + read action.spend.alpha (no math)
            //   2 RAND     — + ask.randomize(&alpha) (Pallas scalar mul)
            //   3 VK       — + VerificationKey::from(&rsk) (Pallas scalar mul → point)
            //   4 CMP      — + (action.spend.rk == rk_derived) compare
            //   5 SIGN     — + rsk.sign(rng, &sighash) (RedPallas Schnorr; result discarded, NOT assigned)
            //   6 APPLY    — + action.apply_signature(sighash, sig) (verify-then-assign)
            //   7 ORIG     — Action::sign full original path (compare-then-assign), used to confirm bug repro
            //
            // The first mode whose output diverges from the input bytes
            // (or fails to reparse) names the corrupting primitive.
            //
            // Response layout: same as OP_PCZT_DIAG_REDACT, plus an
            // additional [mode_run: u8] echoed at offset 7.
            //   [STATUS_OK]
            //   [parse_ok: u8]
            //   [serialized_len: u32 LE]
            //   [reparse_ok: u8]
            //   [action_count: u8]
            //   [mode_run: u8]
            //   for each up to 2 actions:
            //     [enc_head: 16][enc_tail: 16][cv_net: 32][nullifier: 32]
            use pczt::Pczt;
            use pczt::roles::low_level_signer::Signer;
            use pczt::roles::redactor::Redactor;
            use crate::signing::SignError;
            use orchard::primitives::redpallas;

            if payload.len() < 5 {
                return vec![STATUS_ERR_INVALID_DATA];
            }
            let account = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let mode = payload[4];
            let pczt_bytes = &payload[5..];

            // Derive ask from the device's seed.
            let seed = match crate::handlers::get_seed(state) {
                Ok(s) => s,
                Err(_) => return vec![STATUS_ERR_NO_SEED],
            };
            let sk = match crate::crypto::derive_spending_key(&seed, crate::handlers::coin_type(), account) {
                Ok(s) => s,
                Err(_) => return vec![STATUS_ERR_CRYPTO],
            };
            let ask = orchard::keys::SpendAuthorizingKey::from(&sk);

            let parsed = match Pczt::parse(pczt_bytes) {
                Ok(p) => p,
                Err(_) => {
                    let mut out = vec![STATUS_OK];
                    out.push(0); // parse_ok = false
                    out.extend_from_slice(&0u32.to_le_bytes());
                    out.push(0); // reparse_ok
                    out.push(0); // action_count
                    out.push(mode);
                    return out;
                }
            };

            // Compute local sighash for use in primitives 5 / 6 / 7.
            let sighash = match crate::zip244::compute_shielded_sighash(&parsed) {
                Ok(s) => s,
                Err(_) => return vec![STATUS_ERR_INVALID_DATA],
            };

            // Per-action RNG. We need fresh-seeded randomness for the
            // signing modes; using the trng directly via state.rng()
            // borrows mutably alongside our other borrows. Easier: pull
            // 32 bytes of entropy into a ChaChaRng-equivalent. For
            // diagnostic purposes we don't need cryptographic strength
            // here (the produced sigs aren't used).
            let mut rng = state.rng();

            // Run primitives. We capture intermediate values per action;
            // for read-only modes (1-5) we deliberately discard results
            // so the only externally-visible effect should be... nothing.
            // For modes 6/7 we mutate spend_auth_sig.
            let signer = Signer::new(parsed);
            let signer = match signer.sign_orchard_with(|_pczt, bundle, _tx_modifiable| -> Result<(), SignError> {
                if mode == 0 {
                    return Ok(());
                }
                for action in bundle.actions_mut() {
                    let alpha_opt = action.spend().alpha();
                    let alpha = match alpha_opt {
                        Some(a) => *a,
                        None => continue,
                    };
                    if mode == 1 { continue; }
                    let rsk = ask.randomize(&alpha);
                    if mode == 2 { core::hint::black_box(&rsk); continue; }
                    let rk_derived = redpallas::VerificationKey::from(&rsk);
                    if mode == 3 { core::hint::black_box(&rk_derived); continue; }
                    let cmp = action.spend().rk() == &rk_derived;
                    core::hint::black_box(cmp);
                    if mode == 4 { continue; }
                    if !cmp {
                        // Not our key for this action — skip the rest.
                        continue;
                    }
                    let sig: redpallas::Signature<redpallas::SpendAuth> =
                        rsk.sign(&mut rng, &sighash);
                    if mode == 5 { core::hint::black_box(&sig); continue; }
                    if mode == 6 {
                        // apply_signature path (current workaround)
                        let _ = action.apply_signature(sighash, sig);
                        continue;
                    }
                    if mode == 7 {
                        // Original Action::sign path — should reproduce the bug.
                        let _ = action.sign(sighash, &ask, &mut rng);
                        continue;
                    }
                }
                Ok(())
            }) {
                Ok(s) => s,
                Err(_) => return vec![STATUS_ERR_INTERNAL],
            };

            let pczt_after = signer.finish();
            let redacted = Redactor::new(pczt_after)
                .redact_global_with(|mut g| { g.clear_proprietary(); })
                .redact_orchard_with(|mut r| {
                    r.redact_actions(|mut ar| {
                        ar.clear_spend_recipient();
                        ar.clear_spend_value();
                        ar.clear_spend_rho();
                        ar.clear_spend_rseed();
                        ar.clear_spend_fvk();
                        ar.clear_spend_witness();
                        ar.clear_spend_alpha();
                        ar.clear_spend_zip32_derivation();
                        ar.clear_spend_dummy_sk();
                        ar.clear_output_recipient();
                        ar.clear_output_value();
                        ar.clear_output_rseed();
                        ar.clear_output_ock();
                        ar.clear_output_zip32_derivation();
                        ar.clear_output_user_address();
                        ar.clear_spend_proprietary();
                        ar.clear_output_proprietary();
                        ar.clear_rcv();
                    });
                    r.clear_zkproof();
                    r.clear_bsk();
                })
                .finish();
            let serialized = redacted.serialize();

            let mut out = Vec::with_capacity(8 + 1 + 192);
            out.push(STATUS_OK);
            out.push(1); // parse_ok
            out.extend_from_slice(&(serialized.len() as u32).to_le_bytes());
            match Pczt::parse(&serialized) {
                Ok(reparsed) => {
                    out.push(1); // reparse_ok
                    let actions = reparsed.orchard().actions();
                    let action_count = actions.len() as u8;
                    out.push(action_count);
                    out.push(mode);
                    let take = core::cmp::min(2, actions.len());
                    for action in &actions[..take] {
                        let enc = action.output().enc_ciphertext();
                        let head_n = core::cmp::min(16, enc.len());
                        let tail_off = enc.len().saturating_sub(16);
                        let mut head16 = [0u8; 16];
                        head16[..head_n].copy_from_slice(&enc[..head_n]);
                        out.extend_from_slice(&head16);
                        let mut tail16 = [0u8; 16];
                        let tail_slice = &enc[tail_off..];
                        let copy_n = core::cmp::min(16, tail_slice.len());
                        tail16[..copy_n].copy_from_slice(&tail_slice[..copy_n]);
                        out.extend_from_slice(&tail16);
                        let cv = action.cv_net();
                        let mut cv32 = [0u8; 32];
                        let cv_n = core::cmp::min(32, cv.len());
                        cv32[..cv_n].copy_from_slice(&cv[..cv_n]);
                        out.extend_from_slice(&cv32);
                        let nf = action.spend().nullifier();
                        let mut nf32 = [0u8; 32];
                        let nf_n = core::cmp::min(32, nf.len());
                        nf32[..nf_n].copy_from_slice(&nf[..nf_n]);
                        out.extend_from_slice(&nf32);
                    }
                }
                Err(_) => {
                    out.push(0); // reparse_ok = false
                    out.push(0); // action_count
                    out.push(mode);
                }
            }
            out
        }

        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        OP_PCZT_DIAG_SIGN_NOOP => {
            // Diagnostic: drive the *production* sign path's wrapper
            // through a NOOP closure (no action.sign calls), then run
            // the same redactor closure as production, serialize, and
            // re-parse. If this corrupts, the bug is in the
            // `Signer::new + sign_orchard_with(noop) + finish()`
            // wrapper (most likely codegen pathology in pczt 0.6's
            // signer state management on RV32). If this is clean, the
            // bug is specifically in `action.sign(...)` — orchard
            // 0.13's RedPallas signing on RV32.
            //
            // Response layout: same as OP_PCZT_DIAG_REDACT.
            use pczt::Pczt;
            use pczt::roles::low_level_signer::Signer;
            use pczt::roles::redactor::Redactor;
            use crate::signing::SignError;
            let mut out = Vec::with_capacity(8 + 192);
            out.push(STATUS_OK);
            match Pczt::parse(payload) {
                Ok(parsed) => {
                    out.push(1); // parse_ok

                    let signer = Signer::new(parsed);
                    let signer = signer.sign_orchard_with(
                        |_pczt, _bundle, _tx_modifiable| -> Result<(), SignError> { Ok(()) }
                    ).expect("noop sign_orchard_with cannot fail");
                    let pczt_after_signer = signer.finish();

                    let redacted = Redactor::new(pczt_after_signer)
                        .redact_global_with(|mut g| { g.clear_proprietary(); })
                        .redact_orchard_with(|mut r| {
                            r.redact_actions(|mut ar| {
                                ar.clear_spend_recipient();
                                ar.clear_spend_value();
                                ar.clear_spend_rho();
                                ar.clear_spend_rseed();
                                ar.clear_spend_fvk();
                                ar.clear_spend_witness();
                                ar.clear_spend_alpha();
                                ar.clear_spend_zip32_derivation();
                                ar.clear_spend_dummy_sk();
                                ar.clear_output_recipient();
                                ar.clear_output_value();
                                ar.clear_output_rseed();
                                ar.clear_output_ock();
                                ar.clear_output_zip32_derivation();
                                ar.clear_output_user_address();
                                ar.clear_spend_proprietary();
                                ar.clear_output_proprietary();
                                ar.clear_rcv();
                            });
                            r.clear_zkproof();
                            r.clear_bsk();
                        })
                        .finish();
                    let serialized = redacted.serialize();
                    out.extend_from_slice(&(serialized.len() as u32).to_le_bytes());
                    match Pczt::parse(&serialized) {
                        Ok(reparsed) => {
                            out.push(1); // reparse_ok
                            let actions = reparsed.orchard().actions();
                            let action_count = actions.len() as u8;
                            out.push(action_count);
                            let take = core::cmp::min(2, actions.len());
                            for action in &actions[..take] {
                                let enc = action.output().enc_ciphertext();
                                let head_n = core::cmp::min(16, enc.len());
                                let tail_off = enc.len().saturating_sub(16);
                                let mut head16 = [0u8; 16];
                                head16[..head_n].copy_from_slice(&enc[..head_n]);
                                out.extend_from_slice(&head16);
                                let mut tail16 = [0u8; 16];
                                let tail_slice = &enc[tail_off..];
                                let copy_n = core::cmp::min(16, tail_slice.len());
                                tail16[..copy_n].copy_from_slice(&tail_slice[..copy_n]);
                                out.extend_from_slice(&tail16);
                                let cv = action.cv_net();
                                let mut cv32 = [0u8; 32];
                                let cv_n = core::cmp::min(32, cv.len());
                                cv32[..cv_n].copy_from_slice(&cv[..cv_n]);
                                out.extend_from_slice(&cv32);
                                let nf = action.spend().nullifier();
                                let mut nf32 = [0u8; 32];
                                let nf_n = core::cmp::min(32, nf.len());
                                nf32[..nf_n].copy_from_slice(&nf[..nf_n]);
                                out.extend_from_slice(&nf32);
                            }
                        }
                        Err(_) => {
                            out.push(0); // reparse_ok = 0
                            out.push(0); // action_count
                        }
                    }
                }
                Err(_) => {
                    out.push(0);
                    out.extend_from_slice(&0u32.to_le_bytes());
                    out.push(0);
                    out.push(0);
                }
            }
            out
        }

        OP_PCZT_DIAG_REDACT => {
            // Diagnostic-only opcode — does NOT touch the seed and does NOT
            // call any of the signing roles. It runs the EXACT redactor
            // closure used by the production sign path against the input
            // PCZT, serializes, re-parses, and reports the action bytes
            // post-redact-and-reserialize.
            //
            // Response layout:
            //   [STATUS_OK]                                           // 1 byte
            //   [parse_ok: u8]                                        // 1 byte
            //   [redacted_serialize_len: u32 LE]                      // 4 bytes
            //   [reparse_ok: u8]                                      // 1 byte
            //   [reparsed_action_count: u8]                           // 1 byte
            //   for each up to 2 actions of the reparsed bundle:
            //     [enc_head: 16][enc_tail: 16]
            //     [cv_net: 32][nullifier: 32]                         // 96 bytes
            // Total: 8 + 192 = 200 bytes when full.
            use pczt::Pczt;
            use pczt::roles::redactor::Redactor;
            let mut out = Vec::with_capacity(8 + 192);
            out.push(STATUS_OK);
            match Pczt::parse(payload) {
                Ok(parsed) => {
                    out.push(1); // parse_ok
                    let redacted = Redactor::new(parsed)
                        .redact_global_with(|mut g| { g.clear_proprietary(); })
                        .redact_orchard_with(|mut r| {
                            r.redact_actions(|mut ar| {
                                ar.clear_spend_recipient();
                                ar.clear_spend_value();
                                ar.clear_spend_rho();
                                ar.clear_spend_rseed();
                                ar.clear_spend_fvk();
                                ar.clear_spend_witness();
                                ar.clear_spend_alpha();
                                ar.clear_spend_zip32_derivation();
                                ar.clear_spend_dummy_sk();
                                ar.clear_output_recipient();
                                ar.clear_output_value();
                                ar.clear_output_rseed();
                                ar.clear_output_ock();
                                ar.clear_output_zip32_derivation();
                                ar.clear_output_user_address();
                                ar.clear_spend_proprietary();
                                ar.clear_output_proprietary();
                                ar.clear_rcv();
                            });
                            r.clear_zkproof();
                            r.clear_bsk();
                        })
                        .finish();
                    let serialized = redacted.serialize();
                    out.extend_from_slice(&(serialized.len() as u32).to_le_bytes());
                    match Pczt::parse(&serialized) {
                        Ok(reparsed) => {
                            out.push(1); // reparse_ok
                            let actions = reparsed.orchard().actions();
                            let action_count = actions.len() as u8;
                            out.push(action_count);
                            let take = core::cmp::min(2, actions.len());
                            for action in &actions[..take] {
                                let enc = action.output().enc_ciphertext();
                                let head_n = core::cmp::min(16, enc.len());
                                let tail_off = enc.len().saturating_sub(16);
                                let mut head16 = [0u8; 16];
                                head16[..head_n].copy_from_slice(&enc[..head_n]);
                                out.extend_from_slice(&head16);
                                let mut tail16 = [0u8; 16];
                                let tail_slice = &enc[tail_off..];
                                let copy_n = core::cmp::min(16, tail_slice.len());
                                tail16[..copy_n].copy_from_slice(&tail_slice[..copy_n]);
                                out.extend_from_slice(&tail16);
                                let cv = action.cv_net();
                                let mut cv32 = [0u8; 32];
                                let cv_n = core::cmp::min(32, cv.len());
                                cv32[..cv_n].copy_from_slice(&cv[..cv_n]);
                                out.extend_from_slice(&cv32);
                                let nf = action.spend().nullifier();
                                let mut nf32 = [0u8; 32];
                                let nf_n = core::cmp::min(32, nf.len());
                                nf32[..nf_n].copy_from_slice(&nf[..nf_n]);
                                out.extend_from_slice(&nf32);
                            }
                        }
                        Err(_) => {
                            out.push(0); // reparse_ok = 0
                            out.push(0); // action_count
                        }
                    }
                }
                Err(_) => {
                    out.push(0); // parse_ok
                    out.extend_from_slice(&0u32.to_le_bytes()); // serialize_len
                    out.push(0); // reparse_ok
                    out.push(0); // action_count
                }
            }
            out
        }

        _ => vec![STATUS_ERR_INVALID_OPCODE],
    }
}

pub fn error_to_status(err: &zcashapp_common::ZcashAppError) -> u8 {
    use zcashapp_common::ZcashAppError;
    match err {
        ZcashAppError::Success => STATUS_OK,
        ZcashAppError::RejectedByUser => STATUS_ERR_REJECTED,
        ZcashAppError::InvalidOpcode => STATUS_ERR_INVALID_OPCODE,
        ZcashAppError::InvalidParameter => STATUS_ERR_INVALID_PARAM,
        ZcashAppError::InvalidData => STATUS_ERR_INVALID_DATA,
        ZcashAppError::UnsupportedOperation => STATUS_ERR_UNSUPPORTED,
        ZcashAppError::InternalError => STATUS_ERR_INTERNAL,
        ZcashAppError::CryptoError => STATUS_ERR_CRYPTO,
        ZcashAppError::NoSeed => STATUS_ERR_NO_SEED,
        ZcashAppError::InvalidPczt => STATUS_ERR_INVALID_DATA,
        ZcashAppError::SerializationError => STATUS_ERR_INTERNAL,
        ZcashAppError::StorageError => STATUS_ERR_INTERNAL,
        ZcashAppError::UiError => STATUS_ERR_INTERNAL,
        ZcashAppError::SighashMismatch => STATUS_ERR_SIGHASH_MISMATCH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServiceState;
    use zcashapp_common::ZcashAppError;

    fn fresh_state() -> ServiceState {
        ServiceState::new()
    }

    // Pre-import the standard test mnemonic into a fresh state so the
    // signing-dependent paths can derive an Orchard SK on the host.
    fn state_with_seed() -> ServiceState {
        let mut state = fresh_state();
        let mnemonic =
            b"abandon abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon about";
        let seed = crate::crypto::seed_from_mnemonic(mnemonic);
        state.imported_seed = Some(seed);
        state
    }

    #[test]
    fn ping_returns_pong() {
        let mut state = fresh_state();
        let resp = process_serial_command(&mut state, OP_PING, &[]);
        let mut expected = vec![STATUS_OK];
        expected.extend_from_slice(b"pong");
        assert_eq!(resp, expected);
    }

    #[test]
    fn unknown_opcode_returns_invalid_opcode() {
        let mut state = fresh_state();
        for op in [0x00u8, 0x10, 0x42, 0x7F, 0x80, 0xC0, 0xEE] {
            let resp = process_serial_command(&mut state, op, &[]);
            assert_eq!(
                resp,
                vec![STATUS_ERR_INVALID_OPCODE],
                "opcode 0x{:02x} should be invalid",
                op
            );
        }
    }

    #[test]
    fn get_config_layout_no_seed() {
        let mut state = fresh_state();
        let resp = process_serial_command(&mut state, OP_GET_CONFIG, &[]);
        // [status][version: u32 LE][has_seed: u8][network: u8]
        assert_eq!(resp.len(), 1 + 4 + 1 + 1);
        assert_eq!(resp[0], STATUS_OK);
        let version = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]);
        assert_eq!(version, zcashapp_common::PROTOCOL_VERSION);
        assert_eq!(resp[5], 0, "has_seed should be 0 for fresh state");
        assert!(resp[6] == 0 || resp[6] == 1, "network byte must be 0 or 1");
    }

    #[test]
    fn get_config_reflects_seed_presence() {
        let mut state = state_with_seed();
        let resp = process_serial_command(&mut state, OP_GET_CONFIG, &[]);
        assert_eq!(resp[0], STATUS_OK);
        assert_eq!(resp[5], 1, "has_seed should be 1 after import");
    }

    #[test]
    fn import_mnemonic_empty_payload_rejected() {
        let mut state = fresh_state();
        let resp = process_serial_command(&mut state, OP_IMPORT_MNEMONIC, &[]);
        assert_eq!(resp, vec![STATUS_ERR_INVALID_DATA]);
    }

    #[test]
    fn import_mnemonic_invalid_word_count_rejected() {
        let mut state = fresh_state();
        let resp = process_serial_command(
            &mut state,
            OP_IMPORT_MNEMONIC,
            b"abandon abandon abandon", // 3 words — not 12 or 24
        );
        // process_import_mnemonic returns InvalidData => STATUS_ERR_INVALID_DATA.
        assert_eq!(resp, vec![STATUS_ERR_INVALID_DATA]);
    }

    #[test]
    fn import_mnemonic_then_address_round_trip() {
        let mut state = fresh_state();
        let mnemonic =
            b"abandon abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon about";
        let resp = process_serial_command(&mut state, OP_IMPORT_MNEMONIC, mnemonic);
        assert_eq!(resp, vec![STATUS_OK]);

        // Default account 0, payload omitted.
        let resp = process_serial_command(&mut state, OP_GET_ORCHARD_ADDRESS, &[]);
        assert_eq!(resp[0], STATUS_OK);
        assert_eq!(resp.len(), 1 + 43, "raw Orchard address is 43 bytes");

        // Same with explicit account=0 LE — must yield the identical address.
        let resp2 = process_serial_command(
            &mut state,
            OP_GET_ORCHARD_ADDRESS,
            &0u32.to_le_bytes(),
        );
        assert_eq!(resp, resp2);
    }

    #[test]
    fn get_address_no_seed_returns_no_seed() {
        let mut state = fresh_state();
        let resp = process_serial_command(
            &mut state,
            OP_GET_ORCHARD_ADDRESS,
            &0u32.to_le_bytes(),
        );
        // dev-mode feature is OFF in `cargo test` (default features only),
        // so missing seed must surface as STATUS_ERR_NO_SEED.
        assert_eq!(resp, vec![STATUS_ERR_NO_SEED]);
    }

    #[test]
    fn get_fvk_returns_96_bytes() {
        let mut state = state_with_seed();
        let resp = process_serial_command(
            &mut state,
            OP_GET_ORCHARD_FVK,
            &0u32.to_le_bytes(),
        );
        assert_eq!(resp[0], STATUS_OK);
        assert_eq!(resp.len(), 1 + 96);
    }

    #[test]
    fn sign_pczt_too_short_payload_rejected() {
        let mut state = state_with_seed();
        // Payload must be >= 4 (account) + 32 (sighash) + 1 (pczt byte) = 37.
        for len in [0usize, 1, 4, 35, 36] {
            let payload = vec![0u8; len];
            let resp = process_serial_command(&mut state, OP_SIGN_PCZT, &payload);
            assert_eq!(
                resp,
                vec![STATUS_ERR_INVALID_DATA],
                "payload len {} must be rejected",
                len
            );
        }
    }

    #[test]
    fn sign_pczt_invalid_pczt_bytes_returns_invalid_data() {
        let mut state = state_with_seed();
        // 4 (account=0) + 32 (zeros sighash) + 4 garbage pczt bytes.
        let mut payload = vec![0u8; 4 + 32];
        payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let resp = process_serial_command(&mut state, OP_SIGN_PCZT, &payload);
        // InvalidPczt maps to STATUS_ERR_INVALID_DATA via error_to_status.
        assert_eq!(resp, vec![STATUS_ERR_INVALID_DATA]);
    }

    #[test]
    fn pczt_status_reflects_seed_state() {
        // No seed: status_byte == 0x00.
        let mut state = fresh_state();
        let resp = process_serial_command(&mut state, OP_GET_PCZT_STATUS, &[]);
        assert_eq!(resp.len(), 2);
        assert_eq!(resp[0], STATUS_OK);
        assert_eq!(resp[1], 0x00);

        // With seed: 0x01.
        let mut state = state_with_seed();
        let resp = process_serial_command(&mut state, OP_GET_PCZT_STATUS, &[]);
        assert_eq!(resp[1], 0x01);
    }

    #[test]
    fn clear_seed_round_trip() {
        let mut state = state_with_seed();
        assert!(state.has_seed());
        let resp = process_serial_command(&mut state, OP_CLEAR_SEED, &[]);
        assert_eq!(resp, vec![STATUS_OK]);
        assert!(!state.has_seed());
    }

    #[test]
    fn error_to_status_is_total_and_unique_for_distinct_classes() {
        // Sanity-check the error mapping — these are the codes the host
        // CLI's `status_message` interprets, so any drift breaks UX.
        assert_eq!(error_to_status(&ZcashAppError::Success), STATUS_OK);
        assert_eq!(error_to_status(&ZcashAppError::RejectedByUser), STATUS_ERR_REJECTED);
        assert_eq!(error_to_status(&ZcashAppError::InvalidOpcode), STATUS_ERR_INVALID_OPCODE);
        assert_eq!(error_to_status(&ZcashAppError::InvalidParameter), STATUS_ERR_INVALID_PARAM);
        assert_eq!(error_to_status(&ZcashAppError::InvalidData), STATUS_ERR_INVALID_DATA);
        assert_eq!(error_to_status(&ZcashAppError::UnsupportedOperation), STATUS_ERR_UNSUPPORTED);
        assert_eq!(error_to_status(&ZcashAppError::CryptoError), STATUS_ERR_CRYPTO);
        assert_eq!(error_to_status(&ZcashAppError::NoSeed), STATUS_ERR_NO_SEED);
        // InvalidPczt must funnel into INVALID_DATA so the host shows
        // "Invalid data" rather than a numeric mystery.
        assert_eq!(error_to_status(&ZcashAppError::InvalidPczt), STATUS_ERR_INVALID_DATA);
        // SighashMismatch gets its own dedicated wire code so the host can
        // distinguish "this PCZT is malformed" from "your sighash is wrong"
        // without a string match. Required for the OP_SIGN_PCZT contract.
        assert_eq!(
            error_to_status(&ZcashAppError::SighashMismatch),
            STATUS_ERR_SIGHASH_MISMATCH
        );
    }

    #[test]
    fn opcode_constants_match_protocol_doc() {
        // Pin opcode bytes — these are the shipping wire protocol with the host.
        // Changing them silently would break every deployed host CLI.
        assert_eq!(OP_PING, 0xFF);
        assert_eq!(OP_GET_CONFIG, 0x90);
        assert_eq!(OP_GET_ORCHARD_ADDRESS, 0x92);
        assert_eq!(OP_GET_ORCHARD_FVK, 0x93);
        assert_eq!(OP_SIGN_PCZT, 0x94);
        assert_eq!(OP_GET_PCZT_STATUS, 0x95);
        assert_eq!(OP_GENERATE_MNEMONIC, 0xA0);
        assert_eq!(OP_IMPORT_MNEMONIC, 0xA1);
        assert_eq!(OP_CLEAR_SEED, 0xA2);
        // Status codes:
        assert_eq!(STATUS_OK, 0x00);
        assert_eq!(STATUS_ERR_REJECTED, 0x01);
        assert_eq!(STATUS_ERR_NO_SEED, 0x08);
    }
}
