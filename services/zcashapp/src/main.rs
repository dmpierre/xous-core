//! Zcash Shielded Transaction Signing Service for Xous
//!
//! This service provides secure Zcash shielded transaction signing
//! for Baochip-1x hardware running Xous OS, companion to the Zodl
//! mobile wallet.
//!
//! # Architecture
//!
//! The mobile wallet (Zodl) handles blockchain sync, note selection,
//! and ZK proof generation. This service holds the spending key and
//! signs PCZTs (Partially Created Zcash Transactions) after user
//! confirmation on the trusted display.
//!
//! # Docs consulted
//!
//! - ZIP-32: Shielded Hierarchical Deterministic Wallets
//! - PCZT format: Partially Created Zcash Transaction
//! - Zcash Protocol Specification (NU6)

// On bare metal (target_os = "none") we must be no_std. On the firmware
// target (target_os = "xous") and on host tests we want std so we can use
// `std::thread::Builder` to give the message-loop thread a generous stack
// — the default 32 KiB main-thread stack the loader hands out is not
// enough for parsing/signing/serialising a multi-action PCZT (~12 KB).
//
// See `fn main` below: we wrap `service_main` in a 256 KiB thread, the
// same idiom used by `services/codec`, `services/modals`, and friends.
#![cfg_attr(target_os = "none", no_std)]
extern crate alloc;

// `crypto` holds the legacy in-firmware BIP-39/ZIP-32 key derivation
// and signing primitives. Real-target builds delegate all of that to
// bao-seed; the module is only compiled in for host-test code that
// drives the primitives directly without spinning up IPC.
#[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
mod crypto;
mod handlers;
mod platform;
mod serial;
mod signing;
mod state;
mod zip244;

use num_traits::FromPrimitive;
use zcashapp_common::{ZcashAppError, ZcashAppOp, SERVER_NAME};

fn main() -> ! {
    // Xous services run their main entry point on the loader-provided
    // initial thread, which has only 8 stack pages (32 KiB) reserved.
    // PCZT parse/sign on a real ~12 KB transaction comes very close to
    // that limit on the device; under load on real Baochip-1x hardware,
    // we observed a content-corruption bug where action[1].output
    // .enc_ciphertext was re-emitted with garbage spliced from adjacent
    // wire bytes (the same action's cv_net + nullifier suffix). The
    // pattern is consistent with stack pressure during the
    // `pczt::parse → low_level_signer roundtrip → redactor → serialize`
    // pipeline — which on x86 with an 8 MB host stack runs cleanly.
    //
    // Match the convention used by other heap-using Xous services
    // (codec, modals, gam, pddb, status, shellchat) and bootstrap into a
    // worker thread with a 256 KiB stack via `std::thread::Builder`.
    // The IPC server still registers under `SERVER_NAME` from this
    // worker thread, and the kernel demand-pages the stack region.
    // 1 MiB matches `pddb` / `modals` / `gam` (services that handle non-
    // trivial parsers/cryptography). 256 KiB was an under-budget that
    // happened to work for 1-action PCZTs but reproducibly corrupts
    // 2-action signed output (1950-byte response with spliced bytes)
    // even after the parse-then-Box optimization. Until the corruption
    // root cause is fully pinned down we keep generous headroom.
    const SERVICE_STACK_SIZE: usize = 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(SERVICE_STACK_SIZE)
        .spawn(wrapped_main)
        .expect("zcashapp: failed to spawn service worker thread")
        .join()
        .expect("zcashapp: service worker thread panicked")
}

fn wrapped_main() -> ! {
    service_main();
    panic!("zcashapp: service_main returned unexpectedly");
}

fn service_main() {
    log_server::init_wait().unwrap();
    log::info!("zcashapp: Starting Zcash App service");

    let xns = xous_names::XousNames::new().expect("zcashapp: Failed to connect to xous-names");

    let sid = xns
        .register_name(SERVER_NAME, None)
        .expect("zcashapp: Failed to register server name");

    log::info!("zcashapp: Registered as '{}'", SERVER_NAME);

    let mut state = state::ServiceState::new();

    if let Err(e) = state.init_platform() {
        log::error!("zcashapp: Failed to initialize platform: {:?}", e);
    }

    log::info!("zcashapp: Service initialized, entering message loop");

    loop {
        let msg = xous::receive_message(sid).expect("zcashapp: Failed to receive message");

        let opcode = ZcashAppOp::from_usize(msg.body.id());

        match opcode {
            Some(op) => {
                let result = handle_message(&mut state, op, msg);
                if let Err(e) = result {
                    log::warn!("zcashapp: Handler error for {:?}: {:?}", op, e);
                }
            }
            None => {
                if msg.body.id() != 0 {
                    log::warn!("zcashapp: Unknown opcode: {}", msg.body.id());
                }
            }
        }
    }
}

fn handle_message(
    state: &mut state::ServiceState,
    op: ZcashAppOp,
    mut msg: xous::MessageEnvelope,
) -> Result<(), ZcashAppError> {
    match op {
        ZcashAppOp::Ping => {
            xous::return_scalar(msg.sender, 0).ok();
        }

        ZcashAppOp::GetConfig => {
            log::info!("zcashapp: GetConfig");
            let has_seed = if state.has_seed() { 1 } else { 0 };
            xous::return_scalar2(
                msg.sender,
                zcashapp_common::PROTOCOL_VERSION as usize,
                has_seed,
            )
            .ok();
        }

        ZcashAppOp::InitSeed => {
            log::info!("zcashapp: InitSeed");
            match handlers::process_generate_mnemonic(state) {
                Ok(_words) => {
                    xous::return_scalar(msg.sender, 0).ok();
                }
                Err(e) => {
                    xous::return_scalar(msg.sender, e.code() as usize).ok();
                }
            }
        }

        ZcashAppOp::GetOrchardAddress => {
            log::info!("zcashapp: GetOrchardAddress");
            let mut buf = unsafe {
                xous_ipc::Buffer::from_memory_message_mut(msg.body.memory_message_mut().unwrap())
            };
            if let Ok(req) = buf.to_original::<zcashapp_common::SerialFrameData, _>() {
                let account = if req.data.len() >= 4 {
                    u32::from_le_bytes([req.data[0], req.data[1], req.data[2], req.data[3]])
                } else {
                    0
                };
                match handlers::process_get_address(state, account) {
                    Ok(addr_bytes) => {
                        let resp = zcashapp_common::SerialFrameData { data: addr_bytes.to_vec() };
                        buf.replace(resp).ok();
                    }
                    Err(e) => log::warn!("zcashapp: GetOrchardAddress failed: {:?}", e),
                }
            }
        }

        ZcashAppOp::GetOrchardFVK => {
            log::info!("zcashapp: GetOrchardFVK");
            let mut buf = unsafe {
                xous_ipc::Buffer::from_memory_message_mut(msg.body.memory_message_mut().unwrap())
            };
            if let Ok(req) = buf.to_original::<zcashapp_common::SerialFrameData, _>() {
                let account = if req.data.len() >= 4 {
                    u32::from_le_bytes([req.data[0], req.data[1], req.data[2], req.data[3]])
                } else {
                    0
                };
                match handlers::process_get_fvk(state, account) {
                    Ok(fvk_bytes) => {
                        let resp = zcashapp_common::SerialFrameData { data: fvk_bytes.to_vec() };
                        buf.replace(resp).ok();
                    }
                    Err(e) => log::warn!("zcashapp: GetOrchardFVK failed: {:?}", e),
                }
            }
        }

        ZcashAppOp::SignPczt => {
            log::info!("zcashapp: SignPczt");
            let mut buf = unsafe {
                xous_ipc::Buffer::from_memory_message_mut(msg.body.memory_message_mut().unwrap())
            };
            if let Ok(req) = buf.to_original::<zcashapp_common::SerialFrameData, _>() {
                if req.data.len() >= 37 {
                    let account = u32::from_le_bytes([req.data[0], req.data[1], req.data[2], req.data[3]]);
                    let sighash: [u8; 32] = req.data[4..36].try_into().unwrap();
                    let pczt_bytes = &req.data[36..];
                    let signed = handlers::process_sign_pczt(state, pczt_bytes, &sighash, account);
                    let resp = match signed {
                        Ok(signed_bytes) => zcashapp_common::SerialFrameData { data: signed_bytes },
                        Err(e) => {
                            log::warn!("zcashapp: SignPczt failed: {:?}", e);
                            // Return a 2-byte error sentinel: [0x00, status]. A real
                            // signed PCZT always starts with the 4-byte magic
                            // "PCZT" (0x50 0x43 0x5A 0x54), so the leading 0x00
                            // is unambiguous on the IPC return path. The client
                            // (zcashapp-api) decodes this back into a structured
                            // error.
                            let status = serial::error_to_status(&e);
                            zcashapp_common::SerialFrameData {
                                data: alloc::vec![0x00u8, status],
                            }
                        }
                    };
                    buf.replace(resp).ok();
                }
            }
        }

        ZcashAppOp::GetPcztStatus => {
            log::info!("zcashapp: GetPcztStatus");
            let ready = if state.has_seed() { 1 } else { 0 };
            xous::return_scalar(msg.sender, ready).ok();
        }

        ZcashAppOp::GenerateMnemonic => {
            log::info!("zcashapp: GenerateMnemonic (IPC)");
            match handlers::process_generate_mnemonic(state) {
                Ok(_words) => {
                    xous::return_scalar(msg.sender, 0).ok();
                }
                Err(e) => {
                    xous::return_scalar(msg.sender, e.code() as usize).ok();
                }
            }
        }

        ZcashAppOp::ImportMnemonic => {
            log::info!("zcashapp: ImportMnemonic (IPC)");
            let buf = unsafe {
                xous_ipc::Buffer::from_memory_message_mut(msg.body.memory_message_mut().unwrap())
            };
            if let Ok(req) = buf.to_original::<zcashapp_common::SerialFrameData, _>() {
                match handlers::process_import_mnemonic(state, &req.data) {
                    Ok(()) => log::info!("zcashapp: ImportMnemonic success"),
                    Err(e) => log::warn!("zcashapp: ImportMnemonic failed: {:?}", e),
                }
            }
        }

        ZcashAppOp::ClearSeed => {
            log::info!("zcashapp: ClearSeed (IPC)");
            match handlers::process_clear_seed(state) {
                Ok(()) => {
                    xous::return_scalar(msg.sender, 0).ok();
                }
                Err(e) => {
                    xous::return_scalar(msg.sender, e.code() as usize).ok();
                }
            }
        }

        ZcashAppOp::SerialFrame => {
            // Receive a raw serial frame from usb-bao1x (rkyv-serialized SerialFrameData).
            let mut buf = unsafe {
                xous_ipc::Buffer::from_memory_message_mut(
                    msg.body.memory_message_mut().unwrap(),
                )
            };
            if let Ok(req) = buf.to_original::<zcashapp_common::SerialFrameData, _>() {
                if !req.data.is_empty() {
                    let opcode = req.data[0];
                    let payload = if req.data.len() > 1 { &req.data[1..] } else { &[] };
                    let response = serial::process_serial_command(state, opcode, payload);
                    let resp = zcashapp_common::SerialFrameData { data: response };
                    buf.replace(resp).ok();
                }
            }
        }
    }

    Ok(())
}
