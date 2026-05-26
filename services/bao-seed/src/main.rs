//! bao-seed Xous service entry point.
//!
//! Owns the BIP-39 seed bytes; exposes a typed IPC API for lifecycle
//! operations (PR 1) and signing (PR 2+).
//!
//! Pattern A — sign-inside-vault. The `Seed` newtype and any derived
//! private-key material never leave this process.

#![allow(dead_code)]

extern crate alloc;

mod handlers;
mod orchard;
mod platform;
mod secp256k1;
mod seed;
mod state;

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use bao_seed_common::{BaoSeedOp, SERVER_NAME};
#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use num_traits::FromPrimitive;

fn main() -> ! {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    {
        service_main();
        panic!("bao-seed: service_main returned unexpectedly");
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    loop {
        xous::wait_event();
    }
}

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
fn service_main() {
    log_server::init_wait().unwrap();
    log::info!("bao-seed: starting seed vault service");

    let xns = xous_names::XousNames::new().expect("bao-seed: cannot connect to xous-names");
    let sid = xns
        .register_name(SERVER_NAME, None)
        .expect("bao-seed: cannot register server name");
    log::info!("bao-seed: registered as '{}'", SERVER_NAME);

    // Build the platform. On dabao there is no PDDB (no external SPI flash) —
    // store_seed / load_seed / delete_seed degrade to in-memory only via
    // XousPlatform's current impl. State machine handles that gracefully.
    #[cfg(target_os = "xous")]
    let platform = platform::XousPlatform::new().expect("bao-seed: XousPlatform init failed");
    #[cfg(not(target_os = "xous"))]
    let platform = platform::HostPlatform::new();

    let mut state = state::ServiceState::new(platform);

    // Try to restore a persisted seed (no-op on dabao — no PDDB).
    match state.load_persisted_seed() {
        Ok(true) => log::info!("bao-seed: restored seed from persistent storage"),
        Ok(false) => log::info!("bao-seed: no persisted seed (start empty)"),
        Err(e) => log::warn!("bao-seed: load_persisted_seed failed: {:?}", e),
    }

    log::info!("bao-seed: entering message loop");
    loop {
        let msg = xous::receive_message(sid).expect("bao-seed: receive_message failed");
        let op = BaoSeedOp::from_usize(msg.body.id());
        match op {
            Some(BaoSeedOp::Status) => handlers::handle_status(&state, msg),
            Some(BaoSeedOp::HasSeed) => handlers::handle_has_seed(&state, msg),
            Some(BaoSeedOp::Generate) => handlers::handle_generate(&mut state, msg),
            Some(BaoSeedOp::Import) => handlers::handle_import(&mut state, msg),
            Some(BaoSeedOp::Wipe) => handlers::handle_wipe(&mut state, msg),
            Some(BaoSeedOp::Zip32SeedFingerprint) => {
                handlers::handle_zip32_seed_fingerprint(&state, msg)
            }
            Some(BaoSeedOp::ImportSeedBytes) => {
                handlers::handle_import_seed_bytes(&mut state, msg)
            }
            Some(BaoSeedOp::Secp256k1GetPubkey) => {
                handlers::handle_secp256k1_get_pubkey(&state, msg)
            }
            Some(BaoSeedOp::Secp256k1Sign) => handlers::handle_secp256k1_sign(&state, msg),
            Some(BaoSeedOp::OrchardGetFvk) => handlers::handle_orchard_get_fvk(&state, msg),
            Some(BaoSeedOp::OrchardSign) => handlers::handle_orchard_sign(&mut state, msg),
            Some(BaoSeedOp::Disconnect) => {
                // Sent by client Drop. No reply.
            }
            None => {
                if msg.body.id() != 0 {
                    log::warn!("bao-seed: unknown opcode: {}", msg.body.id());
                }
            }
        }
    }
}
