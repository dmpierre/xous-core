//! Integration test app for the zcashapp Zcash signing service.
//!
//! Exercises the zcashapp service via IPC to verify:
//! - Service connectivity (ping)
//! - Configuration retrieval
//! - Seed generation and clearing
//! - Orchard address derivation
//! - Full viewing key export
//!
//! Requires the zcashapp service to be running with `dev-mode` and `autoapprove`
//! features for unattended testing.
//!
//! Run with: cargo xtask dabao-emu zcashapp-test
//!
//! # SignPczt verification testing
//!
//! The device's local ZIP-244 sighash recomputation (see
//! `services/zcashapp/src/zip244.rs`) is intentionally **not** exercised
//! from this app. Building a fixture PCZT here requires `OsRng`-driven
//! orchard / pczt machinery whose IO finalizer hardcodes
//! `rand_core::OsRng`, so the byte stream is non-deterministic across
//! runs and any embedded fixture would silently rot. The host-level
//! cross-check `shielded_sighash_matches_full_signer` and the wire-level
//! mismatch test in `services/zcashapp/src/serial.rs` together cover the
//! same end-to-end behaviour (sighash recomputation, mismatch rejection,
//! IPC error sentinel) without that flakiness.

use zcashapp_api::ZcashAppClient;

// =============================================================================
// Test runner
// =============================================================================

struct TestRunner {
    passed: u32,
    failed: u32,
    skipped: u32,
}

impl TestRunner {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
        }
    }

    fn pass(&mut self, name: &str) {
        self.passed += 1;
        log::info!("[PASS] {}", name);
    }

    fn fail(&mut self, name: &str, reason: &str) {
        self.failed += 1;
        log::error!("[FAIL] {}: {}", name, reason);
    }

    #[allow(dead_code)]
    fn skip(&mut self, name: &str, reason: &str) {
        self.skipped += 1;
        log::warn!("[SKIP] {}: {}", name, reason);
    }

    fn summary(&self) {
        let total = self.passed + self.failed + self.skipped;
        log::info!("========================================");
        log::info!(
            "Results: {} passed, {} failed, {} skipped (of {} total)",
            self.passed, self.failed, self.skipped, total
        );
        if self.failed == 0 {
            log::info!("ALL TESTS PASSED");
        } else {
            log::error!("{} TEST(S) FAILED", self.failed);
        }
        log::info!("========================================");
    }
}

// =============================================================================
// Tests
// =============================================================================

fn test_ping(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.ping() {
        Ok(()) => runner.pass("ping"),
        Err(e) => runner.fail("ping", &format!("{:?}", e)),
    }
}

fn test_get_config(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.get_config() {
        Ok((version, has_seed)) => {
            log::info!("  protocol_version={}, has_seed={}", version, has_seed);
            if version == 1 {
                runner.pass("get_config");
            } else {
                runner.fail(
                    "get_config",
                    &format!("unexpected protocol version: {}", version),
                );
            }
        }
        Err(e) => runner.fail("get_config", &format!("{:?}", e)),
    }
}

fn test_generate_mnemonic(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.generate_mnemonic() {
        Ok(()) => runner.pass("generate_mnemonic"),
        Err(e) => runner.fail("generate_mnemonic", &format!("{:?}", e)),
    }
}

fn test_has_seed_after_generate(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.get_config() {
        Ok((_, has_seed)) => {
            if has_seed {
                runner.pass("has_seed_after_generate");
            } else {
                runner.fail("has_seed_after_generate", "seed not loaded after generate");
            }
        }
        Err(e) => runner.fail("has_seed_after_generate", &format!("{:?}", e)),
    }
}

fn test_get_address(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.get_address(0) {
        Ok(addr) => {
            log::info!("  address: {}", hex::encode(addr));
            if addr.iter().any(|&b| b != 0) {
                runner.pass("get_address");
            } else {
                runner.fail("get_address", "address is all zeros");
            }
        }
        Err(e) => runner.fail("get_address", &format!("{:?}", e)),
    }
}

fn test_address_determinism(client: &ZcashAppClient, runner: &mut TestRunner) {
    let addr1 = client.get_address(0);
    let addr2 = client.get_address(0);

    match (addr1, addr2) {
        (Ok(a1), Ok(a2)) => {
            if a1 == a2 {
                runner.pass("address_determinism");
            } else {
                runner.fail("address_determinism", "same account gives different addresses");
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            runner.fail("address_determinism", &format!("{:?}", e))
        }
    }
}

fn test_different_accounts_different_addresses(client: &ZcashAppClient, runner: &mut TestRunner) {
    let addr0 = client.get_address(0);
    let addr1 = client.get_address(1);

    match (addr0, addr1) {
        (Ok(a0), Ok(a1)) => {
            if a0 != a1 {
                log::info!("  account 0: {}", hex::encode(a0));
                log::info!("  account 1: {}", hex::encode(a1));
                runner.pass("different_accounts");
            } else {
                runner.fail("different_accounts", "same address for different accounts");
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            runner.fail("different_accounts", &format!("{:?}", e))
        }
    }
}

fn test_get_fvk(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.get_fvk(0) {
        Ok(fvk) => {
            log::info!("  fvk: {}...{}", hex::encode(&fvk[..8]), hex::encode(&fvk[88..]));
            if fvk.iter().any(|&b| b != 0) {
                runner.pass("get_fvk");
            } else {
                runner.fail("get_fvk", "FVK is all zeros");
            }
        }
        Err(e) => runner.fail("get_fvk", &format!("{:?}", e)),
    }
}

fn test_status_ready(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.get_status() {
        Ok(ready) => {
            if ready {
                runner.pass("status_ready");
            } else {
                runner.fail("status_ready", "device not ready after seed generation");
            }
        }
        Err(e) => runner.fail("status_ready", &format!("{:?}", e)),
    }
}

fn test_clear_seed(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.clear_seed() {
        Ok(()) => runner.pass("clear_seed"),
        Err(e) => runner.fail("clear_seed", &format!("{:?}", e)),
    }
}

fn test_no_seed_after_clear(client: &ZcashAppClient, runner: &mut TestRunner) {
    match client.get_config() {
        Ok((_, has_seed)) => {
            if !has_seed {
                runner.pass("no_seed_after_clear");
            } else {
                runner.fail("no_seed_after_clear", "seed still present after clear");
            }
        }
        Err(e) => runner.fail("no_seed_after_clear", &format!("{:?}", e)),
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() -> ! {
    run_tests();
    xous::terminate_process(0)
}

fn run_tests() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);

    log::info!("========================================");
    log::info!("zcashapp-test: Zcash signing service integration tests");
    log::info!("========================================");

    // Brief pause for console attachment
    #[cfg(target_os = "xous")]
    {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        tt.sleep_ms(2000).unwrap();
    }

    log::info!("Connecting to zcashapp service...");
    let client = match ZcashAppClient::new() {
        Ok(c) => {
            log::info!("Connected to zcashapp service");
            c
        }
        Err(e) => {
            log::error!("Failed to connect to zcashapp: {:?}", e);
            log::error!("Is the zcashapp service running with dev-mode + autoapprove?");
            return;
        }
    };

    let mut runner = TestRunner::new();

    // Connectivity
    test_ping(&client, &mut runner);
    test_get_config(&client, &mut runner);

    // Seed management
    test_generate_mnemonic(&client, &mut runner);
    test_has_seed_after_generate(&client, &mut runner);

    // Key derivation (requires seed)
    test_get_address(&client, &mut runner);
    test_address_determinism(&client, &mut runner);
    test_different_accounts_different_addresses(&client, &mut runner);
    test_get_fvk(&client, &mut runner);
    test_status_ready(&client, &mut runner);

    // Cleanup
    test_clear_seed(&client, &mut runner);
    test_no_seed_after_clear(&client, &mut runner);

    // Summary
    runner.summary();
}
