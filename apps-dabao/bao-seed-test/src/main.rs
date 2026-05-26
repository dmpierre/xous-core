//! Integration test app for the bao-seed Xous service.
//!
//! Exercises the lifecycle opcodes via IPC to verify on-device behavior:
//! - Service registration / connectivity
//! - `Status` and `HasSeed` queries
//! - `Generate` → seed loaded → fingerprint
//! - `Wipe` → idempotency
//! - `Import` of a valid BIP-39 mnemonic
//! - Rejection of invalid mnemonic (bad checksum)
//! - Rejection of double-generate (must wipe first)
//!
//! Run with: `cargo xtask dabao bao-seed-test` (or the corresponding
//! `xous-build` invocation), then read the log output for the PASS/FAIL
//! summary.

use bao_seed_api::{BaoSeedClient, BaoSeedError, MnemonicWords, PROTOCOL_VERSION};

// =============================================================================
// Test runner (mirrors the zcashapp-test pattern)
// =============================================================================

struct TestRunner {
    passed: u32,
    failed: u32,
}

impl TestRunner {
    fn new() -> Self {
        Self { passed: 0, failed: 0 }
    }

    fn pass(&mut self, name: &str) {
        self.passed += 1;
        log::info!("[PASS] {}", name);
    }

    fn fail(&mut self, name: &str, reason: &str) {
        self.failed += 1;
        log::error!("[FAIL] {}: {}", name, reason);
    }

    fn summary(&self) {
        let total = self.passed + self.failed;
        log::info!("========================================");
        log::info!(
            "Results: {} passed, {} failed (of {} total)",
            self.passed,
            self.failed,
            total
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
// Test cases
// =============================================================================

fn t_status_initial(client: &BaoSeedClient, r: &mut TestRunner) {
    let name = "status_initial";
    match client.status() {
        Ok(s) => {
            if s.protocol_version != PROTOCOL_VERSION {
                r.fail(name, "protocol version mismatch");
                return;
            }
            // We don't assert has_seed=false here because dabao keeps the
            // seed in RAM only — a prior run in the same boot can leave
            // a seed loaded. The wipe_then_status test will assert empty
            // explicitly.
            r.pass(name);
        }
        Err(e) => r.fail(name, &alloc::format!("{:?}", e)),
    }
}

fn t_wipe_then_empty(client: &BaoSeedClient, r: &mut TestRunner) {
    let name = "wipe_then_empty";
    if let Err(e) = client.wipe() {
        r.fail(name, &alloc::format!("wipe: {:?}", e));
        return;
    }
    match client.has_seed() {
        Ok(false) => r.pass(name),
        Ok(true) => r.fail(name, "has_seed still true after wipe"),
        Err(e) => r.fail(name, &alloc::format!("has_seed: {:?}", e)),
    }
}

fn t_wipe_is_idempotent(client: &BaoSeedClient, r: &mut TestRunner) {
    let name = "wipe_is_idempotent";
    if let Err(e) = client.wipe() {
        r.fail(name, &alloc::format!("first wipe: {:?}", e));
        return;
    }
    if let Err(e) = client.wipe() {
        r.fail(name, &alloc::format!("second wipe: {:?}", e));
        return;
    }
    r.pass(name);
}

fn t_generate_creates_seed(client: &BaoSeedClient, r: &mut TestRunner) {
    let name = "generate_creates_seed";
    let _ = client.wipe();
    match client.generate(24) {
        Ok(resp) => {
            if resp.words.len() != 24 {
                r.fail(name, "expected 24 words");
                return;
            }
            match client.has_seed() {
                Ok(true) => r.pass(name),
                Ok(false) => r.fail(name, "has_seed is false after generate"),
                Err(e) => r.fail(name, &alloc::format!("has_seed: {:?}", e)),
            }
        }
        Err(e) => r.fail(name, &alloc::format!("{:?}", e)),
    }
}

fn t_status_reflects_seed(client: &BaoSeedClient, r: &mut TestRunner) {
    let name = "status_reflects_seed";
    let _ = client.wipe();
    let gen = match client.generate(24) {
        Ok(g) => g,
        Err(e) => {
            r.fail(name, &alloc::format!("generate: {:?}", e));
            return;
        }
    };
    match client.status() {
        Ok(s) => {
            if !s.has_seed {
                r.fail(name, "status.has_seed false");
            } else if s.fingerprint != Some(gen.fingerprint) {
                r.fail(name, "status fingerprint != generate fingerprint");
            } else {
                r.pass(name);
            }
        }
        Err(e) => r.fail(name, &alloc::format!("{:?}", e)),
    }
}

fn t_double_generate_rejected(client: &BaoSeedClient, r: &mut TestRunner) {
    let name = "double_generate_rejected";
    let _ = client.wipe();
    if let Err(e) = client.generate(24) {
        r.fail(name, &alloc::format!("first generate: {:?}", e));
        return;
    }
    match client.generate(24) {
        Ok(_) => r.fail(name, "second generate succeeded; should have errored"),
        Err(bao_seed_api::ApiError::Service(BaoSeedError::SeedAlreadyLoaded)) => r.pass(name),
        Err(e) => r.fail(name, &alloc::format!("wrong error: {:?}", e)),
    }
}

fn t_import_valid_mnemonic(client: &BaoSeedClient, r: &mut TestRunner) {
    let name = "import_valid_mnemonic";
    let _ = client.wipe();
    let words = match MnemonicWords::new(
        "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about"
            .split_whitespace()
            .map(alloc::string::String::from)
            .collect(),
    ) {
        Ok(w) => w,
        Err(e) => {
            r.fail(name, &alloc::format!("words: {:?}", e));
            return;
        }
    };
    match client.import(words) {
        Ok(_) => match client.has_seed() {
            Ok(true) => r.pass(name),
            Ok(false) => r.fail(name, "has_seed false after import"),
            Err(e) => r.fail(name, &alloc::format!("has_seed: {:?}", e)),
        },
        Err(e) => r.fail(name, &alloc::format!("import: {:?}", e)),
    }
}

fn t_import_invalid_mnemonic_rejected(client: &BaoSeedClient, r: &mut TestRunner) {
    let name = "import_invalid_mnemonic_rejected";
    let _ = client.wipe();
    // 12 × "abandon" — invalid BIP-39 checksum.
    let words = match MnemonicWords::new(
        "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon"
            .split_whitespace()
            .map(alloc::string::String::from)
            .collect(),
    ) {
        Ok(w) => w,
        Err(e) => {
            r.fail(name, &alloc::format!("words: {:?}", e));
            return;
        }
    };
    match client.import(words) {
        Ok(_) => r.fail(name, "import accepted invalid mnemonic"),
        Err(bao_seed_api::ApiError::Service(BaoSeedError::InvalidMnemonic)) => r.pass(name),
        Err(e) => r.fail(name, &alloc::format!("wrong error: {:?}", e)),
    }
}

// =============================================================================
// Main
// =============================================================================

extern crate alloc;

fn main() {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("bao-seed-test: starting integration tests");

    // Give the bao-seed service a moment to register.
    let tt = ticktimer_server::Ticktimer::new().expect("ticktimer");
    tt.sleep_ms(500).ok();

    let client = match BaoSeedClient::new() {
        Ok(c) => c,
        Err(e) => {
            log::error!("bao-seed-test: cannot connect to bao-seed: {:?}", e);
            return;
        }
    };

    let mut r = TestRunner::new();

    t_status_initial(&client, &mut r);
    t_wipe_then_empty(&client, &mut r);
    t_wipe_is_idempotent(&client, &mut r);
    t_generate_creates_seed(&client, &mut r);
    t_status_reflects_seed(&client, &mut r);
    t_double_generate_rejected(&client, &mut r);
    t_import_valid_mnemonic(&client, &mut r);
    t_import_invalid_mnemonic_rejected(&client, &mut r);

    // Leave the device empty when we're done.
    let _ = client.wipe();

    r.summary();
}
