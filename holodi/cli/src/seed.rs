//! `holodi seed ...` — bao-seed lifecycle via ethapp's USB protocol.
//!
//! All operations transit ethapp on the device (0xE7 frames). ethapp's
//! seed-mgmt opcodes (Import/Generate/Clear) now delegate to bao-seed
//! via Xous IPC — see commit 08bf79e625a. So `holodi seed import …`
//! ends up in the actual vault.

use anyhow::{bail, Result};

use crate::transport::{Transport, STATUS_OK};
use crate::tty;

// Opcodes — must match ethapp_common::EthAppOp variants. Lifted from
// beth/main.rs.
const OP_PING: u8 = 0xFF;
const OP_GET_ADDRESS: u8 = 0x51;
const OP_GENERATE_MNEMONIC: u8 = 0x62;
const OP_IMPORT_MNEMONIC: u8 = 0x61;
const OP_CLEAR_SEED: u8 = 0x63;

// Serial status codes from ethapp_serial::* that we want to distinguish.
const STATUS_ERR_NO_SEED: u8 = 0x03;

pub fn status(t: &mut Transport) -> Result<()> {
    // ethapp doesn't expose a direct bao-seed status proxy yet; use
    // Ping for connectivity and GetAddress(account 0) as a proxy for
    // "is a seed loaded". A success there means bao-seed has a seed.
    let (s, _) = t.command(OP_PING, &[])?;
    if s != STATUS_OK {
        bail!("device ping failed (status 0x{:02x})", s);
    }

    let path = bip44_eth_path(0, 0, 0);
    let (s, payload) = t.command(OP_GET_ADDRESS, &path)?;
    match s {
        STATUS_OK if payload.len() >= 20 => {
            println!("seed: present");
            println!("eth address[0]: 0x{}", hex::encode(&payload[..20]));
        }
        STATUS_ERR_NO_SEED => {
            println!("seed: absent");
        }
        _ => {
            println!("seed: unknown (device error 0x{:02x})", s);
        }
    }
    Ok(())
}

pub fn hasseed(t: &mut Transport) -> Result<()> {
    let path = bip44_eth_path(0, 0, 0);
    let (s, payload) = t.command(OP_GET_ADDRESS, &path)?;
    let present = s == STATUS_OK && payload.len() >= 20;
    if !present && s != STATUS_ERR_NO_SEED && s != STATUS_OK {
        // Be loud about unexpected statuses (e.g. internal error) so the
        // user doesn't think a real device fault is "no seed".
        bail!("device error 0x{:02x}", s);
    }
    println!("{}", if present { "true" } else { "false" });
    Ok(())
}

pub fn generate(t: &mut Transport) -> Result<()> {
    println!("Generating new mnemonic on device (via bao-seed)…");
    let (status, payload) = t.command(OP_GENERATE_MNEMONIC, &[])?;
    if status != STATUS_OK {
        bail!("seed generate failed (status: 0x{:02x})", status);
    }

    if payload.is_empty() {
        // Production build: words shown on the device display only.
        println!("Check the device screen for your recovery phrase.");
        println!("Wallet created.");
        return Ok(());
    }

    // Dev-mode build: device returned the mnemonic for transcription.
    let mnemonic = String::from_utf8_lossy(&payload);
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  DEVELOPER MODE — RECOVERY PHRASE SHOWN ON HOST             ║");
    println!("║  This is INSECURE. Production hardware shows the phrase     ║");
    println!("║  only on the device's secure display.                       ║");
    println!("║                                                              ║");
    println!("║  Write these words down on paper. Store securely.           ║");
    println!("║  This is the ONLY way to recover your wallet.               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    for (i, word) in words.iter().enumerate() {
        print!("  {:>2}. {:<12}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    if words.len() % 4 != 0 {
        println!();
    }
    println!();
    println!("Wallet created.");
    Ok(())
}

pub fn import(t: &mut Transport) -> Result<()> {
    // No-echo prompt so a pasted seed phrase doesn't land in scrollback
    // or shell history. Falls back to plain (echoing) read on non-Unix
    // or when stdin isn't a tty.
    let line = tty::read_line_no_echo(
        "Enter your BIP-39 mnemonic (12, 15, 18, 21, or 24 words; input is hidden): ",
    )?;

    let words: Vec<&str> = line.split_whitespace().collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        bail!(
            "expected 12, 15, 18, 21, or 24 words; got {}",
            words.len()
        );
    }
    println!("[{} words received]", words.len());

    let mnemonic = words.join(" ");
    let (status, _) = t.command(OP_IMPORT_MNEMONIC, mnemonic.as_bytes())?;
    if status != STATUS_OK {
        bail!("seed import failed (status: 0x{:02x})", status);
    }

    println!("Seed imported into vault.");

    // Show derived ETH address as a sanity check that the seed is loaded.
    let path = bip44_eth_path(0, 0, 0);
    if let Ok((s, payload)) = t.command(OP_GET_ADDRESS, &path) {
        if s == STATUS_OK && payload.len() >= 20 {
            println!("eth address[0]: 0x{}", hex::encode(&payload[..20]));
        }
    }
    Ok(())
}

pub fn wipe(t: &mut Transport) -> Result<()> {
    println!("This will wipe the master seed from the vault. Confirm on the device.");
    let (status, _) = t.command(OP_CLEAR_SEED, &[])?;
    if status != STATUS_OK {
        bail!("seed wipe failed (status: 0x{:02x})", status);
    }
    println!("Seed wiped.");
    Ok(())
}

/// Build a serialized BIP-44 Ethereum path `m/44'/60'/account'/change/index`
/// in the wire format the OP_GET_ADDRESS opcode expects.
///
/// Lifted from `beth`'s `bip44_payload`; this is the byte layout
/// ethapp's handler parses from the request body.
fn bip44_eth_path(account: u32, change: u32, index: u32) -> Vec<u8> {
    const HARDENED: u32 = 0x80000000;
    let components: [u32; 5] = [
        44 | HARDENED,
        60 | HARDENED,
        account | HARDENED,
        change,
        index,
    ];
    let mut buf = Vec::with_capacity(1 + 4 * components.len());
    buf.push(components.len() as u8);
    for c in &components {
        // ethapp's serial layer expects big-endian path components
        // (matches beth's `bip44_payload`).
        buf.extend_from_slice(&c.to_be_bytes());
    }
    buf
}
