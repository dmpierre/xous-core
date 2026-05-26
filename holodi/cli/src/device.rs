//! `holodi {ping,firmware-version,config,status}` — device-general operations.
//!
//! These talk to the ethapp service on the device (0xE7 frames). They
//! don't touch Eth or Zec specifics — the underlying hardware is the
//! Baochip companion, which is implicit at the holodi entry point.
//!
//! Future hardening: when ethapp grows an explicit firmware-build
//! identifier opcode (matching zcashapp's `OP_GET_FIRMWARE_VERSION =
//! 0x9B`), `firmware_version` will surface the git-describe string.
//! For now it reports the protocol semver returned by
//! GetAppConfiguration (e.g. `v0.1.0 protocol=1`).

use anyhow::{bail, Result};

use crate::transport::{Transport, STATUS_OK};

const OP_PING: u8 = 0xFF;
const OP_GET_CONFIG: u8 = 0x01;
const OP_GET_ADDRESS: u8 = 0x51;

// ethapp serial status meaning "no seed loaded" — handy for the
// status/config dashboards to distinguish "seed absent" from a real
// device fault.
const STATUS_ERR_NO_SEED: u8 = 0x03;

/// Round-trip a PING frame; print `pong` on success.
pub fn ping(t: &mut Transport) -> Result<()> {
    let (status, _) = t.command(OP_PING, &[])?;
    if status != STATUS_OK {
        bail!("ping failed (status: 0x{:02x})", status);
    }
    println!("pong");
    Ok(())
}

/// Print the device firmware version. Uses ethapp's
/// `GetAppConfiguration` (0x01) response: semver + protocol byte.
/// (Will be replaced by an explicit `OP_GET_FIRMWARE_VERSION` opcode
/// returning a git-describe string once ethapp grows one.)
pub fn firmware_version(t: &mut Transport) -> Result<()> {
    let (status, payload) = t.command(OP_GET_CONFIG, &[])?;
    if status != STATUS_OK {
        bail!("firmware-version failed (status: 0x{:02x})", status);
    }
    if payload.len() < 4 {
        bail!("unexpected config response length: {}", payload.len());
    }
    println!(
        "v{}.{}.{} protocol={}",
        payload[0], payload[1], payload[2], payload[3]
    );
    Ok(())
}

/// Print ethapp's `GetAppConfiguration` response in human form.
pub fn config(t: &mut Transport) -> Result<()> {
    let (status, payload) = t.command(OP_GET_CONFIG, &[])?;
    if status != STATUS_OK {
        bail!("config failed (status: 0x{:02x})", status);
    }
    if payload.len() < 5 {
        println!("raw: {}", hex::encode(&payload));
        return Ok(());
    }
    let blind_signing = payload[4] & 0x01 != 0;
    let eth2 = payload[4] & 0x02 != 0;
    println!(
        "device version: v{}.{}.{}",
        payload[0], payload[1], payload[2]
    );
    println!("protocol:       {}", payload[3]);
    println!("blind signing:  {}", blind_signing);
    println!("eth2 support:   {}", eth2);
    Ok(())
}

/// One-shot dashboard combining reachability, config, and seed status.
pub fn status(t: &mut Transport, host: &str) -> Result<()> {
    // Ping first — if the device is unreachable, everything else is
    // noise.
    match t.command(OP_PING, &[]) {
        Ok((STATUS_OK, _)) => println!("device:   reachable"),
        Ok((s, _)) => {
            println!("device:   error (status 0x{:02x})", s);
            return Ok(());
        }
        Err(e) => {
            println!("device:   unreachable ({})", e);
            return Ok(());
        }
    }

    println!("host:     {}", host);

    if let Ok((STATUS_OK, payload)) = t.command(OP_GET_CONFIG, &[]) {
        if payload.len() >= 4 {
            println!(
                "firmware: v{}.{}.{} protocol={}",
                payload[0], payload[1], payload[2], payload[3]
            );
        }
    }

    // Same proxy `holodi seed status` uses: try to derive address[0].
    // STATUS_OK + 20-byte payload ⇒ seed is loaded. NO_SEED ⇒ vault
    // is empty. Anything else is a real device error.
    let path = bip44_eth_path(0, 0, 0);
    match t.command(OP_GET_ADDRESS, &path) {
        Ok((STATUS_OK, payload)) if payload.len() >= 20 => {
            println!("seed:     present");
            println!("          eth[0] = 0x{}", hex::encode(&payload[..20]));
        }
        Ok((STATUS_ERR_NO_SEED, _)) => {
            println!("seed:     absent — run `holodi seed import` or `seed generate`");
        }
        Ok((s, _)) => {
            println!("seed:     unknown (device error 0x{:02x})", s);
        }
        Err(e) => {
            println!("seed:     query failed ({})", e);
        }
    }
    Ok(())
}

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
        buf.extend_from_slice(&c.to_be_bytes());
    }
    buf
}
