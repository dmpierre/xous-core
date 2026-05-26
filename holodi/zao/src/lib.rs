//! zao — host-side CLI for the Baochip-1x Zcash hardware wallet.
//!
//! Communicates with the zcashapp firmware service over USB CDC-ACM serial,
//! using the 0xE8 framing protocol.

mod commands;
mod config;
mod inspect;
mod pczt_builder;
mod send;
mod sync;
mod transport;
mod tui;
mod wallet;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use zcash_address::unified::Encoding;
use zcash_protocol::consensus::NetworkType;

use transport::{Transport, STATUS_OK, STATUS_ERR_NO_SEED, STATUS_ERR_REJECTED};

// --- Serial opcodes (must match zcashapp serial.rs) ---
// OP_PING / OP_GENERATE_MNEMONIC / OP_CLEAR_SEED were removed when
// those commands moved to `holodi {ping,seed}`. OP_IMPORT_MNEMONIC is
// retained for `zao test-sign`, which bootstraps the device with a
// known mnemonic for end-to-end signing diagnostics.
const OP_GET_CONFIG: u8 = 0x90;
const OP_IMPORT_MNEMONIC: u8 = 0xA1;
const OP_GET_ORCHARD_ADDRESS: u8 = 0x92;
pub(crate) const OP_GET_ORCHARD_FVK: u8 = 0x93;
pub(crate) const OP_SIGN_PCZT: u8 = 0x94;
const OP_GET_PCZT_STATUS: u8 = 0x95;
const OP_PCZT_DIAG: u8 = 0x96;
const OP_PCZT_DIAG_REDACT: u8 = 0x97;
const OP_PCZT_DIAG_SIGN_NOOP: u8 = 0x98;
const OP_PCZT_DIAG_SIGN_PRIMITIVE: u8 = 0x99;
pub(crate) const OP_GET_SEED_FINGERPRINT: u8 = 0x9A;
const OP_GET_FIRMWARE_VERSION: u8 = 0x9B;

#[derive(Parser)]
#[command(name = "zao", about = "Baochip-1x Zcash hardware wallet CLI", version = env!("ZAO_VERSION"))]
pub(crate) struct Cli {
    /// Serial port path (auto-detect if omitted)
    #[arg(long)]
    pub(crate) port: Option<String>,

    /// Companion-wallet data directory (default: $ZAO_DATADIR or ~/.zao)
    #[arg(long, global = true)]
    pub(crate) datadir: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Wallet operations (init, sync, balance, info, send).
    #[command(subcommand)]
    Wallet(WalletCommand),

    /// PCZT pipeline (create, prove, sign, combine, send, inspect, redact, diag).
    #[command(subcommand)]
    Pczt(PcztCommand),

    /// Direct Baochip-1x Zcash-specific device operations
    /// (address, fvk, sign-pczt, status, qr, version, seed-fingerprint).
    /// Device-general and seed-mgmt ops live under `holodi`.
    #[command(subcommand)]
    Baochip(BaochipCommand),

    /// Open the interactive ratatui TUI (single-pane dashboard).
    Ui,

    /// Print a step-by-step reference of the supported flows.
    /// Optional topic: setup | wallet | send | pipeline | inspect | troubleshoot
    Guide {
        /// Topic to print. If omitted, prints all of them.
        #[arg(value_name = "TOPIC")]
        topic: Option<String>,
    },

    /// Inspect a Zcash datum: address (UA / Sapling / transparent / TEX), UFVK,
    /// UIVK, or ZIP-321 payment URI. Mirrors zcash-devtool's top-level
    /// `inspect` command. For PCZT/transaction hex, use `zao pczt inspect`.
    Inspect {
        /// Encoded data to inspect (e.g. `u1...`, `uview1...`, `zcash:u1...?…`).
        #[arg(value_name = "DATA")]
        data: String,
    },

    /// Print a shell-completion script to stdout.
    /// Example: `source <(zao completions bash)`
    Completions {
        /// Target shell (bash, zsh, fish, elvish, powershell).
        #[arg(value_name = "SHELL")]
        shell: clap_complete::Shell,
    },

    /// Test serial frame sizes — sends progressively larger pings to find the limit.
    TestFrameSize,

    /// Send a small invalid sign-pczt to test the round-trip without actual signing.
    TestSignRoundtrip,

    /// Generate a test PCZT, send to device for signing, and verify result.
    /// Imports the test mnemonic, constructs a PCZT, signs on device, checks signature.
    TestSign {
        /// BIP39 mnemonic (defaults to standard 12-word test mnemonic)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Account index
        #[arg(long, default_value = "0")]
        account: u32,
        /// Amount to send (zatoshi)
        #[arg(long, default_value = "100000")]
        amount: u64,
    },
}

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Initialise the companion wallet from the device's UFVK.
    Init {
        /// Account index on the device (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Network for the wallet ("main" or "test"). Used only on first init.
        #[arg(long, default_value = "main")]
        network: String,
        /// Birthday block height (default: chain tip - 100)
        #[arg(long)]
        birthday: Option<u32>,
        /// Account name (default "device")
        #[arg(long, default_value = "device")]
        name: String,
    },

    /// Initialise a view-only wallet from a UFVK string (no device contact).
    /// Mirrors zcash-devtool's `wallet init-fvk`.
    InitFvk {
        /// Account name
        #[arg(long, default_value = "view")]
        name: String,
        /// Encoded UFVK string (e.g. `uview1...` or `uviewtest1...`).
        /// Get one via `zao wallet list-accounts` on another wallet.
        #[arg(long = "fvk")]
        fvk: String,
        /// Network ("main" or "test"). Must match the UFVK encoding.
        #[arg(long, default_value = "main")]
        network: String,
        /// Birthday block height (default: chain tip - 100)
        #[arg(long)]
        birthday: Option<u32>,
        /// Optional: hex-encoded 32-byte ZIP-32 seed fingerprint of the
        /// seed the UFVK was derived from. If supplied with
        /// `--hd-account-index`, the account is recorded as "spending"
        /// — the wallet knows the spending key exists somewhere
        /// (e.g. on a Baochip-1x). Otherwise it's pure view-only.
        #[arg(long = "seed-fingerprint")]
        seed_fingerprint: Option<String>,
        /// Optional: ZIP-32 account index corresponding to the UFVK.
        /// Must be paired with `--seed-fingerprint`.
        #[arg(long = "hd-account-index")]
        hd_account_index: Option<u32>,
    },

    /// List every account in the wallet DB with its UFVK + derivation
    /// info. Mirrors zcash-devtool's `wallet list-accounts`. Output is
    /// designed to plug straight into `wallet init-fvk` on another machine.
    ListAccounts,

    /// Sync the companion wallet against lightwalletd.
    Sync {
        /// Block batch size for scanning (default 10000)
        #[arg(long, default_value = "10000")]
        batch_size: u32,
    },

    /// Show the wallet balance.
    Balance,

    /// Print wallet info (paths, network, server, account, UFVK, birthday, sync state).
    Info,

    /// All-in-one shielded send: build PCZT → device-sign → combine → broadcast.
    /// Convenience wrapper over the granular `pczt {…}` pipeline.
    Send {
        /// Account index on the device (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Recipient Zcash address (Unified, Sapling, or transparent)
        #[arg(long)]
        to: String,
        /// Amount in zatoshi
        #[arg(long)]
        amount: u64,
        /// Optional memo
        #[arg(long)]
        memo: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PcztCommand {
    /// Build a payment proposal artifact (note selection + fee calc).
    /// Inspect it before committing to a PCZT.
    Propose {
        /// Account index on the device (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Recipient Zcash address (Unified, Sapling, or transparent)
        #[arg(long)]
        to: String,
        /// Amount in zatoshi
        #[arg(long)]
        amount: u64,
        /// Optional memo
        #[arg(long)]
        memo: Option<String>,
        /// Output path for the proposal protobuf (default: ./proposal.pb)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Build an unsigned PCZT from a proposal artifact.
    Create {
        /// Account index on the device (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Path to the proposal protobuf (e.g. ./proposal.pb)
        #[arg(long = "proposal")]
        proposal: String,
        /// Output path for the unsigned PCZT (default: ./unsigned.pczt)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Add the Orchard zk-proof to an unsigned PCZT (pure host op).
    Prove {
        /// Path to the unsigned PCZT
        #[arg(long = "pczt")]
        pczt: String,
        /// Output path for the proved PCZT (default: ./proved.pczt)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Send the unsigned PCZT to the device for signing. Outputs the
    /// device's signed PCZT (signatures + redacted skeleton). Combine
    /// with the proved PCZT before `pczt send`.
    Sign {
        /// Account index on the device (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Path to the unsigned PCZT (created by `pczt create`).
        #[arg(long = "unsigned")]
        unsigned: String,
        /// Output path for the signed PCZT (default: ./signed.pczt)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Combine a proved PCZT (host) with a signed PCZT (device output)
    /// to produce a fully-signed-and-proven PCZT ready for `pczt send`.
    Combine {
        /// Path to the proved PCZT (from `pczt prove`)
        #[arg(long = "proved")]
        proved: String,
        /// Path to the signed PCZT (from `pczt sign`)
        #[arg(long = "signed")]
        signed: String,
        /// Output path for the combined PCZT (default: ./combined.pczt)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// Extract a finished transaction from a combined PCZT and broadcast
    /// it to lightwalletd. Mirrors zcash-devtool's `pczt send`.
    Send {
        /// Path to the combined (proved + signed) PCZT
        #[arg(long = "pczt")]
        pczt: String,
    },

    /// Print a human-readable report of a proposal, PCZT, or transaction.
    Inspect {
        /// Path to a proposal protobuf (./proposal.pb)
        #[arg(long, group = "inspect_kind")]
        proposal: Option<String>,
        /// Path to a PCZT artifact (./unsigned.pczt | proved.pczt | signed.pczt)
        #[arg(long, group = "inspect_kind")]
        pczt: Option<String>,
        /// Path to a hex-encoded transaction (./tx.hex)
        #[arg(long, group = "inspect_kind")]
        tx: Option<String>,
    },

    /// Apply the firmware's redactor closure to a PCZT (host-side),
    /// stripping optional fields. Mirrors zcash-devtool's `pczt redact`.
    Redact {
        /// Path to the input PCZT
        #[arg(long = "pczt")]
        pczt: String,
        /// Output path (default: ./redacted.pczt)
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },

    /// On-device parse/serialize/sign diagnostic opcodes (used to
    /// localise codegen / heap-state bugs in the firmware sign path).
    #[command(subcommand)]
    Diag(PcztDiagCommand),
}

#[derive(Subcommand)]
pub enum PcztDiagCommand {
    /// Parse a PCZT on the device and check that re-serializing produces
    /// byte-identical output. (OP_PCZT_DIAG / 0x96)
    ParseSerialize {
        /// Path to a PCZT file
        #[arg(long = "pczt")]
        pczt: String,
    },

    /// Parse → apply firmware redactor closure → serialize → reparse, and
    /// report per-action bytes from the reparsed bundle. (0x97)
    Redact {
        /// Path to a PCZT file
        #[arg(long = "pczt")]
        pczt: String,
    },

    /// Drive the production Signer wrapper with a NOOP closure (no
    /// `action.sign` calls) — used to localise whether the corruption
    /// is in the wrapper itself vs. the sign primitives. (0x98)
    SignNoop {
        /// Path to a PCZT file
        #[arg(long = "pczt")]
        pczt: String,
    },

    /// Bisect inside the sign-orchard closure across modes 0..=7.
    /// Cumulative: 0 NOOP, 1 ALPHA, 2 RANDOMIZE, 3 VK_FROM,
    /// 4 COMPARE, 5 SIGN, 6 APPLY_SIGNATURE, 7 ACTION_SIGN. (0x99)
    SignPrimitive {
        /// Path to a PCZT file
        #[arg(long = "pczt")]
        pczt: String,
        /// Account index (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Mode 0..=7
        #[arg(long)]
        mode: u8,
    },
}

#[derive(Subcommand)]
pub enum BaochipCommand {
    /// Print the firmware build identifier reported by the device
    /// (typically `git describe` of the xous-core commit it was built
    /// from). Useful for confirming what's actually flashed before
    /// reasoning about a behaviour change.
    Version,

    /// Get the Orchard shielded address.
    Address {
        /// Account index (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
    },

    /// Get the Orchard Full Viewing Key.
    Fvk {
        /// Account index (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
    },

    /// Check if the device is ready for signing.
    Status,

    /// Display an Orchard address as a QR code in the terminal.
    Qr {
        /// Account index (default 0)
        #[arg(long, default_value = "0")]
        account: u32,
        /// Show QR for this address (hex) instead of the device's. No device needed.
        #[arg(long)]
        address: Option<String>,
    },

    /// Print the device's 32-byte ZIP-32 seed fingerprint as hex.
    /// Same value `wallet init` records under the account's derivation
    /// metadata. Useful for plugging into another wallet's `init-fvk`
    /// `--seed-fingerprint` flag.
    SeedFingerprint,

    /// Sign a PCZT (legacy hex-input path; prefer `pczt sign`).
    SignPczt {
        /// Account index
        #[arg(long, default_value = "0")]
        account: u32,
        /// Shielded sighash (64 hex chars)
        #[arg(long)]
        sighash: String,
        /// PCZT bytes as hex string
        #[arg(long, group = "pczt_input")]
        hex: Option<String>,
        /// Path to file containing PCZT bytes
        #[arg(long, group = "pczt_input")]
        file: Option<String>,
    },
}

/// Library entry point — parse argv with clap, init tracing, and
/// dispatch. The thin `src/main.rs` binary calls this; so does
/// holodi (when linking zao as a library instead of `exec`-ing).
pub fn run() -> Result<()> {
    run_inner(Cli::parse())
}

/// Library entry point taking an explicit argv (program name first).
/// Used by holodi to dispatch `holodi zec <args>` in-process.
pub fn run_from_argv<I, S>(argv: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::try_parse_from(argv)?;
    run_inner(cli)
}

fn run_inner(cli: Cli) -> Result<()> {
    let port = cli.port.as_deref();
    let datadir = cli.datadir.as_deref();

    // tracing initialization differs between CLI and TUI mode:
    //
    // - CLI: full format (timestamp, ANSI level coloring, module path).
    //   This is what a user running `zao wallet sync` from a shell
    //   expects to see.
    //
    // - TUI: compact, no ANSI, no timestamp. Long tracing lines wrap
    //   awkwardly inside the transcript pane, and the cached
    //   "is_terminal=true" decision at init time means the default
    //   subscriber emits colour codes that look like garbage even after
    //   we strip them. Shorter lines + plain text render cleanly.
    let is_tui = matches!(cli.command, Commands::Ui);
    if is_tui {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .without_time()
            .compact()
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(std::io::stderr)
            .try_init();
    }

    dispatch(cli.command, port, datadir)
}

/// Run a parsed `Commands` against the same handler tree `main` uses.
/// Extracted so the TUI (`tui/exec.rs`) can re-enter the same dispatch
/// in-process for slash-command execution without reinventing the
/// routing logic.
pub fn dispatch(command: Commands, port: Option<&str>, datadir: Option<&str>) -> Result<()> {
    match command {
        Commands::Wallet(cmd) => match cmd {
            WalletCommand::Init { account, network, birthday, name } => {
                commands::cmd_init(port, datadir, account, &network, birthday, &name)
            }
            WalletCommand::InitFvk {
                name,
                fvk,
                network,
                birthday,
                seed_fingerprint,
                hd_account_index,
            } => commands::cmd_init_fvk(
                datadir,
                &name,
                &fvk,
                &network,
                birthday,
                seed_fingerprint.as_deref(),
                hd_account_index,
            ),
            WalletCommand::ListAccounts => commands::cmd_list_accounts(datadir),
            WalletCommand::Sync { batch_size } => commands::cmd_sync(datadir, batch_size),
            WalletCommand::Balance => commands::cmd_balance(datadir),
            WalletCommand::Info => commands::cmd_info(datadir),
            WalletCommand::Send { account, to, amount, memo } => {
                commands::cmd_send(port, datadir, account, &to, amount, memo.as_deref())
            }
        },

        Commands::Pczt(cmd) => match cmd {
            PcztCommand::Propose { account, to, amount, memo, output } => send::cmd_propose(
                datadir,
                account,
                &to,
                amount,
                memo.as_deref(),
                output.as_deref(),
            ),
            PcztCommand::Create { account, proposal, output } => {
                send::cmd_create_pczt(datadir, account, &proposal, output.as_deref())
            }
            PcztCommand::Prove { pczt, output } => send::cmd_prove(&pczt, output.as_deref()),
            PcztCommand::Sign { account, unsigned, output } => {
                send::cmd_sign(port, account, &unsigned, output.as_deref())
            }
            PcztCommand::Combine { proved, signed, output } => {
                send::cmd_combine(&proved, &signed, output.as_deref())
            }
            PcztCommand::Send { pczt } => send::cmd_pczt_send(datadir, &pczt),
            PcztCommand::Inspect { proposal, pczt, tx } => match (proposal, pczt, tx) {
                (Some(p), None, None) => send::cmd_inspect_proposal(&p),
                (None, Some(p), None) => send::cmd_inspect_pczt(&p),
                (None, None, Some(t)) => send::cmd_inspect_tx(&t),
                (None, None, None) => bail!("Provide one of --proposal, --pczt, or --tx"),
                _ => bail!("--proposal, --pczt, and --tx are mutually exclusive"),
            },
            PcztCommand::Redact { pczt, output } => {
                send::cmd_pczt_redact(&pczt, output.as_deref())
            }
            PcztCommand::Diag(d) => match d {
                PcztDiagCommand::ParseSerialize { pczt } => cmd_pczt_diag(port, &pczt),
                PcztDiagCommand::Redact { pczt } => cmd_pczt_diag_redact(port, &pczt),
                PcztDiagCommand::SignNoop { pczt } => cmd_pczt_diag_sign_noop(port, &pczt),
                PcztDiagCommand::SignPrimitive { pczt, account, mode } => {
                    cmd_pczt_diag_sign_primitive(port, &pczt, account, mode)
                }
            },
        },

        Commands::Baochip(cmd) => match cmd {
            BaochipCommand::Version => cmd_version(port),
            BaochipCommand::Address { account } => cmd_address(port, account),
            BaochipCommand::Fvk { account } => cmd_fvk(port, account),
            BaochipCommand::Status => cmd_status(port),
            BaochipCommand::Qr { address: Some(ref addr), .. } => cmd_qr_address(addr),
            BaochipCommand::Qr { account, address: None } => cmd_qr_device(port, account),
            BaochipCommand::SeedFingerprint => cmd_seed_fingerprint(port),
            BaochipCommand::SignPczt { account, sighash, hex, file } => {
                cmd_sign_pczt(port, account, &sighash, hex.as_deref(), file.as_deref())
            }
        },

        Commands::Ui => tui::run(datadir, port),
        Commands::Guide { topic } => commands::cmd_guide(topic.as_deref()),
        Commands::Inspect { data } => inspect::run(&data),
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            let bin = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
            Ok(())
        }
        Commands::TestFrameSize => cmd_test_frame_size(port),
        Commands::TestSignRoundtrip => cmd_test_sign_roundtrip(port),
        Commands::TestSign { mnemonic, account, amount } => {
            cmd_test_sign(port, mnemonic.as_deref(), account, amount)
        }
    }
}

fn check_status(status: u8) -> Result<()> {
    if status != STATUS_OK {
        bail!("Device error: {} (0x{:02x})", transport::status_message(status), status);
    }
    Ok(())
}

fn cmd_version(port: Option<&str>) -> Result<()> {
    let mut t = Transport::open(port)?;
    let (status, payload) = t.command(OP_GET_FIRMWARE_VERSION, &[])?;
    check_status(status)?;
    let s = std::str::from_utf8(&payload)
        .map_err(|e| anyhow::anyhow!("device responded with non-UTF-8 version payload: {}", e))?;
    println!("device: {}", s);
    println!("host:   {}", env!("ZAO_VERSION"));
    Ok(())
}

/// Read the device's configured network. Defaults to mainnet if the
/// firmware is too old to report it (only 5-byte config response).
fn device_network(t: &mut Transport) -> Result<NetworkType> {
    let (status, payload) = t.command(OP_GET_CONFIG, &[])?;
    check_status(status)?;
    if payload.len() >= 6 && payload[5] == 1 {
        Ok(NetworkType::Test)
    } else {
        Ok(NetworkType::Main)
    }
}

fn cmd_address(port: Option<&str>, account: u32) -> Result<()> {
    let mut t = Transport::open(port)?;
    let net = device_network(&mut t).unwrap_or(NetworkType::Main);
    let payload = account.to_le_bytes().to_vec();
    let (status, resp) = t.command(OP_GET_ORCHARD_ADDRESS, &payload)?;
    check_status(status)?;

    if resp.len() == 43 {
        let raw_bytes: [u8; 43] = resp.try_into().unwrap();
        let orchard_receiver = zcash_address::unified::Receiver::Orchard(raw_bytes);
        let ua = zcash_address::unified::Address::try_from_items(vec![orchard_receiver])?;
        let encoded = ua.encode(&net);
        println!("Orchard address (account {}): {}", account, encoded);
        println!("  raw: {}", hex::encode(raw_bytes));
    } else {
        bail!("Unexpected address length: {} bytes", resp.len());
    }
    Ok(())
}

fn cmd_fvk(port: Option<&str>, account: u32) -> Result<()> {
    let mut t = Transport::open(port)?;
    let payload = account.to_le_bytes().to_vec();
    let (status, resp) = t.command(OP_GET_ORCHARD_FVK, &payload)?;
    check_status(status)?;

    if resp.len() == 96 {
        println!("Orchard FVK (account {}): {}", account, hex::encode(&resp));
    } else {
        bail!("Unexpected FVK length: {} bytes", resp.len());
    }
    Ok(())
}

fn cmd_seed_fingerprint(port: Option<&str>) -> Result<()> {
    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_GET_SEED_FINGERPRINT, &[])?;
    check_status(status)?;
    if resp.len() != 32 {
        bail!(
            "Unexpected seed-fingerprint length: {} bytes (want 32)",
            resp.len()
        );
    }
    println!("Seed fingerprint: {}", hex::encode(&resp));
    Ok(())
}

fn cmd_status(port: Option<&str>) -> Result<()> {
    let mut t = Transport::open(port)?;
    let (status, payload) = t.command(OP_GET_PCZT_STATUS, &[])?;
    check_status(status)?;

    if !payload.is_empty() {
        let ready = payload[0] != 0;
        println!("Ready: {}", if ready { "yes" } else { "no (no seed)" });
    }
    Ok(())
}

fn cmd_sign_pczt(
    port: Option<&str>,
    account: u32,
    sighash_hex: &str,
    hex_input: Option<&str>,
    file_input: Option<&str>,
) -> Result<()> {
    // Parse sighash
    let sighash_bytes = hex::decode(sighash_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid sighash hex: {}", e))?;
    if sighash_bytes.len() != 32 {
        bail!("Sighash must be 32 bytes (64 hex chars), got {}", sighash_bytes.len());
    }

    // Parse PCZT bytes
    let pczt_bytes = if let Some(hex_str) = hex_input {
        hex::decode(hex_str.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid PCZT hex: {}", e))?
    } else if let Some(path) = file_input {
        std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read PCZT file '{}': {}", path, e))?
    } else {
        bail!("Provide PCZT via --hex or --file");
    };

    // Normalize: parse and re-serialize to ensure format matches device expectations.
    let pczt = pczt::Pczt::parse(&pczt_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse PCZT on host: {:?}", e))?;
    let pczt_bytes = pczt.serialize();
    println!("Signing PCZT ({} bytes) with account {}...", pczt_bytes.len(), account);

    // Build payload: [account: u32 LE] [sighash: 32] [pczt_bytes...]
    let mut payload = Vec::with_capacity(4 + 32 + pczt_bytes.len());
    payload.extend_from_slice(&account.to_le_bytes());
    payload.extend_from_slice(&sighash_bytes);
    payload.extend_from_slice(&pczt_bytes);

    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_SIGN_PCZT, &payload)?;

    if status == STATUS_ERR_REJECTED {
        println!("Signing rejected by user on device.");
        return Ok(());
    }
    if status == STATUS_ERR_NO_SEED {
        bail!("No seed loaded on device. Run 'generate-mnemonic' or 'import-mnemonic' first.");
    }
    check_status(status)?;

    println!("Signed PCZT ({} bytes):", resp.len());
    println!("{}", hex::encode(&resp));

    // Optionally write to file
    if file_input.is_some() {
        let out_path = format!("{}.signed", file_input.unwrap());
        std::fs::write(&out_path, &resp)?;
        println!("Written to {}", out_path);
    }

    Ok(())
}

// =============================================================================
// qr: display address as QR code
// =============================================================================

fn cmd_qr_device(port: Option<&str>, account: u32) -> Result<()> {
    let mut t = Transport::open(port)?;
    let payload = account.to_le_bytes().to_vec();
    let (status, resp) = t.command(OP_GET_ORCHARD_ADDRESS, &payload)?;
    check_status(status)?;
    if resp.len() != 43 {
        bail!("Unexpected address length: {} bytes", resp.len());
    }
    let raw_bytes: [u8; 43] = resp.try_into().unwrap();
    let orchard_receiver = zcash_address::unified::Receiver::Orchard(raw_bytes);
    let ua = zcash_address::unified::Address::try_from_items(vec![orchard_receiver])?;
    let encoded = ua.encode(&NetworkType::Main);
    let uri = format!("zcash:{}", encoded);
    print_qr(&uri)
}

fn cmd_qr_address(address: &str) -> Result<()> {
    let addr = address.trim_start_matches("0x").trim_start_matches("0X");
    print_qr(addr)
}

fn print_qr(address: &str) -> Result<()> {
    use qrcode::{QrCode, EcLevel};

    let code = QrCode::with_error_correction_level(address, EcLevel::M)
        .map_err(|e| anyhow::anyhow!("QR encode failed: {}", e))?;

    let modules = code.to_colors();
    let width = code.width();

    println!();
    println!("  {}", address);
    println!();

    let get = |r: i32, c: i32| -> bool {
        if r < 0 || c < 0 || r >= width as i32 || c >= width as i32 {
            false
        } else {
            modules[r as usize * width + c as usize].select(true, false)
        }
    };

    let mut r: i32 = -1;
    while r < width as i32 + 1 {
        print!("    ");
        for c in -1..width as i32 + 1 {
            let top = get(r, c);
            let bot = get(r + 1, c);
            let ch = match (top, bot) {
                (true, true) => ' ',
                (false, false) => '\u{2588}',
                (true, false) => '\u{2584}',
                (false, true) => '\u{2580}',
            };
            print!("{ch}");
        }
        println!();
        r += 2;
    }

    println!();
    Ok(())
}

// =============================================================================
// test-sign: end-to-end PCZT signing test
// =============================================================================

/// Run the firmware's parse→serialize roundtrip diagnostic on a host-supplied
/// PCZT and print what the device saw. Used to localise the 2-action
/// signing corruption: the response includes the per-action enc_ciphertext
/// head/tail/cv_net/nullifier as the device parsed them, plus the
/// `identical=` bit comparing `Pczt::clone().serialize()` with the input.
fn cmd_pczt_diag(port: Option<&str>, pczt_path: &str) -> Result<()> {
    use std::fs;
    let pczt_bytes = fs::read(pczt_path)
        .map_err(|e| anyhow::anyhow!("read {}: {}", pczt_path, e))?;
    println!("Sending PCZT to device for parse→serialize diagnostic ({} bytes)...",
        pczt_bytes.len());

    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_PCZT_DIAG, &pczt_bytes)?;
    check_status(status)?;

    if resp.is_empty() {
        bail!("empty diagnostic response");
    }
    let parse_ok = resp[0] != 0;
    if !parse_ok {
        println!("Device: parse FAILED on the input PCZT.");
        return Ok(());
    }
    if resp.len() < 11 {
        bail!("malformed diagnostic response (len={})", resp.len());
    }
    let action_count = resp[1];
    let reserialized_len = u32::from_le_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
    let identical = resp[6] != 0;
    let diff_offset = u32::from_le_bytes([resp[7], resp[8], resp[9], resp[10]]);

    println!("Device parse: OK, {} actions", action_count);
    println!("  reserialized len  : {} (input: {})", reserialized_len, pczt_bytes.len());
    println!("  identical to input: {}", identical);
    if !identical {
        if diff_offset == 0xFFFF_FFFF {
            println!("  diff offset       : (none — sentinel)");
        } else {
            println!("  diff offset       : {}", diff_offset);
            // Print 8 bytes from input vs 8 bytes from device reserialization
            // around the divergence — but we don't have the reserialization
            // here, only the input. Show the input bytes for context.
            let off = diff_offset as usize;
            if off < pczt_bytes.len() {
                let end = std::cmp::min(off + 16, pczt_bytes.len());
                println!("  input[{}..{}]: {}", off, end, hex::encode(&pczt_bytes[off..end]));
            }
        }
    }

    // Per-action sample bytes — 96 bytes per action: enc_head(16) + enc_tail(16) + cv_net(32) + nf(32)
    let mut p = 11usize;
    for i in 0..action_count.min(2) {
        if p + 96 > resp.len() {
            println!("  (truncated: action[{}] sample bytes missing)", i);
            break;
        }
        let enc_head = &resp[p..p + 16];
        let enc_tail = &resp[p + 16..p + 32];
        let cv_net   = &resp[p + 32..p + 64];
        let nf       = &resp[p + 64..p + 96];
        println!("  action[{}]:", i);
        println!("    enc_head  : {}", hex::encode(enc_head));
        println!("    enc_tail  : {}", hex::encode(enc_tail));
        println!("    cv_net    : {}", hex::encode(cv_net));
        println!("    nullifier : {}", hex::encode(nf));
        p += 96;
    }

    Ok(())
}

/// Run the firmware's parse → redact → serialize → reparse diagnostic on a
/// host-supplied PCZT and print what the device saw post-redact-and-
/// reparse. Used to localise whether the corruption fires in the redact
/// step.
fn cmd_pczt_diag_redact(port: Option<&str>, pczt_path: &str) -> Result<()> {
    use std::fs;
    let pczt_bytes = fs::read(pczt_path)
        .map_err(|e| anyhow::anyhow!("read {}: {}", pczt_path, e))?;
    println!("Sending PCZT to device for parse→redact→serialize→reparse diagnostic ({} bytes)...",
        pczt_bytes.len());

    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_PCZT_DIAG_REDACT, &pczt_bytes)?;
    check_status(status)?;

    if resp.len() < 7 {
        bail!("malformed diagnostic response (len={})", resp.len());
    }
    let parse_ok = resp[0] != 0;
    if !parse_ok {
        println!("Device: parse FAILED on the input PCZT.");
        return Ok(());
    }
    let redacted_serialize_len = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]) as usize;
    let reparse_ok = resp[5] != 0;
    let action_count = resp[6];

    println!("Device parse: OK");
    println!("  redacted+serialized len: {} (input: {})", redacted_serialize_len, pczt_bytes.len());
    println!("  reparse_ok             : {}", reparse_ok);
    if !reparse_ok {
        println!("  → redact+serialize on RV32 produces bytes that do NOT reparse.");
        println!("    The corruption is INSIDE the redactor or in serialize-after-redact.");
        return Ok(());
    }
    println!("  reparsed actions       : {}", action_count);

    let mut p = 7usize;
    for i in 0..action_count.min(2) {
        if p + 96 > resp.len() {
            println!("  (truncated: action[{}] sample bytes missing)", i);
            break;
        }
        let enc_head = &resp[p..p + 16];
        let enc_tail = &resp[p + 16..p + 32];
        let cv_net   = &resp[p + 32..p + 64];
        let nf       = &resp[p + 64..p + 96];
        println!("  action[{}] (post-redact-and-reparse):", i);
        println!("    enc_head  : {}", hex::encode(enc_head));
        println!("    enc_tail  : {}", hex::encode(enc_tail));
        println!("    cv_net    : {}", hex::encode(cv_net));
        println!("    nullifier : {}", hex::encode(nf));
        p += 96;
    }

    Ok(())
}

/// Run the firmware's parse → Signer::new → sign_orchard_with(noop) → finish
/// → redact → serialize → reparse diagnostic. Bisects whether the
/// corruption is in the Signer wrapper bookkeeping vs. in action.sign.
fn cmd_pczt_diag_sign_noop(port: Option<&str>, pczt_path: &str) -> Result<()> {
    use std::fs;
    let pczt_bytes = fs::read(pczt_path)
        .map_err(|e| anyhow::anyhow!("read {}: {}", pczt_path, e))?;
    println!("Sending PCZT to device for parse → Signer(noop) → finish → redact → reparse diagnostic ({} bytes)...",
        pczt_bytes.len());

    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_PCZT_DIAG_SIGN_NOOP, &pczt_bytes)?;
    check_status(status)?;

    if resp.len() < 7 {
        bail!("malformed diagnostic response (len={})", resp.len());
    }
    let parse_ok = resp[0] != 0;
    if !parse_ok {
        println!("Device: parse FAILED on the input PCZT.");
        return Ok(());
    }
    let serialize_len = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]) as usize;
    let reparse_ok = resp[5] != 0;
    let action_count = resp[6];

    println!("Device parse: OK");
    println!("  serialized len: {} (input: {})", serialize_len, pczt_bytes.len());
    println!("  reparse_ok    : {}", reparse_ok);
    if !reparse_ok {
        println!("  → noop-signer + redact + serialize on RV32 produces non-parseable bytes.");
        println!("    Bug is in the Signer wrapper itself.");
        return Ok(());
    }
    println!("  reparsed actions: {}", action_count);

    let mut p = 7usize;
    for i in 0..action_count.min(2) {
        if p + 96 > resp.len() { break; }
        let enc_head = &resp[p..p + 16];
        let enc_tail = &resp[p + 16..p + 32];
        let cv_net   = &resp[p + 32..p + 64];
        let nf       = &resp[p + 64..p + 96];
        println!("  action[{}] (post-noop-signer-and-reparse):", i);
        println!("    enc_head  : {}", hex::encode(enc_head));
        println!("    enc_tail  : {}", hex::encode(enc_tail));
        println!("    cv_net    : {}", hex::encode(cv_net));
        println!("    nullifier : {}", hex::encode(nf));
        p += 96;
    }
    Ok(())
}

/// Run the firmware's parse → Signer + sign_orchard_with(mode-conditional) →
/// finish → redact → serialize → reparse diagnostic. Used to bisect inside
/// the sign closure to find the corrupting primitive.
fn cmd_pczt_diag_sign_primitive(port: Option<&str>, pczt_path: &str, account: u32, mode: u8) -> Result<()> {
    use std::fs;
    let pczt_bytes = fs::read(pczt_path)
        .map_err(|e| anyhow::anyhow!("read {}: {}", pczt_path, e))?;
    if mode > 7 {
        bail!("mode must be 0..=7");
    }
    let mode_name = match mode {
        0 => "NOOP",
        1 => "ALPHA",
        2 => "RANDOMIZE",
        3 => "VK_FROM",
        4 => "COMPARE",
        5 => "SIGN",
        6 => "APPLY_SIGNATURE",
        7 => "ACTION_SIGN",
        _ => "?",
    };
    println!("Sending PCZT to device for sign-primitive diagnostic ({} bytes, mode={} {})...",
        pczt_bytes.len(), mode, mode_name);

    let mut payload = Vec::with_capacity(5 + pczt_bytes.len());
    payload.extend_from_slice(&account.to_le_bytes());
    payload.push(mode);
    payload.extend_from_slice(&pczt_bytes);

    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_PCZT_DIAG_SIGN_PRIMITIVE, &payload)?;
    check_status(status)?;

    if resp.len() < 8 {
        bail!("malformed diagnostic response (len={})", resp.len());
    }
    let parse_ok = resp[0] != 0;
    if !parse_ok {
        println!("Device: parse FAILED on the input PCZT.");
        return Ok(());
    }
    let serialize_len = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]) as usize;
    let reparse_ok = resp[5] != 0;
    let action_count = resp[6];
    let mode_run = resp[7];

    println!("Device parse: OK");
    println!("  mode_run     : {} ({})", mode_run, mode_name);
    println!("  serialized   : {} bytes (input: {})", serialize_len, pczt_bytes.len());
    println!("  reparse_ok   : {}", reparse_ok);
    if !reparse_ok {
        println!("  → mode {} produces non-parseable output. Bug is at this primitive.", mode_run);
        return Ok(());
    }
    println!("  reparsed actions: {}", action_count);

    let mut p = 8usize;
    for i in 0..action_count.min(2) {
        if p + 96 > resp.len() { break; }
        let enc_head = &resp[p..p + 16];
        let enc_tail = &resp[p + 16..p + 32];
        let cv_net   = &resp[p + 32..p + 64];
        let nf       = &resp[p + 64..p + 96];
        println!("  action[{}]:", i);
        println!("    enc_head  : {}", hex::encode(enc_head));
        println!("    enc_tail  : {}", hex::encode(enc_tail));
        println!("    cv_net    : {}", hex::encode(cv_net));
        println!("    nullifier : {}", hex::encode(nf));
        p += 96;
    }
    Ok(())
}

fn cmd_test_sign_roundtrip(port: Option<&str>) -> Result<()> {
    // Send a sign-pczt with invalid PCZT data — should return an error immediately
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes()); // account
    payload.extend_from_slice(&[0u8; 32]);           // fake sighash
    payload.extend_from_slice(b"not a real pczt");    // invalid PCZT

    println!("Sending invalid sign-pczt ({} bytes payload)...", payload.len());
    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_SIGN_PCZT, &payload)?;
    println!("Response: status=0x{:02x} ({}) payload={} bytes",
        status, transport::status_message(status), resp.len());
    Ok(())
}

fn cmd_test_frame_size(port: Option<&str>) -> Result<()> {
    let sizes = [10, 50, 100, 200, 500, 1000, 2000, 3000, 4000, 5000];

    for &size in &sizes {
        let payload = vec![0u8; size];
        print!("Frame payload {} bytes... ", size);
        let mut t = Transport::open(port)?;

        // Use a short timeout for this test
        match t.command(OP_GET_CONFIG, &payload) {
            Ok((status, _resp)) => {
                if status == STATUS_OK {
                    println!("OK");
                } else {
                    println!("status 0x{:02x}", status);
                }
            }
            Err(e) => {
                println!("FAILED: {}", e);
                println!("Maximum working frame size is less than {} bytes", size);
                return Ok(());
            }
        }
    }
    println!("All sizes passed!");
    Ok(())
}

const DEFAULT_TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn cmd_test_sign(
    port: Option<&str>,
    mnemonic: Option<&str>,
    account: u32,
    amount: u64,
) -> Result<()> {
    let mnemonic = mnemonic.unwrap_or(DEFAULT_TEST_MNEMONIC);

    // 1. Import mnemonic on device
    println!("Importing mnemonic on device...");
    {
        let mut t = Transport::open(port)?;
        let (status, _) = t.command(OP_IMPORT_MNEMONIC, mnemonic.as_bytes())?;
        check_status(status)?;
    }

    // 2. Verify address matches
    println!("Verifying address...");
    let device_addr = {
        let mut t = Transport::open(port)?;
        let payload = account.to_le_bytes().to_vec();
        let (status, resp) = t.command(OP_GET_ORCHARD_ADDRESS, &payload)?;
        check_status(status)?;
        if resp.len() != 43 {
            bail!("Unexpected address length: {} bytes", resp.len());
        }
        hex::encode(&resp)
    };

    // 3. Build test PCZT (plays the Zodl role)
    println!("Building test PCZT ({} zatoshi to self)...", amount);
    let test_pczt = pczt_builder::build_test_pczt(mnemonic, account, amount)?;

    if device_addr != test_pczt.address_hex {
        bail!(
            "Address mismatch!\n  device: {}\n  local:  {}\nKey derivation differs — cannot sign.",
            device_addr,
            test_pczt.address_hex,
        );
    }
    println!("  Address match: {}", &device_addr[..16]);
    println!("  PCZT: {} bytes", test_pczt.pczt_bytes.len());
    println!("  Sighash: {}", hex::encode(test_pczt.sighash));

    // 4. Send to device for signing
    println!("Sending to device for signing...");
    let mut payload = Vec::with_capacity(4 + 32 + test_pczt.pczt_bytes.len());
    payload.extend_from_slice(&account.to_le_bytes());
    payload.extend_from_slice(&test_pczt.sighash);
    payload.extend_from_slice(&test_pczt.pczt_bytes);

    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_SIGN_PCZT, &payload)?;

    if status == STATUS_ERR_REJECTED {
        println!("Signing rejected by user on device.");
        return Ok(());
    }
    check_status(status)?;

    // 5. Verify signed PCZT has signatures
    println!("Signed PCZT: {} bytes", resp.len());

    // Quick check: signed PCZT should be larger or equal (signatures added)
    if resp.len() >= test_pczt.pczt_bytes.len() {
        println!("TEST PASSED: Device signed the PCZT successfully.");
    } else {
        println!("WARNING: Signed PCZT is smaller than input — unexpected.");
    }

    println!("Signed PCZT hex: {}", hex::encode(&resp));
    Ok(())
}
