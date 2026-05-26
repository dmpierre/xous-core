//! holodi — unified host CLI for the Baochip hardware wallet.
//!
//! Subcommand layout:
//!   holodi ping               # round-trip a serial frame to confirm reachability
//!   holodi firmware-version   # device firmware version
//!   holodi config             # device firmware semver + protocol + flags
//!   holodi status             # dashboard: reachability + firmware + seed
//!   holodi seed ...           # bao-seed lifecycle (routes through ethapp's USB)
//!   holodi eth  ...           # links beth as a library, dispatches in-process
//!   holodi zec  ...           # links zao  as a library, dispatches in-process
//!
//! `holodi --version` (clap-builtin flag) prints the host CLI version
//! — distinct from `holodi firmware-version` which talks to the
//! device. `ping`/`firmware-version`/`config`/`status` are
//! device-general; the underlying hardware (Baochip) is implicit at
//! the holodi entry point.
//!
//! ## Wire path for `seed`
//!
//! holodi → USB-serial 0xE7 frames → ethapp → Xous IPC → bao-seed.
//! ethapp's seed-management opcodes (Import/Generate/Clear) all
//! delegate to bao-seed, so `holodi seed import …` sets the seed in
//! the actual vault, and subsequent `holodi eth address` /
//! `holodi zec address` calls derive from the same vault.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};

mod device;
mod seed;
mod transport;
mod tty;

use transport::Transport;

/// Build version string. Prefers what `build.rs` injects via
/// `cargo:rustc-env=HOLODI_VERSION=...` (git-describe in a dev
/// checkout, or `$HOLODI_VERSION` from Guix/Nix release builds).
/// Falls back to `CARGO_PKG_VERSION` so the crate compiles even if
/// the build script is skipped for any reason (sandboxed builds,
/// stale cargo cache, etc.).
const HOLODI_VERSION: &str = match option_env!("HOLODI_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(
    name = "holodi",
    version = HOLODI_VERSION,
    about = "Unified host CLI for the Baochip hardware wallet",
    long_about = None,
)]
struct Cli {
    /// Serial port path (default: auto-detect by VID/PID).
    #[arg(long, global = true)]
    port: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Round-trip a serial frame to confirm the device is reachable.
    Ping,

    /// Print the device firmware version.
    /// For the host CLI version, use `holodi --version`.
    FirmwareVersion,

    /// Show the device firmware semver, protocol byte, and feature flags.
    Config,

    /// Dashboard: device reachability + firmware version + seed presence.
    /// Single command for a "is everything wired up?" health check.
    Status,

    /// Seed-vault lifecycle (status, generate, import, wipe).
    ///
    /// Routes through ethapp's USB protocol to bao-seed. The same vault
    /// underlies both `holodi eth` and `holodi zec` — import once,
    /// derive everywhere.
    Seed {
        #[command(subcommand)]
        op: SeedOp,
    },

    /// Ethereum operations — runs beth's subcommand tree in-process.
    /// `holodi eth address 0` is equivalent to `beth address 0`.
    ///
    /// beth's full subcommand tree is inlined here so `--help`, tab
    /// completion, and clap error messages all work natively.
    Eth {
        #[command(subcommand)]
        command: beth::Commands,
    },

    /// Zcash operations — runs zao's subcommand tree in-process.
    /// `holodi zec address 0` ≡ `zao address 0`.
    ///
    /// zao's full subcommand tree is inlined here so `--help`, tab
    /// completion, and clap error messages all work natively.
    Zec {
        /// Companion-wallet data directory. If omitted, zao falls back to
        /// $ZAO_DATADIR, then ~/.zao.
        #[arg(long, global = true)]
        datadir: Option<String>,

        #[command(subcommand)]
        command: zao::Commands,
    },

    /// Print a shell-completion script to stdout.
    /// Example: `source <(holodi completions bash)`
    Completions {
        /// Target shell (bash, zsh, fish, elvish, powershell).
        #[arg(value_name = "SHELL")]
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum SeedOp {
    /// Show seed presence + protocol version.
    Status,

    /// Cheap presence check — prints `true` or `false`.
    Hasseed,

    /// Generate a new BIP-39 mnemonic on the device. The words are
    /// shown via the device (or, on dev-mode builds, returned to the
    /// host for transcription).
    Generate,

    /// Import a BIP-39 mnemonic from stdin. Wipes any existing seed
    /// first.
    Import,

    /// Wipe the seed from device RAM and persistent storage (if any).
    Wipe,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Ping => {
            let mut t = Transport::open(cli.port.as_deref())?;
            device::ping(&mut t)
        }
        Commands::FirmwareVersion => {
            let mut t = Transport::open(cli.port.as_deref())?;
            device::firmware_version(&mut t)
        }
        Commands::Config => {
            let mut t = Transport::open(cli.port.as_deref())?;
            device::config(&mut t)
        }
        Commands::Status => {
            match Transport::open(cli.port.as_deref()) {
                Ok(mut t) => device::status(&mut t, HOLODI_VERSION),
                Err(e) => {
                    println!("host:     {}", HOLODI_VERSION);
                    println!("device:   unreachable ({})", e);
                    Ok(())
                }
            }
        }
        Commands::Seed { op } => {
            let mut t = Transport::open(cli.port.as_deref())?;
            match op {
                SeedOp::Status => seed::status(&mut t),
                SeedOp::Hasseed => seed::hasseed(&mut t),
                SeedOp::Generate => seed::generate(&mut t),
                SeedOp::Import => seed::import(&mut t),
                SeedOp::Wipe => seed::wipe(&mut t),
            }
        }
        Commands::Eth { command } => beth::dispatch(command, cli.port.as_deref()),
        Commands::Zec { command, datadir } => {
            zao::dispatch(command, cli.port.as_deref(), datadir.as_deref())
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
            Ok(())
        }
    }
}

