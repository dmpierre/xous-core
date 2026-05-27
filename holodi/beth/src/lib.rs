//! beth — Host-side CLI for the Baochip-1x Ethereum hardware wallet.
//!
//! Communicates with the ethapp service over USB CDC-ACM serial,
//! replacing the need for `tio /dev/ttyACM0`.
//!
//! The TUI (`beth ui`) is a chat-style slash-command palette that
//! re-enters the same dispatch tree in-process; see `src/tui/`.

mod rpc;
mod transport;
mod tui;

use std::io::{self, BufRead, Write};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use transport::{Transport, STATUS_OK};

// Opcodes matching EthAppOp values. Device-general / seed-mgmt opcodes
// (PING / GET_CONFIG / GENERATE_MNEMONIC / IMPORT_MNEMONIC / CLEAR_SEED)
// were removed when their commands moved to `holodi {ping,config,seed}`.
const OP_GET_ADDRESS: u8 = 0x51;
const OP_ENABLE_DANGEROUS_MAINNET: u8 = 0x64;
const OP_SIGN_PERSONAL_MESSAGE: u8 = 0x20;
const OP_SIGN_TRANSACTION: u8 = 0x10;
const OP_INIT_IMPORT_KEY: u8 = 0x65;
const OP_GET_IMPORT_KEY: u8 = 0x66;
const OP_IMPORT_ENCRYPTED: u8 = 0x67;
const OP_SIGN_EIP7702_AUTH: u8 = 0x23;
const OP_INIT_ATTESTATION: u8 = 0x80;
const OP_GET_ATTESTATION_KEY: u8 = 0x81;
const OP_ATTEST_SIGN: u8 = 0x82;

#[derive(Parser)]
#[command(name = "beth", about = "Baochip-1x Ethereum hardware wallet CLI", version = env!("BETH_VERSION"))]
pub(crate) struct Cli {
    /// Serial port path (auto-detected if not specified)
    #[arg(long, short)]
    pub(crate) port: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Open the interactive ratatui TUI — chat-style slash-command palette
    /// over the same `beth` subcommand tree. Type `/` for the menu.
    Ui,

    /// Print a step-by-step guide for funding and transferring USDC.
    /// Shows Sepolia testnet by default; pass --mainnet for mainnet.
    Guide {
        /// Show mainnet guide instead of Sepolia testnet
        #[arg(long)]
        mainnet: bool,
    },

    /// Display an Ethereum address as a QR code in the terminal.
    Qr {
        /// Account index (m/44'/60'/0'/0/<index>). Ignored if --address is set.
        #[arg(long, default_value = "0")]
        index: u32,

        /// Show QR for this address instead of the device's. No device needed.
        #[arg(long)]
        address: Option<String>,
    },

    /// Get Ethereum address at BIP44 path
    Address {
        /// Account index (m/44'/60'/0'/0/<index>)
        #[arg(long, default_value = "0")]
        index: u32,
    },

    /// List first N account addresses
    Accounts {
        /// Number of accounts to list
        #[arg(long, default_value = "5")]
        count: u32,
    },

    /// Initialize the device import keypair for encrypted mnemonic import (one-time).
    InitImportKey {
        /// Overwrite existing import key
        #[arg(long)]
        overwrite: bool,
    },

    /// Print the device's import public key (for encrypted mnemonic transfer).
    GetImportKey,

    /// Import a BIP39 mnemonic encrypted to the device's import public key (ECIES).
    /// The mnemonic is encrypted locally before being sent to the device.
    ImportEncrypted,

    /// DANGEROUS: enable mainnet signing on a displayless device.
    /// Session-only (resets on reboot). You assume all risk.
    #[command(alias = "yolo")]
    DangerousMode,

    /// Generate the device attestation identity (one-time).
    InitAttestation {
        /// Overwrite existing attestation key
        #[arg(long)]
        overwrite: bool,
    },

    /// Print the device's attestation public key (33-byte compressed secp256k1).
    GetAttestationKey,

    /// Sign a transaction with attestation co-signature.
    AttestSignTx {
        /// Hex-encoded RLP transaction (with or without 0x prefix)
        rlp_hex: String,

        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },

    /// Verify an attestation co-signature offline (no device needed).
    VerifyAttestation {
        /// Attestation public key (33-byte compressed hex)
        #[arg(long)]
        pubkey: String,

        /// Transaction sign hash (32-byte hex)
        #[arg(long)]
        sign_hash: String,

        /// Transaction signature v
        #[arg(long)]
        tx_v: u64,

        /// Transaction signature r (32-byte hex)
        #[arg(long)]
        tx_r: String,

        /// Transaction signature s (32-byte hex)
        #[arg(long)]
        tx_s: String,

        /// Attestation signature v
        #[arg(long)]
        attest_v: u64,

        /// Attestation signature r (32-byte hex)
        #[arg(long)]
        attest_r: String,

        /// Attestation signature s (32-byte hex)
        #[arg(long)]
        attest_s: String,
    },

    /// Sign an EIP-191 personal message
    SignMessage {
        /// The message to sign
        message: String,

        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },

    /// Sign a raw RLP-encoded transaction
    SignTx {
        /// Hex-encoded RLP transaction (with or without 0x prefix)
        rlp_hex: String,

        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },

    /// Check the ETH balance of an address. Uses the device's address at
    /// --index by default, or an arbitrary --address if provided.
    Balance {
        /// JSON-RPC URL (e.g. https://ethereum-sepolia-rpc.publicnode.com
        /// for Sepolia testnet, https://ethereum-rpc.publicnode.com for mainnet)
        #[arg(long)]
        rpc_url: String,

        /// Account index (uses device address at this index). Ignored if --address is set.
        #[arg(long, default_value = "0")]
        index: u32,

        /// Query this address instead of the device's. No device needed.
        #[arg(long)]
        address: Option<String>,
    },

    /// Fetch chain state needed to build a transaction: chain ID, nonce,
    /// gas price, EIP-1559 fee suggestion, balance, and gas limit estimate.
    /// Uses the device's address at the given index.
    TxInfo {
        /// JSON-RPC URL (e.g. https://ethereum-sepolia-rpc.publicnode.com
        /// for Sepolia testnet, https://ethereum-rpc.publicnode.com for mainnet)
        #[arg(long)]
        rpc_url: String,

        /// Account index — uses device address at this index for queries
        #[arg(long, default_value = "0")]
        index: u32,

        /// Recipient address for gas estimation context (else assumes 21000)
        #[arg(long)]
        to: Option<String>,

        /// Value in wei for gas estimation context
        #[arg(long, default_value = "0")]
        value: u128,

        /// Calldata hex for contract-call gas estimation
        #[arg(long)]
        data: Option<String>,
    },

    /// Broadcast a pre-signed transaction (eth_sendRawTransaction).
    /// Equivalent to foundry's `cast publish`. Does NOT touch the device.
    #[command(alias = "broadcast")]
    Publish {
        /// Hex-encoded signed transaction (with or without 0x prefix)
        signed_tx_hex: String,

        /// JSON-RPC URL (e.g. https://ethereum-sepolia-rpc.publicnode.com
        /// for Sepolia testnet, https://ethereum-rpc.publicnode.com for mainnet)
        #[arg(long)]
        rpc_url: String,

        /// Poll until the tx is mined and print the receipt
        #[arg(long)]
        wait: bool,

        /// How long to poll before giving up (seconds)
        #[arg(long, default_value = "120")]
        wait_timeout: u64,
    },

    /// Check the ERC-20 token balance of an address.
    TokenBalance {
        /// Token contract address (hex, 20 bytes)
        #[arg(long)]
        token: String,

        /// JSON-RPC URL (e.g. https://ethereum-sepolia-rpc.publicnode.com
        /// for Sepolia testnet, https://ethereum-rpc.publicnode.com for mainnet)
        #[arg(long)]
        rpc_url: String,

        /// Account index (uses device address). Ignored if --address is set.
        #[arg(long, default_value = "0")]
        index: u32,

        /// Query this address instead of the device's. No device needed.
        #[arg(long)]
        address: Option<String>,

        /// Token decimals for formatting (default: 18)
        #[arg(long, default_value = "18")]
        decimals: u8,

        /// Token symbol for display (default: "tokens")
        #[arg(long, default_value = "tokens")]
        symbol: String,
    },

    /// Build, sign, and optionally broadcast an ERC-20 transfer transaction.
    /// Uses EIP-1559 by default; pass --legacy for legacy EIP-155.
    SendToken {
        /// Token contract address (hex, 20 bytes)
        #[arg(long)]
        token: String,

        /// Recipient address (hex, 20 bytes)
        to: String,

        /// Amount in the token's smallest unit (e.g. 1000000 = 1 USDC)
        amount: u128,

        /// JSON-RPC URL for auto-fetching nonce/fees/gas
        /// (e.g. https://ethereum-sepolia-rpc.publicnode.com for Sepolia testnet,
        /// https://ethereum-rpc.publicnode.com for mainnet)
        #[arg(long)]
        rpc_url: String,

        /// Account index for signing
        #[arg(long, default_value = "0")]
        index: u32,

        /// Override nonce
        #[arg(long)]
        nonce: Option<u64>,

        /// Override chain ID
        #[arg(long)]
        chain_id: Option<u64>,

        /// Override gas limit
        #[arg(long)]
        gas_limit: Option<u64>,

        /// Use legacy transaction instead of EIP-1559
        #[arg(long)]
        legacy: bool,

        /// Broadcast the signed tx immediately
        #[arg(long)]
        broadcast: bool,
    },

    /// Build (only) the unsigned RLP for a legacy EIP-155 transaction.
    /// Does NOT touch the device — useful for offline workflows where you
    /// build the tx on one machine and sign it elsewhere with `sign-tx`.
    BuildTx {
        /// Recipient address (hex, with or without 0x prefix, 20 bytes)
        to: String,

        /// Value to send in wei
        value: u128,

        /// Account nonce
        #[arg(long, default_value = "0")]
        nonce: u64,

        /// Chain ID (1=mainnet, 11155111=sepolia, 17000=holesky, ...)
        #[arg(long, default_value = "11155111")]
        chain_id: u64,

        /// Gas price in wei
        #[arg(long, default_value = "1000000000")]
        gas_price: u64,

        /// Gas limit
        #[arg(long, default_value = "21000")]
        gas_limit: u64,

        /// Optional hex-encoded calldata (for contract calls)
        #[arg(long)]
        data: Option<String>,
    },

    /// Sign an EIP-7702 authorization tuple on the device.
    ///
    /// The device signs keccak256(0x05 || rlp([chain_id, delegate, nonce]))
    /// with the key at --index. The output (y_parity, r, s) can be fed
    /// directly into `beth build-eip7702-tx --auth`.
    SignEip7702Auth {
        /// Chain ID of the authorization (use 0 to sign for any chain)
        #[arg(long)]
        chain_id: u64,

        /// Contract address to delegate to (hex, 20 bytes)
        #[arg(long)]
        delegate: String,

        /// Current nonce of the authorizing EOA
        #[arg(long)]
        nonce: u64,

        /// Account index (m/44'/60'/0'/0/<index>)
        #[arg(long, default_value = "0")]
        index: u32,
    },

    /// Build an unsigned EIP-7702 type-4 transaction (offline, no device).
    ///
    /// Takes one or more pre-signed authorization tuples (from `sign-eip7702-auth`)
    /// and produces unsigned RLP ready for `beth sign-tx`.
    BuildEip7702Tx {
        /// Recipient address (hex, 20 bytes)
        destination: String,

        /// Value in wei
        value: u128,

        /// Sender nonce
        #[arg(long, default_value = "0")]
        nonce: u64,

        /// Chain ID
        #[arg(long, default_value = "11155111")]
        chain_id: u64,

        /// EIP-1559 max priority fee per gas (wei)
        #[arg(long, default_value = "1000000000")]
        max_priority_fee: u128,

        /// EIP-1559 max fee per gas (wei)
        #[arg(long, default_value = "1000000000")]
        max_fee: u128,

        /// Gas limit
        #[arg(long, default_value = "50000")]
        gas_limit: u64,

        /// Pre-signed authorization tuple: chain_id:address:nonce:y_parity:r_hex:s_hex
        /// Repeat --auth for multiple delegating EOAs.
        #[arg(long = "auth", required = true)]
        authorizations: Vec<String>,
    },

    /// Build, sign, and optionally broadcast an EIP-7702 type-4 transaction.
    ///
    /// Fetches nonce and fee estimates from --rpc-url, signs on the device,
    /// and optionally broadcasts via eth_sendRawTransaction.
    GenEip7702Tx {
        /// Recipient address (hex, 20 bytes)
        destination: String,

        /// Value in wei
        value: u128,

        /// JSON-RPC URL for chain state and broadcast
        #[arg(long)]
        rpc_url: String,

        /// Pre-signed authorization tuple: chain_id:address:nonce:y_parity:r_hex:s_hex
        /// Repeat --auth for multiple delegating EOAs.
        #[arg(long = "auth", required = true)]
        authorizations: Vec<String>,

        /// Account index for signing
        #[arg(long, default_value = "0")]
        index: u32,

        /// Broadcast the signed tx immediately
        #[arg(long)]
        broadcast: bool,

        /// Override nonce (default: fetched from RPC)
        #[arg(long)]
        nonce: Option<u64>,

        /// Override chain ID (default: fetched from RPC)
        #[arg(long)]
        chain_id: Option<u64>,

        /// Override gas limit (default: 50000)
        #[arg(long)]
        gas_limit: Option<u64>,
    },

    /// Build, sign, and emit a legacy (EIP-155) ETH transfer transaction.
    /// Output is the raw signed tx hex ready to broadcast via eth_sendRawTransaction.
    GenTx {
        /// Recipient address (hex, with or without 0x prefix, 20 bytes)
        to: String,

        /// Value to send in wei
        value: u128,

        /// Account nonce
        #[arg(long, default_value = "0")]
        nonce: u64,

        /// Chain ID (1=mainnet, 11155111=sepolia, 17000=holesky, ...)
        #[arg(long, default_value = "11155111")]
        chain_id: u64,

        /// Gas price in wei
        #[arg(long, default_value = "1000000000")]
        gas_price: u64,

        /// Gas limit
        #[arg(long, default_value = "21000")]
        gas_limit: u64,

        /// Account index for signing
        #[arg(long, default_value = "0")]
        index: u32,

        /// Optional hex-encoded calldata (for contract calls)
        #[arg(long)]
        data: Option<String>,
    },
}

/// Library entry point — parse argv with clap and dispatch. The thin
/// `src/main.rs` binary calls this; so does holodi (when linking beth
/// as a library instead of `exec`-ing the binary).
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    dispatch(cli.command, cli.port.as_deref())
}

/// Library entry point taking an explicit argv (program name first).
/// Used by holodi to dispatch `holodi eth <args>` in-process.
pub fn run_from_argv<I, S>(argv: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::try_parse_from(argv)?;
    dispatch(cli.command, cli.port.as_deref())
}

/// Run a parsed `Commands` against the same handler tree `run` uses.
/// Extracted so the TUI (`tui/exec.rs`) can re-enter the same dispatch
/// in-process for slash-command execution without reinventing the
/// routing logic.
pub fn dispatch(command: Commands, port: Option<&str>) -> Result<()> {
    // TUI is its own subcommand — it manages the terminal lifecycle
    // itself, no transport opened here.
    if matches!(command, Commands::Ui) {
        return tui::run(port);
    }

    // Offline commands: handle before opening the device. Match by
    // reference so the value stays available for the online dispatch
    // below if no arm fires.
    match &command {
        Commands::Guide { mainnet } => return cmd_guide(*mainnet),
        Commands::Qr { address: Some(addr), .. } => return cmd_qr_address(addr),
        Commands::BuildTx {
            to, value, nonce, chain_id, gas_price, gas_limit, data,
        } => {
            return cmd_build_tx(
                to, *value, *nonce, *chain_id, *gas_price, *gas_limit, data.as_deref(),
            );
        }
        Commands::BuildEip7702Tx {
            destination, value, nonce, chain_id, max_priority_fee, max_fee,
            gas_limit, authorizations,
        } => {
            return cmd_build_eip7702_tx(
                destination, *value, *nonce, *chain_id,
                *max_priority_fee, *max_fee, *gas_limit, authorizations,
            );
        }
        Commands::Publish { signed_tx_hex, rpc_url, wait, wait_timeout } => {
            return cmd_publish(signed_tx_hex, rpc_url, *wait, *wait_timeout);
        }
        Commands::Balance { rpc_url, address: Some(addr), .. } => {
            return cmd_balance_address(rpc_url, addr);
        }
        Commands::TokenBalance { token, rpc_url, address: Some(addr), decimals, symbol, .. } => {
            return cmd_token_balance_address(rpc_url, token, addr, *decimals, symbol);
        }
        Commands::VerifyAttestation {
            pubkey, sign_hash,
            tx_v, tx_r, tx_s,
            attest_v, attest_r, attest_s,
        } => {
            return cmd_verify_attestation(
                pubkey, sign_hash, *tx_v, tx_r, tx_s, *attest_v, attest_r, attest_s,
            );
        }
        _ => {}
    }

    let mut transport = Transport::open(port)?;

    match command {
        Commands::Address { index } => cmd_address(&mut transport, index),
        Commands::Accounts { count } => cmd_accounts(&mut transport, count),
        Commands::InitImportKey { overwrite } => cmd_init_import_key(&mut transport, overwrite),
        Commands::GetImportKey => cmd_get_import_key(&mut transport),
        Commands::ImportEncrypted => cmd_import_encrypted(&mut transport),
        Commands::DangerousMode => cmd_dangerous_mode(&mut transport),
        Commands::SignMessage { message, index } => cmd_sign_message(&mut transport, &message, index),
        Commands::SignTx { rlp_hex, index } => cmd_sign_tx(&mut transport, &rlp_hex, index),
        Commands::SignEip7702Auth { chain_id, delegate, nonce, index } => {
            cmd_sign_eip7702_auth(&mut transport, chain_id, &delegate, nonce, index)
        }
        Commands::GenEip7702Tx {
            destination, value, rpc_url, authorizations, index,
            broadcast, nonce, chain_id, gas_limit,
        } => cmd_gen_eip7702_tx(
            &mut transport, &destination, value, &rpc_url, &authorizations,
            index, broadcast, nonce, chain_id, gas_limit,
        ),
        Commands::GenTx {
            to, value, nonce, chain_id, gas_price, gas_limit, index, data,
        } => cmd_gen_tx(
            &mut transport, &to, value, nonce, chain_id, gas_price, gas_limit, index,
            data.as_deref(),
        ),
        Commands::TxInfo { rpc_url, index, to, value, data } => cmd_tx_info(
            &mut transport, &rpc_url, index, to.as_deref(), value, data.as_deref(),
        ),
        Commands::Balance { rpc_url, index, address: None } => {
            cmd_balance_device(&mut transport, &rpc_url, index)
        }
        Commands::TokenBalance { token, rpc_url, index, address: None, decimals, symbol } => {
            cmd_token_balance_device(&mut transport, &rpc_url, &token, index, decimals, &symbol)
        }
        Commands::SendToken {
            token, to, amount, rpc_url, index,
            nonce, chain_id, gas_limit, legacy, broadcast,
        } => cmd_send_token(
            &mut transport, &token, &to, amount, &rpc_url, index,
            nonce, chain_id, gas_limit, legacy, broadcast,
        ),
        Commands::InitAttestation { overwrite } => {
            cmd_init_attestation(&mut transport, overwrite)
        }
        Commands::GetAttestationKey => cmd_get_attestation_key(&mut transport),
        Commands::AttestSignTx { rlp_hex, index } => {
            cmd_attest_sign_tx(&mut transport, &rlp_hex, index)
        }
        Commands::Qr { index, address: None } => {
            cmd_qr_device(&mut transport, index)
        }
        Commands::Ui
        | Commands::Guide { .. }
        | Commands::BuildTx { .. } | Commands::BuildEip7702Tx { .. }
        | Commands::Publish { .. }
        | Commands::Balance { address: Some(_), .. }
        | Commands::TokenBalance { address: Some(_), .. }
        | Commands::Qr { address: Some(_), .. }
        | Commands::VerifyAttestation { .. } => unreachable!("handled above"),
    }
}

fn cmd_address(t: &mut Transport, index: u32) -> Result<()> {
    // Payload: BIP44 path components [purpose, coin_type, account, change, index]
    // Each as u32 BE, with hardened bit set on first three
    let path = bip44_payload(0, 0, index);
    let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK {
        bail!("address failed (status: 0x{:02x})", status);
    }
    if payload.len() >= 20 {
        println!("m/44'/60'/0'/0/{} -> 0x{}", index, hex::encode(&payload[..20]));
    } else {
        bail!("unexpected response length: {}", payload.len());
    }
    Ok(())
}

fn cmd_accounts(t: &mut Transport, count: u32) -> Result<()> {
    for i in 0..count {
        let path = bip44_payload(0, 0, i);
        let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
        if status != STATUS_OK {
            eprintln!("[{}] error (status: 0x{:02x})", i, status);
            break;
        }
        if payload.len() >= 20 {
            println!("[{}] 0x{}", i, hex::encode(&payload[..20]));
        }
    }
    Ok(())
}

fn cmd_dangerous_mode(t: &mut Transport) -> Result<()> {
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: ENABLING DANGEROUS MAINNET MODE                   ║");
    eprintln!("║                                                              ║");
    eprintln!("║  This device has NO trusted display.                         ║");
    eprintln!("║  You CANNOT verify what you are signing on the device.       ║");
    eprintln!("║  A compromised host can steal ALL your funds.                ║");
    eprintln!("║                                                              ║");
    eprintln!("║  By proceeding you accept FULL responsibility for losses.    ║");
    eprintln!("║  This mode resets on device reboot.                          ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprint!("Type 'I ACCEPT THE RISK' to continue: ");
    io::stderr().flush()?;

    let stdin = io::stdin();
    let line = stdin.lock().lines().next()
        .ok_or_else(|| anyhow::anyhow!("No input"))??;
    if line.trim() != "I ACCEPT THE RISK" {
        bail!("Aborted. You must type exactly: I ACCEPT THE RISK");
    }

    let (status, _) = t.command(OP_ENABLE_DANGEROUS_MAINNET, &[])?;
    if status == STATUS_OK {
        eprintln!("Dangerous mainnet mode ENABLED for this session.");
    } else {
        bail!("failed (status: 0x{:02x})", status);
    }
    Ok(())
}

fn cmd_sign_message(t: &mut Transport, message: &str, index: u32) -> Result<()> {
    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(message.as_bytes());

    let (status, resp) = t.command(OP_SIGN_PERSONAL_MESSAGE, &payload)?;
    if status != STATUS_OK {
        bail!("sign-message failed (status: 0x{:02x})", status);
    }
    print_signature(&resp);
    Ok(())
}

fn cmd_sign_tx(t: &mut Transport, rlp_hex: &str, index: u32) -> Result<()> {
    let hex_str = rlp_hex.strip_prefix("0x").unwrap_or(rlp_hex);
    let tx_data = hex::decode(hex_str)?;

    // Detect tx type. EIP-2718 typed txs start with a type byte < 0x80.
    // Legacy txs start with the RLP list prefix (0xc0..=0xff).
    let tx_type = if !tx_data.is_empty() && tx_data[0] < 0x80 {
        Some(tx_data[0])
    } else {
        None
    };

    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(&tx_data);

    let (status, resp) = t.command(OP_SIGN_TRANSACTION, &payload)?;
    if status != STATUS_OK {
        bail!("sign-tx failed (status: 0x{:02x})", status);
    }
    if resp.len() < 72 {
        print_signature(&resp);
        return Ok(());
    }
    let v = u64::from_le_bytes(resp[0..8].try_into().unwrap());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&resp[8..40]);
    s.copy_from_slice(&resp[40..72]);

    println!("v={}", v);
    println!("r={}", hex::encode(&r));
    println!("s={}", hex::encode(&s));

    // Assemble the broadcastable signed RLP.
    match assemble_signed_tx(&tx_data, tx_type, v, &r, &s) {
        Ok(signed) => println!("raw: 0x{}", hex::encode(&signed)),
        Err(e) => eprintln!(
            "warning: could not assemble signed RLP ({}); pass an *unsigned* tx to get a broadcastable result",
            e
        ),
    }

    Ok(())
}

// =============================================================================
// EIP-7702 signing commands
// =============================================================================

/// Sign a single EIP-7702 authorization tuple on the device.
///
/// Output includes the `y_parity:r:s` values and a ready-to-paste
/// `--auth` string for `beth build-eip7702-tx` or `beth gen-eip7702-tx`.
fn cmd_sign_eip7702_auth(
    t: &mut Transport,
    chain_id: u64,
    delegate: &str,
    nonce: u64,
    index: u32,
) -> Result<()> {
    let addr_hex = delegate.strip_prefix("0x").unwrap_or(delegate);
    let addr_bytes = hex::decode(addr_hex)?;
    if addr_bytes.len() != 20 {
        bail!("delegate address must be 20 bytes, got {}", addr_bytes.len());
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&addr_bytes);

    // Wire payload: [path_bytes...][chain_id: 8 BE][address: 20][nonce: 8 BE]
    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(&chain_id.to_be_bytes());
    payload.extend_from_slice(&address);
    payload.extend_from_slice(&nonce.to_be_bytes());

    let (status, resp) = t.command(OP_SIGN_EIP7702_AUTH, &payload)?;
    if status != STATUS_OK {
        bail!("sign-eip7702-auth failed (status: 0x{:02x})", status);
    }
    if resp.len() < 72 {
        bail!("unexpected response length: {}", resp.len());
    }

    let y_parity = u64::from_le_bytes(resp[0..8].try_into().unwrap());
    if y_parity > 1 {
        bail!("device returned invalid y_parity: {} (expected 0 or 1)", y_parity);
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&resp[8..40]);
    s.copy_from_slice(&resp[40..72]);

    println!("y_parity={}", y_parity);
    println!("r=0x{}", hex::encode(&r));
    println!("s=0x{}", hex::encode(&s));
    // Ready-to-paste --auth argument
    println!(
        "auth: {}:0x{}:{}:{}:0x{}:0x{}",
        chain_id, addr_hex, nonce, y_parity,
        hex::encode(&r), hex::encode(&s)
    );
    Ok(())
}

/// Build an unsigned EIP-7702 type-4 transaction (offline, no device).
#[allow(clippy::too_many_arguments)]
fn cmd_build_eip7702_tx(
    destination: &str,
    value: u128,
    nonce: u64,
    chain_id: u64,
    max_priority_fee: u128,
    max_fee: u128,
    gas_limit: u64,
    authorizations: &[String],
) -> Result<()> {
    let dest_hex = destination.strip_prefix("0x").unwrap_or(destination);
    let dest_bytes = hex::decode(dest_hex)?;
    if dest_bytes.len() != 20 {
        bail!("destination must be 20 bytes, got {}", dest_bytes.len());
    }

    let auth_tuples: Result<Vec<Vec<u8>>> = authorizations.iter()
        .map(|s| parse_signed_auth(s))
        .collect();
    let auth_tuples = auth_tuples?;

    let unsigned = rlp_encode_eip7702_unsigned(
        chain_id, nonce, max_priority_fee, max_fee,
        gas_limit, &dest_bytes, value, &[], &[], &auth_tuples,
    );

    println!("chain:     {} ({})", chain_id, chain_name(chain_id));
    println!("to:        0x{}", dest_hex);
    println!("value:     {} wei", value);
    println!("nonce:     {}  gas: {}  maxFee: {} wei  priorityFee: {} wei",
        nonce, gas_limit, max_fee, max_priority_fee);
    println!("auths:     {}", auth_tuples.len());
    println!("unsigned:  0x{}", hex::encode(&unsigned));
    println!();
    println!("To sign and broadcast: beth sign-tx 0x{}", hex::encode(&unsigned));
    Ok(())
}

/// Build, sign, and optionally broadcast an EIP-7702 type-4 transaction.
#[allow(clippy::too_many_arguments)]
fn cmd_gen_eip7702_tx(
    t: &mut Transport,
    destination: &str,
    value: u128,
    rpc_url: &str,
    authorizations: &[String],
    index: u32,
    broadcast: bool,
    nonce_override: Option<u64>,
    chain_id_override: Option<u64>,
    gas_limit_override: Option<u64>,
) -> Result<()> {
    let dest_hex = destination.strip_prefix("0x").unwrap_or(destination);
    let dest_bytes = hex::decode(dest_hex)?;
    if dest_bytes.len() != 20 {
        bail!("destination must be 20 bytes, got {}", dest_bytes.len());
    }

    // Get sender address from device
    let path = bip44_payload(0, 0, index);
    let (status, addr_resp) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK || addr_resp.len() < 20 {
        bail!("failed to get address from device (status: 0x{:02x})", status);
    }
    let sender_hex = format!("0x{}", hex::encode(&addr_resp[..20]));

    // Fetch chain state
    let mut rpc = rpc::RpcClient::new(rpc_url);
    let chain_id = chain_id_override.map_or_else(|| rpc.chain_id(), Ok)?;
    let nonce = nonce_override.map_or_else(|| rpc.nonce(&sender_hex), Ok)?;
    let fees = rpc.fee_suggestion()?
        .ok_or_else(|| anyhow::anyhow!("chain does not support EIP-1559"))?;
    let max_priority_fee = fees.priority_fee_per_gas;
    let max_fee = fees.max_fee_per_gas();
    let gas_limit = gas_limit_override.unwrap_or(50_000);

    let auth_tuples: Result<Vec<Vec<u8>>> = authorizations.iter()
        .map(|s| parse_signed_auth(s))
        .collect();
    let auth_tuples = auth_tuples?;

    let unsigned = rlp_encode_eip7702_unsigned(
        chain_id, nonce, max_priority_fee, max_fee,
        gas_limit, &dest_bytes, value, &[], &[], &auth_tuples,
    );

    // Sign via OP_SIGN_TRANSACTION — parser handles type-4 RLP
    let mut sign_payload = bip44_payload(0, 0, index);
    sign_payload.extend_from_slice(&unsigned);
    let (status, resp) = t.command(OP_SIGN_TRANSACTION, &sign_payload)?;
    if status != STATUS_OK {
        bail!("sign failed (status: 0x{:02x})", status);
    }
    if resp.len() < 72 {
        bail!("unexpected signature response length: {}", resp.len());
    }

    let v = u64::from_le_bytes(resp[0..8].try_into().unwrap());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&resp[8..40]);
    s.copy_from_slice(&resp[40..72]);

    let signed = assemble_signed_tx(&unsigned, Some(0x04), v, &r, &s)?;

    println!("chain:     {} ({})", chain_id, chain_name(chain_id));
    println!("to:        0x{}", dest_hex);
    println!("value:     {} wei", value);
    println!("nonce:     {}  gas: {}  maxFee: {} wei  priorityFee: {} wei",
        nonce, gas_limit, max_fee, max_priority_fee);
    println!("auths:     {}", auth_tuples.len());
    println!("y_parity={}", v);
    println!("r={}", hex::encode(&r));
    println!("s={}", hex::encode(&s));
    println!("raw: 0x{}", hex::encode(&signed));

    if broadcast {
        let tx_hash = rpc.send_raw_transaction(&signed)?;
        println!("tx hash: {}", tx_hash);
    }

    Ok(())
}

/// Combine an unsigned tx with the signature returned by the device into a
/// broadcastable signed RLP. Supports legacy EIP-155, EIP-2930, EIP-1559, and EIP-7702.
fn assemble_signed_tx(
    tx_data: &[u8],
    tx_type: Option<u8>,
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<Vec<u8>> {
    match tx_type {
        // Legacy EIP-155: unsigned has 9 items [n, gp, gl, to, value, data, chainId, 0, 0].
        // Replace last 3 with [v, r, s] to form the signed form.
        None => {
            let items = decode_top_level_items(tx_data)?;
            if items.len() != 9 {
                bail!("expected 9 RLP items in legacy tx, got {}", items.len());
            }
            // Sanity: items[7] and items[8] of an unsigned EIP-155 tx are the empty bytes (0).
            // If they aren't, the input is likely already signed.
            if items[7] != [0x80] || items[8] != [0x80] {
                bail!("input looks already signed (items 7,8 not zero)");
            }
            let mut payload = Vec::new();
            for item in items.iter().take(6) {
                payload.extend_from_slice(item);
            }
            payload.extend_from_slice(&rlp_encode_u64(v));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
            Ok(rlp_encode_list(&payload))
        }
        // EIP-2930 (type 0x01): unsigned has 8 items [chainId, n, gp, gl, to, value, data, accessList].
        // Append [yParity, r, s] to form the signed body, then prepend type byte.
        Some(0x01) => {
            let items = decode_top_level_items(&tx_data[1..])?;
            if items.len() != 8 {
                bail!("expected 8 RLP items in EIP-2930 tx, got {}", items.len());
            }
            let mut payload = Vec::new();
            for item in &items {
                payload.extend_from_slice(item);
            }
            payload.extend_from_slice(&rlp_encode_u64(v));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
            let mut out = vec![0x01];
            out.extend_from_slice(&rlp_encode_list(&payload));
            Ok(out)
        }
        // EIP-1559 (type 0x02): unsigned has 9 items
        // [chainId, n, maxPriorityFeePerGas, maxFeePerGas, gl, to, value, data, accessList].
        Some(0x02) => {
            let items = decode_top_level_items(&tx_data[1..])?;
            if items.len() != 9 {
                bail!("expected 9 RLP items in EIP-1559 tx, got {}", items.len());
            }
            let mut payload = Vec::new();
            for item in &items {
                payload.extend_from_slice(item);
            }
            payload.extend_from_slice(&rlp_encode_u64(v));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
            let mut out = vec![0x02];
            out.extend_from_slice(&rlp_encode_list(&payload));
            Ok(out)
        }
        // EIP-7702 (type 0x04): unsigned has 10 items
        // [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to,
        //  value, data, accessList, authorizationList].
        // Append [yParity, r, s] to form the signed body, then prepend type byte.
        Some(0x04) => {
            let items = decode_top_level_items(&tx_data[1..])?;
            if items.len() != 10 {
                bail!("expected 10 RLP items in EIP-7702 tx, got {}", items.len());
            }
            if v > 1 {
                bail!("invalid y_parity for EIP-7702 tx: {} (must be 0 or 1)", v);
            }
            let mut payload = Vec::new();
            for item in &items {
                payload.extend_from_slice(item);
            }
            payload.extend_from_slice(&rlp_encode_u64(v));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
            payload.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
            let mut out = vec![0x04];
            out.extend_from_slice(&rlp_encode_list(&payload));
            Ok(out)
        }
        Some(t) => bail!("unsupported tx type byte: 0x{:02x}", t),
    }
}

/// Decode a top-level RLP list into its constituent items, returning each
/// item in its original encoded form (so we can splice without re-encoding
/// nested structures like accessList).
fn decode_top_level_items(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if data.is_empty() {
        bail!("empty RLP");
    }
    let (header_len, payload_len, is_list) = parse_rlp_header(data)?;
    if !is_list {
        bail!("expected RLP list, got string");
    }
    let payload = &data[header_len..header_len + payload_len];
    let mut items = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let item_len = item_total_len(&payload[offset..])?;
        items.push(payload[offset..offset + item_len].to_vec());
        offset += item_len;
    }
    Ok(items)
}

/// Returns (header_len, payload_len, is_list).
fn parse_rlp_header(data: &[u8]) -> Result<(usize, usize, bool)> {
    if data.is_empty() {
        bail!("empty RLP");
    }
    let first = data[0];
    match first {
        0x00..=0x7f => Ok((0, 1, false)), // single-byte string, "header" is implicit
        0x80..=0xb7 => Ok((1, (first - 0x80) as usize, false)),
        0xb8..=0xbf => {
            let lb = (first - 0xb7) as usize;
            if data.len() < 1 + lb {
                bail!("truncated long string length");
            }
            let mut len = 0usize;
            for i in 0..lb {
                len = (len << 8) | data[1 + i] as usize;
            }
            Ok((1 + lb, len, false))
        }
        0xc0..=0xf7 => Ok((1, (first - 0xc0) as usize, true)),
        0xf8..=0xff => {
            let lb = (first - 0xf7) as usize;
            if data.len() < 1 + lb {
                bail!("truncated long list length");
            }
            let mut len = 0usize;
            for i in 0..lb {
                len = (len << 8) | data[1 + i] as usize;
            }
            Ok((1 + lb, len, true))
        }
    }
}

fn item_total_len(data: &[u8]) -> Result<usize> {
    let (header_len, payload_len, _) = parse_rlp_header(data)?;
    if header_len == 0 {
        // single-byte string in 0x00..=0x7f: data[0] IS the value
        Ok(1)
    } else {
        Ok(header_len + payload_len)
    }
}

/// Encode a BIP44 Ethereum path as bytes for the wire protocol.
///
/// Path: m/44'/60'/account'/change/index
/// Each component is u32 BE; hardened components have bit 31 set.
fn bip44_payload(account: u32, change: u32, index: u32) -> Vec<u8> {
    let components = [
        44 | 0x80000000,       // purpose (hardened)
        60 | 0x80000000,       // coin_type (hardened)
        account | 0x80000000,  // account (hardened)
        change,                // change
        index,                 // address_index
    ];
    let mut buf = Vec::with_capacity(1 + 5 * 4);
    buf.push(5); // path length
    for c in &components {
        buf.extend_from_slice(&c.to_be_bytes());
    }
    buf
}

fn print_signature(data: &[u8]) {
    // Expected: v (8 bytes u64 LE) + r (32 bytes) + s (32 bytes) = 72 bytes
    if data.len() >= 72 {
        let v = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let r = &data[8..40];
        let s = &data[40..72];
        println!("v={}", v);
        println!("r={}", hex::encode(r));
        println!("s={}", hex::encode(s));
    } else {
        println!("signature: {}", hex::encode(data));
    }
}

// =============================================================================
// balance: check ETH balance
// =============================================================================

fn cmd_balance_device(t: &mut Transport, rpc_url: &str, index: u32) -> Result<()> {
    let path = bip44_payload(0, 0, index);
    let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK || payload.len() < 20 {
        bail!("failed to get address from device (status: 0x{:02x})", status);
    }
    let addr_hex = format!("0x{}", hex::encode(&payload[..20]));
    print_balance(&addr_hex, rpc_url)
}

fn cmd_balance_address(rpc_url: &str, address: &str) -> Result<()> {
    let addr = if address.starts_with("0x") || address.starts_with("0X") {
        address.to_string()
    } else {
        format!("0x{}", address)
    };
    print_balance(&addr, rpc_url)
}

fn print_balance(addr_hex: &str, rpc_url: &str) -> Result<()> {
    let mut rpc = rpc::RpcClient::new(rpc_url);
    let balance = rpc.balance(addr_hex)?;
    println!("{} {}", addr_hex, format_eth(balance));
    Ok(())
}

// =============================================================================
// token-balance: check ERC-20 token balance
// =============================================================================

fn cmd_token_balance_device(
    t: &mut Transport,
    rpc_url: &str,
    token: &str,
    index: u32,
    decimals: u8,
    symbol: &str,
) -> Result<()> {
    let path = bip44_payload(0, 0, index);
    let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK || payload.len() < 20 {
        bail!("failed to get address from device (status: 0x{:02x})", status);
    }
    let addr_hex = format!("0x{}", hex::encode(&payload[..20]));
    print_token_balance(&addr_hex, rpc_url, token, decimals, symbol)
}

fn cmd_token_balance_address(
    rpc_url: &str,
    token: &str,
    address: &str,
    decimals: u8,
    symbol: &str,
) -> Result<()> {
    let addr = if address.starts_with("0x") || address.starts_with("0X") {
        address.to_string()
    } else {
        format!("0x{}", address)
    };
    print_token_balance(&addr, rpc_url, token, decimals, symbol)
}

fn print_token_balance(
    owner_hex: &str,
    rpc_url: &str,
    token: &str,
    decimals: u8,
    symbol: &str,
) -> Result<()> {
    let token_clean = token.strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .unwrap_or(token);
    let token_addr = hex::decode(token_clean)?;
    if token_addr.len() != 20 {
        bail!("invalid token address: need 20 bytes, got {}", token_addr.len());
    }

    let owner_clean = owner_hex.strip_prefix("0x").unwrap_or(owner_hex);
    let owner_bytes = hex::decode(owner_clean)?;
    if owner_bytes.len() != 20 {
        bail!("invalid owner address: need 20 bytes, got {}", owner_bytes.len());
    }
    let owner_arr: [u8; 20] = owner_bytes.try_into().unwrap();

    let calldata = encode_erc20_balance_of(&owner_arr);
    let token_hex = format!("0x{}", hex::encode(&token_addr));

    let mut rpc = rpc::RpcClient::new(rpc_url);
    let result = rpc.eth_call(&token_hex, &calldata)?;

    // Parse uint256 result — use the last 16 bytes as u128
    let balance = if result.len() >= 32 {
        // Check for overflow in top 16 bytes
        let has_high = result[..16].iter().any(|&b| b != 0);
        if has_high {
            println!("{} 0x{} {} (too large for decimal formatting)", owner_hex, hex::encode(&result), symbol);
            return Ok(());
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&result[16..32]);
        u128::from_be_bytes(buf)
    } else {
        bail!("unexpected eth_call result length: {}", result.len());
    };

    let formatted = format_token_balance(balance, decimals);
    println!("{} {} {}", owner_hex, formatted, symbol);
    Ok(())
}

fn format_token_balance(value: u128, decimals: u8) -> String {
    if decimals == 0 {
        return format!("{}", value);
    }
    let divisor = 10u128.pow(decimals as u32);
    let whole = value / divisor;
    let frac = value % divisor;
    if frac == 0 {
        format!("{}", whole)
    } else {
        let frac_str = format!("{:0width$}", frac, width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    }
}

// =============================================================================
// send-token: build, sign, and emit an ERC-20 transfer
// =============================================================================

#[allow(clippy::too_many_arguments)]
fn cmd_send_token(
    t: &mut Transport,
    token: &str,
    to: &str,
    amount: u128,
    rpc_url: &str,
    index: u32,
    nonce_override: Option<u64>,
    chain_id_override: Option<u64>,
    gas_limit_override: Option<u64>,
    legacy: bool,
    broadcast: bool,
) -> Result<()> {
    // Parse addresses
    let token_clean = token.strip_prefix("0x").unwrap_or(token);
    let token_addr = hex::decode(token_clean)?;
    if token_addr.len() != 20 {
        bail!("invalid token address: need 20 bytes, got {}", token_addr.len());
    }

    let to_clean = to.strip_prefix("0x").unwrap_or(to);
    let to_bytes = hex::decode(to_clean)?;
    if to_bytes.len() != 20 {
        bail!("invalid recipient address: need 20 bytes, got {}", to_bytes.len());
    }
    let to_arr: [u8; 20] = to_bytes.try_into().unwrap();

    // Encode ERC-20 transfer calldata
    let calldata = encode_erc20_transfer(&to_arr, amount);

    // Get sender address from device
    let path = bip44_payload(0, 0, index);
    let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK || payload.len() < 20 {
        bail!("failed to get address from device (status: 0x{:02x})", status);
    }
    let sender_hex = format!("0x{}", hex::encode(&payload[..20]));
    let token_hex = format!("0x{}", hex::encode(&token_addr));

    // Fetch chain state
    let mut rpc = rpc::RpcClient::new(rpc_url);
    let chain_id = chain_id_override.map_or_else(|| rpc.chain_id(), Ok)?;
    let nonce = nonce_override.map_or_else(|| rpc.nonce(&sender_hex), Ok)?;

    let gas_limit = match gas_limit_override {
        Some(g) => g,
        None => {
            let estimated = rpc.estimate_gas(&sender_hex, &token_hex, 0, &calldata)?;
            // Add 20% buffer for ERC-20 transfers
            estimated * 6 / 5
        }
    };

    // Build unsigned tx
    let unsigned = if legacy {
        let gas_price = rpc.gas_price()? as u64;
        let params = TxParams { nonce, gas_price, gas_limit, chain_id };
        let unsigned = rlp_encode_legacy_unsigned(&token_addr, 0, &calldata, &params);

        println!("type:      Legacy (EIP-155)");
        println!("chain:     {} ({})", chain_id, chain_name(chain_id));
        println!("token:     0x{}", token_clean);
        println!("to:        0x{}", to_clean);
        println!("amount:    {} (smallest unit)", amount);
        println!("nonce:     {}  gas: {}  gasPrice: {} wei", nonce, gas_limit, gas_price);

        unsigned
    } else {
        let fees = rpc.fee_suggestion()?
            .ok_or_else(|| anyhow::anyhow!("chain does not support EIP-1559; use --legacy"))?;
        let max_priority_fee = fees.priority_fee_per_gas;
        let max_fee = fees.max_fee_per_gas();

        let unsigned = rlp_encode_eip1559_unsigned(
            chain_id, nonce, max_priority_fee, max_fee,
            gas_limit, &token_addr, 0, &calldata,
        );

        println!("type:      EIP-1559");
        println!("chain:     {} ({})", chain_id, chain_name(chain_id));
        println!("token:     0x{}", token_clean);
        println!("to:        0x{}", to_clean);
        println!("amount:    {} (smallest unit)", amount);
        println!(
            "nonce:     {}  gas: {}  maxFee: {} wei  priorityFee: {} wei",
            nonce, gas_limit, max_fee, max_priority_fee,
        );

        unsigned
    };

    // Sign on device
    let mut sign_payload = bip44_payload(0, 0, index);
    sign_payload.extend_from_slice(&unsigned);

    let (status, resp) = t.command(OP_SIGN_TRANSACTION, &sign_payload)?;
    if status != STATUS_OK {
        bail!("sign failed (status: 0x{:02x})", status);
    }
    if resp.len() < 72 {
        bail!("unexpected signature response length: {}", resp.len());
    }

    let v = u64::from_le_bytes(resp[0..8].try_into().unwrap());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&resp[8..40]);
    s.copy_from_slice(&resp[40..72]);

    let tx_type = if legacy { None } else { Some(0x02) };
    let signed = assemble_signed_tx(&unsigned, tx_type, v, &r, &s)?;

    println!("v={}", v);
    println!("r={}", hex::encode(&r));
    println!("s={}", hex::encode(&s));
    println!("raw: 0x{}", hex::encode(&signed));

    if broadcast {
        let tx_hash = rpc.send_raw_transaction(&signed)?;
        println!("tx hash: {}", tx_hash);
    }

    Ok(())
}

// =============================================================================
// tx-info: fetch chain state for transaction construction
// =============================================================================

fn cmd_tx_info(
    t: &mut Transport,
    rpc_url: &str,
    index: u32,
    to: Option<&str>,
    value: u128,
    data_hex: Option<&str>,
) -> Result<()> {
    // 1. Get our address from the device
    let path = bip44_payload(0, 0, index);
    let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK || payload.len() < 20 {
        bail!("failed to get address from device (status: 0x{:02x})", status);
    }
    let addr_hex = format!("0x{}", hex::encode(&payload[..20]));

    println!("address[{}]   {}", index, addr_hex);

    // 2. Query the RPC
    let mut rpc = rpc::RpcClient::new(rpc_url);

    let chain_id = rpc.chain_id()?;
    println!("chain id     {} ({})", chain_id, chain_name(chain_id));

    let balance = rpc.balance(&addr_hex)?;
    println!("balance      {} wei  ({})", balance, format_eth(balance));

    let nonce = rpc.nonce(&addr_hex)?;
    println!("nonce        {}  (pending)", nonce);

    let gas_price = rpc.gas_price()?;
    println!("gas price    {} wei  ({})", gas_price, format_gwei(gas_price));

    match rpc.fee_suggestion() {
        Ok(Some(fees)) => {
            println!("EIP-1559:");
            println!(
                "  next base fee       {} wei  ({})",
                fees.next_base_fee, format_gwei(fees.next_base_fee)
            );
            println!(
                "  priority fee (p50)  {} wei  ({})",
                fees.priority_fee_per_gas, format_gwei(fees.priority_fee_per_gas)
            );
            let max_fee = fees.max_fee_per_gas();
            println!(
                "  suggested max fee   {} wei  ({})",
                max_fee, format_gwei(max_fee)
            );
        }
        Ok(None) => println!("EIP-1559:    not supported by this RPC"),
        Err(e) => println!("EIP-1559:    error fetching feeHistory: {}", e),
    }

    // 3. Gas estimate
    let calldata: Vec<u8> = match data_hex {
        Some(h) => hex::decode(h.strip_prefix("0x").unwrap_or(h))?,
        None => Vec::new(),
    };
    let gas_limit = match to {
        Some(to_addr) => {
            let to_clean = to_addr.strip_prefix("0x").unwrap_or(to_addr);
            let to_full = format!("0x{}", to_clean);
            match rpc.estimate_gas(&addr_hex, &to_full, value, &calldata) {
                Ok(g) => {
                    println!("gas limit    {} (estimated for the given --to/--value/--data)", g);
                    g
                }
                Err(e) => {
                    eprintln!("gas estimate failed: {}", e);
                    21_000
                }
            }
        }
        None => {
            println!("gas limit    21000 (default; pass --to to estimate against a target)");
            21_000
        }
    };

    // 4. Convenience: print a ready-to-use gen-tx invocation
    if let Some(to_addr) = to {
        println!();
        println!("Ready-to-use gen-tx command:");
        let calldata_arg = if data_hex.is_some() {
            format!(" --data {}", data_hex.unwrap())
        } else {
            String::new()
        };
        println!(
            "  beth gen-tx {} {} \\\n    --nonce {} --chain-id {} \\\n    --gas-price {} --gas-limit {} --index {}{}",
            to_addr, value, nonce, chain_id, gas_price, gas_limit, index, calldata_arg
        );
    }

    Ok(())
}

fn format_eth(wei: u128) -> String {
    let eth = wei as f64 / 1e18;
    if eth >= 0.0001 {
        format!("{:.6} ETH", eth)
    } else {
        format!("{:.9} ETH", eth)
    }
}

fn format_gwei(wei: u128) -> String {
    format!("{:.3} gwei", wei as f64 / 1e9)
}

// =============================================================================
// publish: broadcast a signed tx via eth_sendRawTransaction
// =============================================================================

fn cmd_publish(signed_tx_hex: &str, rpc_url: &str, wait: bool, wait_timeout: u64) -> Result<()> {
    let hex_str = signed_tx_hex.strip_prefix("0x").unwrap_or(signed_tx_hex);
    let signed = hex::decode(hex_str)?;
    if signed.is_empty() {
        bail!("empty signed tx");
    }

    let mut rpc = rpc::RpcClient::new(rpc_url);
    let tx_hash = rpc.send_raw_transaction(&signed)?;
    println!("tx hash: {}", tx_hash);

    if !wait {
        return Ok(());
    }

    println!("waiting for inclusion (timeout: {}s)...", wait_timeout);
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_secs(3);
    loop {
        if start.elapsed().as_secs() > wait_timeout {
            bail!("timeout waiting for tx receipt");
        }
        match rpc.get_transaction_receipt(&tx_hash)? {
            Some(receipt) => {
                let block = receipt.get("blockNumber")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let status = receipt.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let gas_used = receipt.get("gasUsed")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let status_label = match status {
                    "0x1" => "success",
                    "0x0" => "REVERTED",
                    _ => status,
                };
                println!("included in block {}", block);
                println!("status:    {}", status_label);
                println!("gas used:  {}", gas_used);
                return Ok(());
            }
            None => {
                std::thread::sleep(poll_interval);
            }
        }
    }
}

// =============================================================================
// build-tx: produce the unsigned RLP without touching the device
// =============================================================================

#[allow(clippy::too_many_arguments)]
fn cmd_build_tx(
    to: &str,
    value: u128,
    nonce: u64,
    chain_id: u64,
    gas_price: u64,
    gas_limit: u64,
    data_hex: Option<&str>,
) -> Result<()> {
    let to_clean = to.strip_prefix("0x").unwrap_or(to);
    let to_addr = hex::decode(to_clean)?;
    if to_addr.len() != 20 {
        bail!("invalid address: need 20 bytes, got {}", to_addr.len());
    }

    let calldata: Vec<u8> = match data_hex {
        Some(h) => hex::decode(h.strip_prefix("0x").unwrap_or(h))?,
        None => Vec::new(),
    };

    let params = TxParams { nonce, gas_price, gas_limit, chain_id };
    let unsigned = rlp_encode_legacy_unsigned(&to_addr, value, &calldata, &params);

    println!("chain:    {} ({})", chain_id, chain_name(chain_id));
    println!("to:       0x{}", to_clean);
    println!("value:    {} wei", value);
    println!("nonce:    {}  gas: {}  gasPrice: {} wei", nonce, gas_limit, gas_price);
    if !calldata.is_empty() {
        println!("data:     0x{}", hex::encode(&calldata));
    }
    println!("unsigned: 0x{}", hex::encode(&unsigned));
    println!();
    println!("To sign and broadcast: beth sign-tx 0x{}", hex::encode(&unsigned));
    Ok(())
}

// =============================================================================
// gen-tx: build, sign, and emit a legacy EIP-155 transaction
// =============================================================================

#[allow(clippy::too_many_arguments)]
fn cmd_gen_tx(
    t: &mut Transport,
    to: &str,
    value: u128,
    nonce: u64,
    chain_id: u64,
    gas_price: u64,
    gas_limit: u64,
    index: u32,
    data_hex: Option<&str>,
) -> Result<()> {
    let to_clean = to.strip_prefix("0x").unwrap_or(to);
    let to_addr = hex::decode(to_clean)?;
    if to_addr.len() != 20 {
        bail!("invalid address: need 20 bytes, got {}", to_addr.len());
    }

    let calldata: Vec<u8> = match data_hex {
        Some(h) => {
            let h = h.strip_prefix("0x").unwrap_or(h);
            hex::decode(h)?
        }
        None => Vec::new(),
    };

    let params = TxParams { nonce, gas_price, gas_limit, chain_id };
    let unsigned = rlp_encode_legacy_unsigned(&to_addr, value, &calldata, &params);

    // Build payload: [path_bytes...][rlp_unsigned_tx_bytes...]
    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(&unsigned);

    let (status, resp) = t.command(OP_SIGN_TRANSACTION, &payload)?;
    if status != STATUS_OK {
        bail!("sign failed (status: 0x{:02x})", status);
    }
    if resp.len() < 72 {
        bail!("unexpected signature response length: {}", resp.len());
    }

    let v = u64::from_le_bytes(resp[0..8].try_into().unwrap());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&resp[8..40]);
    s.copy_from_slice(&resp[40..72]);

    let signed = rlp_encode_legacy_signed(&to_addr, value, &calldata, &params, v, &r, &s);

    println!("chain: {} ({})", chain_id, chain_name(chain_id));
    println!("to:    0x{}", to_clean);
    println!("value: {} wei", value);
    println!("nonce: {}  gas: {}  gasPrice: {} wei", nonce, gas_limit, gas_price);
    if !calldata.is_empty() {
        println!("data:  0x{}", hex::encode(&calldata));
    }
    println!("v={}", v);
    println!("r={}", hex::encode(&r));
    println!("s={}", hex::encode(&s));
    println!("raw:   0x{}", hex::encode(&signed));
    Ok(())
}

// =============================================================================
// qr: display address as QR code
// =============================================================================

fn cmd_qr_device(t: &mut Transport, index: u32) -> Result<()> {
    let path = bip44_payload(0, 0, index);
    let (status, payload) = t.command(OP_GET_ADDRESS, &path)?;
    if status != STATUS_OK || payload.len() < 20 {
        bail!("failed to get address from device (status: 0x{:02x})", status);
    }
    let addr = format!("0x{}", hex::encode(&payload[..20]));
    print_qr(&addr)
}

fn cmd_qr_address(address: &str) -> Result<()> {
    let addr = if address.starts_with("0x") || address.starts_with("0X") {
        address.to_string()
    } else {
        format!("0x{}", address)
    };
    print_qr(&addr)
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

    // Render using Unicode upper/lower half blocks for 2 rows per line.
    // Black module = dark, white module = light.
    // U+2588 = full block, U+2580 = upper half, U+2584 = lower half, space = empty
    //
    // With inverted colors (dark terminal): dark=space, light=block
    // We add a quiet zone (1 module border).

    let get = |r: i32, c: i32| -> bool {
        if r < 0 || c < 0 || r >= width as i32 || c >= width as i32 {
            false // quiet zone = light
        } else {
            modules[r as usize * width + c as usize].select(true, false)
        }
    };

    // Process two rows at a time
    let mut r: i32 = -1;
    while r < width as i32 + 1 {
        print!("    "); // left margin
        for c in -1..width as i32 + 1 {
            let top = get(r, c);      // true = dark
            let bot = get(r + 1, c);  // true = dark
            // Terminal is typically dark background, so:
            // dark+dark = space, light+light = full block,
            // dark+light = lower half, light+dark = upper half
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
// encrypted import: ECIES mnemonic transfer
// =============================================================================

fn cmd_init_import_key(t: &mut Transport, overwrite: bool) -> Result<()> {
    let payload = [if overwrite { 0x01 } else { 0x00 }];
    let (status, _) = t.command(OP_INIT_IMPORT_KEY, &payload)?;
    match status {
        STATUS_OK => println!("Import key initialized."),
        0x08 => bail!("Import key already exists. Use --overwrite to replace."),
        _ => bail!("init-import-key failed (status: 0x{:02x})", status),
    }
    Ok(())
}

fn cmd_get_import_key(t: &mut Transport) -> Result<()> {
    let (status, payload) = t.command(OP_GET_IMPORT_KEY, &[])?;
    if status != STATUS_OK {
        bail!("get-import-key failed (status: 0x{:02x})", status);
    }
    if payload.len() < 33 {
        bail!("unexpected response length: {}", payload.len());
    }
    println!("0x{}", hex::encode(&payload[..33]));
    Ok(())
}

fn cmd_import_encrypted(t: &mut Transport) -> Result<()> {
    // First, get the device's import public key
    let (status, key_resp) = t.command(OP_GET_IMPORT_KEY, &[])?;
    if status != STATUS_OK {
        bail!(
            "failed to get import key (status: 0x{:02x}). Run init-import-key first.",
            status
        );
    }
    if key_resp.len() < 33 {
        bail!("unexpected import key length: {}", key_resp.len());
    }
    let pubkey_hex = hex::encode(&key_resp[..33]);
    println!("Device import pubkey: 0x{}", pubkey_hex);

    // Prompt for mnemonic
    print!("Enter your BIP39 mnemonic (12 or 24 words): ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let line = stdin.lock().lines().next()
        .ok_or_else(|| anyhow::anyhow!("No input"))??;

    let words: Vec<&str> = line.split_whitespace().collect();
    if words.len() != 12 && words.len() != 24 {
        bail!("Expected 12 or 24 words, got {}", words.len());
    }

    let mnemonic = words.join(" ");

    // Encrypt with ECIES
    let encrypted = ecies_encrypt(&key_resp[..33], mnemonic.as_bytes())?;
    println!("Encrypted payload: {} bytes", encrypted.len());

    // Send to device
    let (status, _) = t.command(OP_IMPORT_ENCRYPTED, &encrypted)?;
    match status {
        STATUS_OK => {
            println!("Encrypted mnemonic imported.");
            // Show derived address
            let path = bip44_payload(0, 0, 0);
            if let Ok((s, payload)) = t.command(OP_GET_ADDRESS, &path) {
                if s == STATUS_OK && payload.len() >= 20 {
                    println!("address[0]: 0x{}", hex::encode(&payload[..20]));
                }
            }
        }
        0x0A => bail!("Decryption failed on device (wrong key or corrupted ciphertext)"),
        _ => bail!("import-encrypted failed (status: 0x{:02x})", status),
    }
    Ok(())
}

/// ECIES encrypt: secp256k1 ECDH + HKDF-SHA256 + ChaCha20-Poly1305.
fn ecies_encrypt(recipient_pubkey: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
    use hkdf::Hkdf;
    use k256::ecdsa::SigningKey;
    use sha2::Digest;

    let recipient = k256::PublicKey::from_sec1_bytes(recipient_pubkey)
        .map_err(|e| anyhow::anyhow!("invalid import pubkey: {}", e))?;

    // Ephemeral keypair
    let e_priv = SigningKey::random(&mut rand_core::OsRng);
    let e_pub_point = e_priv.verifying_key().to_encoded_point(true);
    let e_pub_bytes = e_pub_point.as_bytes(); // 33 bytes

    // ECDH shared secret
    let shared = k256::ecdh::diffie_hellman(
        e_priv.as_nonzero_scalar(),
        recipient.as_affine(),
    );

    // HKDF-SHA256
    let hk = Hkdf::<sha2::Sha256>::new(Some(b"ethapp-import-v1"), shared.raw_secret_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"", &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    // Nonce: first 12 bytes of SHA-256(e_pub_bytes)
    let hash = sha2::Sha256::digest(e_pub_bytes);
    let nonce: [u8; 12] = hash[..12].try_into().unwrap();

    // ChaCha20-Poly1305 encrypt
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ct = cipher.encrypt((&nonce).into(), plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    // Wire: [e_pub:33][ciphertext+tag]
    let mut payload = Vec::with_capacity(33 + ct.len());
    payload.extend_from_slice(e_pub_bytes);
    payload.extend_from_slice(&ct);
    Ok(payload)
}

// =============================================================================
// attestation: device attestation identity
// =============================================================================

fn cmd_init_attestation(t: &mut Transport, overwrite: bool) -> Result<()> {
    let payload = [if overwrite { 0x01 } else { 0x00 }];
    let (status, _) = t.command(OP_INIT_ATTESTATION, &payload)?;
    match status {
        STATUS_OK => println!("Attestation key initialized."),
        0x06 => bail!("Attestation key already exists. Use --overwrite to replace."),
        _ => bail!("init-attestation failed (status: 0x{:02x})", status),
    }
    Ok(())
}

fn cmd_get_attestation_key(t: &mut Transport) -> Result<()> {
    let (status, payload) = t.command(OP_GET_ATTESTATION_KEY, &[])?;
    if status != STATUS_OK {
        bail!("get-attestation-key failed (status: 0x{:02x})", status);
    }
    if payload.len() < 33 {
        bail!("unexpected response length: {}", payload.len());
    }
    println!("0x{}", hex::encode(&payload[..33]));
    Ok(())
}

fn cmd_attest_sign_tx(t: &mut Transport, rlp_hex: &str, index: u32) -> Result<()> {
    let hex_str = rlp_hex.strip_prefix("0x").unwrap_or(rlp_hex);
    let tx_data = hex::decode(hex_str)?;

    let tx_type = if !tx_data.is_empty() && tx_data[0] < 0x80 {
        Some(tx_data[0])
    } else {
        None
    };

    let mut payload = bip44_payload(0, 0, index);
    payload.extend_from_slice(&tx_data);

    let (status, resp) = t.command(OP_ATTEST_SIGN, &payload)?;
    if status != STATUS_OK {
        bail!("attest-sign-tx failed (status: 0x{:02x})", status);
    }

    // Response: tx_sig (72 bytes: v:8 + r:32 + s:32) + attest_sig (72 bytes)
    if resp.len() < 144 {
        bail!("unexpected response length: {} (expected 144)", resp.len());
    }

    // Parse tx signature
    let tx_v = u64::from_le_bytes(resp[0..8].try_into().unwrap());
    let mut tx_r = [0u8; 32];
    let mut tx_s = [0u8; 32];
    tx_r.copy_from_slice(&resp[8..40]);
    tx_s.copy_from_slice(&resp[40..72]);

    // Parse attestation signature
    let attest_v = u64::from_le_bytes(resp[72..80].try_into().unwrap());
    let mut attest_r = [0u8; 32];
    let mut attest_s = [0u8; 32];
    attest_r.copy_from_slice(&resp[80..112]);
    attest_s.copy_from_slice(&resp[112..144]);

    println!("tx_v={}", tx_v);
    println!("tx_r={}", hex::encode(&tx_r));
    println!("tx_s={}", hex::encode(&tx_s));
    println!("attest_v={}", attest_v);
    println!("attest_r={}", hex::encode(&attest_r));
    println!("attest_s={}", hex::encode(&attest_s));

    // Assemble broadcastable signed RLP from the tx signature
    match assemble_signed_tx(&tx_data, tx_type, tx_v, &tx_r, &tx_s) {
        Ok(signed) => println!("raw: 0x{}", hex::encode(&signed)),
        Err(e) => eprintln!("warning: could not assemble signed RLP ({})", e),
    }

    Ok(())
}

fn cmd_verify_attestation(
    pubkey_hex: &str,
    sign_hash_hex: &str,
    tx_v: u64,
    tx_r_hex: &str,
    tx_s_hex: &str,
    attest_v: u64,
    attest_r_hex: &str,
    attest_s_hex: &str,
) -> Result<()> {
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
    use tiny_keccak::{Hasher, Keccak};

    // Parse inputs
    let pubkey_bytes = hex::decode(pubkey_hex.strip_prefix("0x").unwrap_or(pubkey_hex))?;
    if pubkey_bytes.len() != 33 {
        bail!("pubkey must be 33 bytes (compressed), got {}", pubkey_bytes.len());
    }

    let sign_hash = hex::decode(sign_hash_hex.strip_prefix("0x").unwrap_or(sign_hash_hex))?;
    if sign_hash.len() != 32 {
        bail!("sign_hash must be 32 bytes, got {}", sign_hash.len());
    }

    let tx_r = hex::decode(tx_r_hex.strip_prefix("0x").unwrap_or(tx_r_hex))?;
    let tx_s = hex::decode(tx_s_hex.strip_prefix("0x").unwrap_or(tx_s_hex))?;
    let attest_r = hex::decode(attest_r_hex.strip_prefix("0x").unwrap_or(attest_r_hex))?;
    let attest_s = hex::decode(attest_s_hex.strip_prefix("0x").unwrap_or(attest_s_hex))?;

    if tx_r.len() != 32 || tx_s.len() != 32 || attest_r.len() != 32 || attest_s.len() != 32 {
        bail!("r and s values must be 32 bytes each");
    }

    // Reconstruct the attestation message: keccak256(sign_hash || v_le || r || s)
    let mut message = Vec::with_capacity(32 + 8 + 32 + 32);
    message.extend_from_slice(&sign_hash);
    message.extend_from_slice(&tx_v.to_le_bytes());
    message.extend_from_slice(&tx_r);
    message.extend_from_slice(&tx_s);

    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(&message);
    keccak.finalize(&mut hash);

    // Recover the signer from the attestation signature
    let recovery_id = match attest_v {
        27 => RecoveryId::new(false, false),
        28 => RecoveryId::new(true, false),
        v => bail!("invalid attestation v value: {} (expected 27 or 28)", v),
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&attest_r);
    sig_bytes[32..].copy_from_slice(&attest_s);
    let sig = K256Sig::from_bytes((&sig_bytes[..]).into())
        .map_err(|e| anyhow::anyhow!("invalid attestation signature: {}", e))?;

    let recovered = VerifyingKey::recover_from_prehash(&hash, &sig, recovery_id)
        .map_err(|e| anyhow::anyhow!("signature recovery failed: {}", e))?;

    let recovered_point = recovered.to_encoded_point(true);
    let expected = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|e| anyhow::anyhow!("invalid pubkey: {}", e))?;
    let expected_point = expected.to_encoded_point(true);

    if recovered_point == expected_point {
        println!("VALID: attestation matches device pubkey 0x{}", hex::encode(&pubkey_bytes));
    } else {
        println!("INVALID: recovered signer 0x{} does not match expected 0x{}",
            hex::encode(recovered_point.as_bytes()), hex::encode(&pubkey_bytes));
        std::process::exit(1);
    }

    Ok(())
}

// =============================================================================
// guide: step-by-step walkthrough
// =============================================================================

fn cmd_guide(mainnet: bool) -> Result<()> {
    if mainnet {
        print!(r#"
Ethereum Mainnet Guide: Transfer USDC
======================================

  WARNING: This uses REAL funds on Ethereum mainnet.
  On displayless dev boards, run `beth dangerous-mode` first.

Prerequisites:
  - beth built and in PATH
  - Baochip device connected via USB
  - A wallet seed loaded (generate-mnemonic or import-mnemonic)

Constants:
  RPC     = https://ethereum-rpc.publicnode.com
  USDC    = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48  (Circle USDC, 6 decimals)
  CHAIN   = 1 (mainnet)

Step 1: Get your address
  beth address --index 0
  # -> 0xYourAddress

Step 2: Fund with ETH (for gas)
  Send at least 0.005 ETH to your address from an exchange or
  another wallet. An ERC-20 transfer costs ~65,000 gas * ~5 gwei
  = ~0.000325 ETH. Check current gas at https://etherscan.io/gastracker

Step 3: Fund with USDC
  Send USDC to your address from an exchange or another wallet.

Step 4: Verify balances
  beth balance \
    --rpc-url https://ethereum-rpc.publicnode.com \
    --index 0

  beth token-balance \
    --token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
    --rpc-url https://ethereum-rpc.publicnode.com \
    --index 0 --decimals 6 --symbol USDC

Step 5: Enable mainnet signing (dev boards only)
  beth dangerous-mode
  # Type "I ACCEPT THE RISK" when prompted. Session-only, resets on reboot.

Step 6: Send USDC
  # Send 8 USDC (= 8000000 smallest units) to a recipient:
  beth send-token \
    --token 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
    0xRECIPIENT_ADDRESS 8000000 \
    --rpc-url https://ethereum-rpc.publicnode.com \
    --index 0 --broadcast

Step 7: Verify on block explorer
  Check the tx hash at https://etherscan.io

Tips:
  - Drop --broadcast to get the raw signed hex without sending
  - Add --legacy to use a legacy (non-EIP-1559) transaction
  - Use --nonce and --gas-limit to override auto-detected values
  - Use beth tx-info to inspect chain state before sending
  - Show your address as a QR code: beth qr --index 0
"#);
    } else {
        print!(r#"
Sepolia Testnet Guide: Fund and Transfer USDC
==============================================

Prerequisites:
  - beth built and in PATH
  - Baochip device connected via USB
  - A wallet seed loaded (generate-mnemonic or import-mnemonic)

Constants:
  RPC     = https://ethereum-sepolia-rpc.publicnode.com
  USDC    = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238  (Circle's Sepolia USDC, 6 decimals)
  CHAIN   = 11155111 (Sepolia)

Step 1: Get your address
  beth address --index 0
  # -> 0xYourAddress

Step 2: Fund with Sepolia ETH (for gas)
  Visit https://cloud.google.com/application/web3/faucet/ethereum/sepolia
  or any Sepolia faucet. Paste your address. You need ~0.01 ETH.

Step 3: Fund with testnet USDC
  Visit https://faucet.circle.com
  Select "Ethereum Sepolia", paste your address.
  You'll receive 10 USDC (may take a few seconds).

Step 4: Verify balances
  beth balance \
    --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
    --index 0

  beth token-balance \
    --token 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 \
    --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
    --index 0 --decimals 6 --symbol USDC

Step 5: Send USDC
  # Send 1 USDC (= 1000000 smallest units) to a recipient:
  beth send-token \
    --token 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 \
    0xRECIPIENT_ADDRESS 1000000 \
    --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
    --index 0 --broadcast

Step 6: Verify on block explorer
  Check the tx hash at https://sepolia.etherscan.io

Tips:
  - Drop --broadcast to get the raw signed hex without sending
  - Add --legacy to use a legacy (non-EIP-1559) transaction
  - Use --nonce and --gas-limit to override auto-detected values
  - Use beth tx-info to inspect chain state before sending
  - Show your address as a QR code: beth qr --index 0
"#);
    }
    Ok(())
}

struct TxParams {
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    chain_id: u64,
}

// =============================================================================
// ERC-20 ABI encoding helpers
// =============================================================================

/// ERC-20 transfer(address,uint256) selector: keccak256("transfer(address,uint256)")[:4]
const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// ERC-20 balanceOf(address) selector: keccak256("balanceOf(address)")[:4]
const ERC20_BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// Encode an ERC-20 `transfer(address,uint256)` call.
/// Returns 68 bytes: 4-byte selector + 32-byte address + 32-byte amount.
fn encode_erc20_transfer(recipient: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&ERC20_TRANSFER_SELECTOR);
    // ABI: address is left-padded to 32 bytes
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(recipient);
    // ABI: uint256 is big-endian, left-padded to 32 bytes
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&amount.to_be_bytes());
    data
}

/// Encode an ERC-20 `balanceOf(address)` call.
/// Returns 36 bytes: 4-byte selector + 32-byte address.
fn encode_erc20_balance_of(owner: &[u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&ERC20_BALANCE_OF_SELECTOR);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(owner);
    data
}

/// RLP-encode a single EIP-7702 authorization tuple:
/// `[chain_id, address, nonce, y_parity, r, s]`
fn rlp_encode_auth_tuple(
    chain_id: u64,
    address: &[u8; 20],
    nonce: u64,
    y_parity: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(chain_id));
    items.extend_from_slice(&rlp_encode_bytes(address));
    items.extend_from_slice(&rlp_encode_u64(nonce));
    items.extend_from_slice(&rlp_encode_u64(y_parity as u64));
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
    rlp_encode_list(&items)
}

/// RLP-encode a list of pre-encoded authorization tuples into an
/// `authorization_list` RLP list.
fn rlp_encode_auth_list(encoded_tuples: &[Vec<u8>]) -> Vec<u8> {
    let mut items = Vec::new();
    for t in encoded_tuples {
        items.extend_from_slice(t);
    }
    rlp_encode_list(&items)
}

/// RLP-encode an unsigned EIP-7702 type-4 transaction:
/// `0x04 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit,
///               to, value, data, access_list, authorization_list])`
///
/// `access_list` accepts pre-encoded EIP-2930 access list entries.
/// Pass `&[]` for an empty access list (the common case).
#[allow(clippy::too_many_arguments)]
fn rlp_encode_eip7702_unsigned(
    chain_id: u64,
    nonce: u64,
    max_priority_fee: u128,
    max_fee: u128,
    gas_limit: u64,
    to: &[u8],
    value: u128,
    data: &[u8],
    access_list: &[u8],
    auth_tuples: &[Vec<u8>],
) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(chain_id));
    items.extend_from_slice(&rlp_encode_u64(nonce));
    items.extend_from_slice(&rlp_encode_u128(max_priority_fee));
    items.extend_from_slice(&rlp_encode_u128(max_fee));
    items.extend_from_slice(&rlp_encode_u64(gas_limit));
    items.extend_from_slice(&rlp_encode_bytes(to));
    items.extend_from_slice(&rlp_encode_u128(value));
    items.extend_from_slice(&rlp_encode_bytes(data));
    items.extend_from_slice(&rlp_encode_list(access_list));
    items.extend_from_slice(&rlp_encode_auth_list(auth_tuples));
    let mut out = vec![0x04];
    out.extend_from_slice(&rlp_encode_list(&items));
    out
}

/// Parse a signed authorization tuple from the CLI string format:
/// `chain_id:address_hex:nonce:y_parity:r_hex:s_hex`
///
/// Returns the RLP-encoded tuple ready for inclusion in an authorization list.
fn parse_signed_auth(s: &str) -> Result<Vec<u8>> {
    let parts: Vec<&str> = s.splitn(6, ':').collect();
    if parts.len() != 6 {
        bail!("--auth must have 6 elements, chain_id:address:nonce:y_parity:r:s, got: {} elements", parts.len());
    }
    let chain_id: u64 = parts[0].parse()
        .map_err(|e| anyhow::anyhow!("invalid auth chain_id '{}': {}", parts[0], e))?;

    let addr_hex = parts[1].strip_prefix("0x").unwrap_or(parts[1]);
    let addr_bytes = hex::decode(addr_hex)
        .map_err(|e| anyhow::anyhow!("invalid auth address '{}': {}", parts[1], e))?;
    if addr_bytes.len() != 20 {
        bail!("auth address must be 20 bytes, got {}", addr_bytes.len());
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&addr_bytes);

    let nonce: u64 = parts[2].parse()
        .map_err(|e| anyhow::anyhow!("invalid auth nonce '{}': {}", parts[2], e))?;

    let y_parity: u8 = parts[3].parse()
        .map_err(|e| anyhow::anyhow!("invalid auth y_parity '{}': {}", parts[3], e))?;
    if y_parity > 1 {
        bail!("auth y_parity must be 0 or 1, got {}", y_parity);
    }

    let r_hex = parts[4].strip_prefix("0x").unwrap_or(parts[4]);
    let r_bytes = hex::decode(r_hex)
        .map_err(|e| anyhow::anyhow!("invalid auth r '{}': {}", parts[4], e))?;
    if r_bytes.is_empty() || r_bytes.len() > 32 {
        bail!("auth r must be 1–32 bytes, got {}", r_bytes.len());
    }
    let mut r = [0u8; 32];
    r[32 - r_bytes.len()..].copy_from_slice(&r_bytes);

    let s_hex = parts[5].strip_prefix("0x").unwrap_or(parts[5]);
    let s_bytes = hex::decode(s_hex)
        .map_err(|e| anyhow::anyhow!("invalid auth s '{}': {}", parts[5], e))?;
    if s_bytes.is_empty() || s_bytes.len() > 32 {
        bail!("auth s must be 1–32 bytes, got {}", s_bytes.len());
    }
    let mut s = [0u8; 32];
    s[32 - s_bytes.len()..].copy_from_slice(&s_bytes);

    Ok(rlp_encode_auth_tuple(chain_id, &address, nonce, y_parity, &r, &s))
}

/// RLP-encode an unsigned EIP-1559 transaction:
/// 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
///              gasLimit, to, value, data, accessList(empty)])
fn rlp_encode_eip1559_unsigned(
    chain_id: u64,
    nonce: u64,
    max_priority_fee: u128,
    max_fee: u128,
    gas_limit: u64,
    to: &[u8],
    value: u128,
    data: &[u8],
) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(chain_id));
    items.extend_from_slice(&rlp_encode_u64(nonce));
    items.extend_from_slice(&rlp_encode_u128(max_priority_fee));
    items.extend_from_slice(&rlp_encode_u128(max_fee));
    items.extend_from_slice(&rlp_encode_u64(gas_limit));
    items.extend_from_slice(&rlp_encode_bytes(to));
    items.extend_from_slice(&rlp_encode_u128(value));
    items.extend_from_slice(&rlp_encode_bytes(data));
    items.extend_from_slice(&rlp_encode_list(&[])); // empty access list
    let mut out = vec![0x02]; // EIP-1559 type byte
    out.extend_from_slice(&rlp_encode_list(&items));
    out
}

/// RLP-encode an unsigned legacy EIP-155 transaction:
/// [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
fn rlp_encode_legacy_unsigned(to: &[u8], value: u128, data: &[u8], p: &TxParams) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(p.nonce));
    items.extend_from_slice(&rlp_encode_u64(p.gas_price));
    items.extend_from_slice(&rlp_encode_u64(p.gas_limit));
    items.extend_from_slice(&rlp_encode_bytes(to));
    items.extend_from_slice(&rlp_encode_u128(value));
    items.extend_from_slice(&rlp_encode_bytes(data));
    items.extend_from_slice(&rlp_encode_u64(p.chain_id));
    items.extend_from_slice(&rlp_encode_u64(0));
    items.extend_from_slice(&rlp_encode_u64(0));
    rlp_encode_list(&items)
}

/// RLP-encode a signed legacy transaction:
/// [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
fn rlp_encode_legacy_signed(
    to: &[u8], value: u128, data: &[u8], p: &TxParams,
    v: u64, r: &[u8; 32], s: &[u8; 32],
) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp_encode_u64(p.nonce));
    items.extend_from_slice(&rlp_encode_u64(p.gas_price));
    items.extend_from_slice(&rlp_encode_u64(p.gas_limit));
    items.extend_from_slice(&rlp_encode_bytes(to));
    items.extend_from_slice(&rlp_encode_u128(value));
    items.extend_from_slice(&rlp_encode_bytes(data));
    items.extend_from_slice(&rlp_encode_u64(v));
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(r)));
    items.extend_from_slice(&rlp_encode_bytes(trim_leading_zeros(s)));
    rlp_encode_list(&items)
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    rlp_encode_bytes(&bytes[start..])
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(16);
    rlp_encode_bytes(&bytes[start..])
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0x80];
    }
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    if data.len() <= 55 {
        let mut result = vec![0x80 + data.len() as u8];
        result.extend_from_slice(data);
        return result;
    }
    let len_bytes = (data.len() as u64).to_be_bytes();
    let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let len_bytes = &len_bytes[start..];
    let mut result = vec![0xb7 + len_bytes.len() as u8];
    result.extend_from_slice(len_bytes);
    result.extend_from_slice(data);
    result
}

fn rlp_encode_list(items: &[u8]) -> Vec<u8> {
    if items.len() <= 55 {
        let mut result = vec![0xc0 + items.len() as u8];
        result.extend_from_slice(items);
        return result;
    }
    let len_bytes = (items.len() as u64).to_be_bytes();
    let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let len_bytes = &len_bytes[start..];
    let mut result = vec![0xf7 + len_bytes.len() as u8];
    result.extend_from_slice(len_bytes);
    result.extend_from_slice(items);
    result
}

fn chain_name(id: u64) -> &'static str {
    match id {
        1 => "mainnet",
        5 => "goerli",
        10 => "optimism",
        56 => "bsc",
        137 => "polygon",
        17000 => "holesky",
        42161 => "arbitrum",
        11155111 => "sepolia",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_encode_auth_tuple_field_count() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let encoded = rlp_encode_auth_tuple(1, &[0xab; 20], 5, 0, &r, &s);

        let items = decode_top_level_items(&encoded).expect("should decode as list");
        assert_eq!(items.len(), 6, "auth tuple must have exactly 6 fields");
    }

    #[test]
    fn test_rlp_encode_auth_tuple_field_values() {
        // Verify each field is in the correct position.
        let chain_id: u64 = 11155111;
        let address = [0xdeu8; 20];
        let nonce: u64 = 42;
        let y_parity: u8 = 1;
        let r = [0x33u8; 32];
        let s = [0x44u8; 32];

        let encoded = rlp_encode_auth_tuple(chain_id, &address, nonce, y_parity, &r, &s);
        let items = decode_top_level_items(&encoded).unwrap();

        let (_, payload_len, _) = parse_rlp_header(&items[0]).unwrap();
        let chain_id_bytes = &items[0][items[0].len() - payload_len..];
        let decoded_chain_id = chain_id_bytes.iter().fold(0u64, |a, &b| (a << 8) | b as u64);
        assert_eq!(decoded_chain_id, chain_id);

        assert_eq!(items[1][0], 0x94, "address field must have 20-byte string prefix");

        let (_, yp_len, _) = parse_rlp_header(&items[3]).unwrap();
        let yp_val = if yp_len == 0 { 0u8 } else { items[3][items[3].len() - 1] };
        assert_eq!(yp_val, y_parity);
    }

    #[test]
    fn test_rlp_encode_decode_eip7702() {
        // EIP-7702 type-4 transactions must start with 0x04.
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let auth = rlp_encode_auth_tuple(1, &[0xab; 20], 0, 0, &r, &s);
        let tx = rlp_encode_eip7702_unsigned(
            1, 0, 1_000_000_000, 1_000_000_000, 50_000,
            &[0xde; 20], 0, &[], &[], &[auth],
        );
        assert_eq!(tx[0], 0x04, "type-4 tx must start with 0x04");

        let items = decode_top_level_items(&tx[1..]).expect("should decode");
        assert_eq!(items.len(), 10, "unsigned EIP-7702 tx must have 10 fields");

        let (_, _, is_list) = parse_rlp_header(&items[9]).unwrap();
        assert!(is_list, "field 9 must be the authorization_list (an RLP list)");

        // That list must contain exactly one entry.
        let auth_list_items = decode_top_level_items(&items[9]).unwrap();
        assert_eq!(auth_list_items.len(), 1, "authorization_list must contain 1 entry");
    }


    // =========================================================================
    // assemble_signed_tx — type-4 arm
    // =========================================================================

    #[test]
    fn test_assemble_signed_tx_type4_produces_13_fields() {
        // Signing a type-4 tx appends (y_parity, r, s) → 13 total fields.
        let r_sig = [0x55u8; 32];
        let s_sig = [0x66u8; 32];
        let auth = rlp_encode_auth_tuple(1, &[0xab; 20], 0, 0, &[0x11; 32], &[0x22; 32]);
        let unsigned = rlp_encode_eip7702_unsigned(
            1, 0, 0, 0, 50_000,
            &[0xde; 20], 0, &[], &[], &[auth],
        );

        let signed = assemble_signed_tx(&unsigned, Some(0x04), 0, &r_sig, &s_sig)
            .expect("assemble should succeed");

        assert_eq!(signed[0], 0x04, "signed tx must start with 0x04");
        let items = decode_top_level_items(&signed[1..]).unwrap();
        assert_eq!(items.len(), 13, "signed EIP-7702 tx must have 13 fields");
    }

    #[test]
    fn test_assemble_signed_tx_type4_rejects_invalid_y_parity() {
        let auth = rlp_encode_auth_tuple(1, &[0xab; 20], 0, 0, &[0x11; 32], &[0x22; 32]);
        let unsigned = rlp_encode_eip7702_unsigned(
            1, 0, 0, 0, 50_000,
            &[0xde; 20], 0, &[], &[], &[auth],
        );
        // v = 2 is invalid for EIP-7702
        let result = assemble_signed_tx(&unsigned, Some(0x04), 2, &[0x55; 32], &[0x66; 32]);
        assert!(result.is_err(), "y_parity=2 must be rejected");
    }
}
