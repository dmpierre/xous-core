//! Companion-wallet command handlers (init, balance, sync, send).
//!
//! Bridges synchronous serial-bound flows (device IPC) and asynchronous
//! lightwalletd / wallet operations via an on-demand tokio runtime.

use anyhow::{anyhow, bail, Context, Result};
use tokio::runtime::Runtime;
use tonic::transport::Channel;

use zcash_client_backend::{
    data_api::{
        wallet::ConfirmationsPolicy, Account as _, AccountBirthday, WalletRead,
    },
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_keys::keys::UnifiedAddressRequest;
use zcash_protocol::consensus::Network;

use crate::{
    config::{self, Config},
    transport::Transport,
    wallet,
    OP_GET_ORCHARD_FVK,
};

const STATUS_OK: u8 = 0x00;

/// Tokio runtime created per-command. The borrow checker keeps it alive
/// while futures run via `block_on`.
fn rt() -> Result<Runtime> {
    Runtime::new().context("Failed to create tokio runtime")
}

/// Format a scan/recovery progress fraction. When the wallet has no
/// notes yet the fraction is 0/0, which would print as `NaN%`; we
/// surface that as a dash so the output stays readable.
fn format_progress(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        "—".to_string()
    } else {
        format!("{:0.3}%", (numerator as f64) * 100.0 / (denominator as f64))
    }
}

/// Establish a tonic gRPC client to the configured lightwalletd server.
pub(crate) async fn lwd_connect(server: &str) -> Result<CompactTxStreamerClient<Channel>> {
    let endpoint = tonic::transport::Endpoint::from_shared(server.to_string())
        .with_context(|| format!("Invalid lightwalletd URL: {}", server))?;
    let endpoint = if server.starts_with("https://") {
        endpoint.tls_config(
            tonic::transport::ClientTlsConfig::new()
                .with_webpki_roots()
                .assume_http2(true),
        )?
    } else {
        endpoint
    };
    let channel = endpoint.connect().await.context("Connecting to lightwalletd")?;
    Ok(CompactTxStreamerClient::new(channel))
}

/// Read the device's raw 96-byte Orchard FVK for `account`.
fn fetch_device_orchard_fvk(port: Option<&str>, account: u32) -> Result<[u8; 96]> {
    let mut t = Transport::open(port)?;
    let payload = account.to_le_bytes().to_vec();
    let (status, resp) = t.command(OP_GET_ORCHARD_FVK, &payload)?;
    if status != STATUS_OK {
        bail!(
            "Device error fetching FVK: {} (0x{:02x})",
            crate::transport::status_message(status),
            status
        );
    }
    if resp.len() != 96 {
        bail!("Unexpected FVK length: {} bytes", resp.len());
    }
    let mut out = [0u8; 96];
    out.copy_from_slice(&resp);
    Ok(out)
}

/// Read the device's 32-byte ZIP-32 seed fingerprint. The fingerprint
/// is a one-way BLAKE2b-256 of the seed, used to identify which
/// signing wallet a UFVK belongs to (without exposing the seed
/// itself). Older firmware that doesn't implement OP_GET_SEED_FINGERPRINT
/// returns an `INVALID_OPCODE` status — callers should treat that as
/// "fingerprint unavailable" and fall back to a view-only account.
fn fetch_device_seed_fingerprint(port: Option<&str>) -> Result<Option<[u8; 32]>> {
    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(crate::OP_GET_SEED_FINGERPRINT, &[])?;
    // INVALID_OPCODE on older firmware → graceful fall-through.
    if status == crate::transport::STATUS_ERR_INVALID_OPCODE {
        return Ok(None);
    }
    if status != STATUS_OK {
        bail!(
            "Device error fetching seed fingerprint: {} (0x{:02x})",
            crate::transport::status_message(status),
            status
        );
    }
    if resp.len() != 32 {
        bail!(
            "Unexpected seed-fingerprint length: {} bytes (want 32)",
            resp.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&resp);
    Ok(Some(out))
}

// =============================================================================
// init
// =============================================================================

/// Initialise a view-only wallet from a UFVK string (no device contact).
///
/// Mirrors zcash-devtool's `wallet init-fvk`. Use when you've extracted
/// a UFVK from another wallet (e.g. via `zao wallet list-accounts`)
/// and want to set up an observer on a different machine.
///
/// If `seed_fingerprint` + `hd_account_index` are both supplied, the
/// account is recorded as `Spending` (the spending key exists on a
/// matching device somewhere); future PCZTs carry the ZIP-32
/// derivation so the signer can identify "yes, this is mine". If both
/// omitted, the account is `ViewOnly` (pure observer).
pub fn cmd_init_fvk(
    datadir_override: Option<&str>,
    name: &str,
    ufvk_str: &str,
    network: &str,
    birthday: Option<u32>,
    seed_fingerprint_hex: Option<&str>,
    hd_account_index: Option<u32>,
) -> Result<()> {
    let net = config::Network::parse(network)?;
    let datadir = Config::resolve_datadir(datadir_override)?;
    let cfg = Config::load_or_init(datadir, net)?;
    cfg.ensure_dirs()?;

    let params = cfg.network.as_consensus();
    let ufvk = wallet::parse_ufvk(&params, ufvk_str)?;

    let seed_fingerprint = match seed_fingerprint_hex {
        Some(hex_s) => {
            let bytes = hex::decode(hex_s.trim_start_matches("0x"))
                .map_err(|e| anyhow!("invalid seed_fingerprint hex: {:?}", e))?;
            if bytes.len() != 32 {
                bail!(
                    "seed_fingerprint must be 32 bytes (got {})",
                    bytes.len()
                );
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes);
            Some(a)
        }
        None => None,
    };

    let mut db = wallet::open_wallet_db(&cfg)?;
    wallet::init_wallet_db(&mut db)?;
    wallet::init_block_db(&cfg)?;

    println!("Connecting to lightwalletd at {}...", cfg.server);
    let runtime = rt()?;
    let birthday = runtime.block_on(async {
        let mut client = lwd_connect(&cfg.server).await?;
        let tip: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await
            .context("get_latest_block")?
            .into_inner()
            .height
            .try_into()
            .map_err(|_| anyhow!("Invalid chain tip height"))?;
        let target = birthday.unwrap_or_else(|| tip.saturating_sub(100));
        println!("Chain tip: {}, using birthday: {}", tip, target);
        let request = service::BlockId {
            height: u64::from(target).saturating_sub(1),
            hash: vec![],
        };
        let treestate = client
            .get_tree_state(request)
            .await
            .context("get_tree_state")?
            .into_inner();
        AccountBirthday::from_treestate(treestate, Some(tip.into()))
            .map_err(|e| anyhow!("Invalid tree state: {:?}", debug_birthday_err(&e)))
    })?;

    wallet::import_account_ufvk_with_derivation(
        &mut db,
        name,
        &ufvk,
        &birthday,
        seed_fingerprint.as_ref(),
        hd_account_index,
    )?;

    let purpose_label = match (seed_fingerprint.as_ref(), hd_account_index) {
        (Some(_), Some(_)) => "spending (with derivation)",
        _ => "view-only",
    };
    println!(
        "View-only wallet initialised at {} (network={:?}, birthday={}, purpose={})",
        cfg.datadir.display(),
        cfg.network,
        birthday.height(),
        purpose_label,
    );
    Ok(())
}

/// Print every account in the wallet DB along with its UFVK + ZIP-32
/// derivation if known. Mirrors zcash-devtool's `wallet list-accounts`.
/// The output is intended to be plug-and-play for another tool's
/// `init-fvk` (or an external watch-only wallet).
pub fn cmd_list_accounts(datadir_override: Option<&str>) -> Result<()> {
    use zcash_client_backend::data_api::{Account, AccountSource, WalletRead};

    let cfg = config::load_existing(datadir_override)?;
    let params = cfg.network.as_consensus();
    let db = wallet::open_wallet_db(&cfg)?;

    let account_ids = db.get_account_ids()?;
    if account_ids.is_empty() {
        println!("(no accounts; run `zao wallet init` or `wallet init-fvk` first)");
        return Ok(());
    }

    for (idx, account_id) in account_ids.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        let account = db
            .get_account(*account_id)?
            .ok_or_else(|| anyhow!("Account {:?} missing from db", account_id))?;
        println!(
            "Account {} (birthday height {})",
            account_id.expose_uuid(),
            u32::from(account.birthday_height())
        );
        if let Some(name) = account.name() {
            println!("     Name: {}", name);
        }
        println!("     UIVK: {}", account.uivk().encode(&params));
        println!(
            "     UFVK: {}",
            account
                .ufvk()
                .map_or_else(|| String::from("None"), |k| k.encode(&params))
        );
        match account.source() {
            AccountSource::Derived { derivation, key_source } => {
                println!("     Source: derived");
                println!(
                    "       Seed fingerprint: {}",
                    hex::encode(derivation.seed_fingerprint().to_bytes())
                );
                println!(
                    "       Account index: {}",
                    u32::from(derivation.account_index())
                );
                if let Some(ks) = key_source {
                    println!("       Key source: {}", ks);
                }
            }
            AccountSource::Imported { purpose, key_source } => {
                println!("     Source: imported");
                match purpose {
                    AccountPurposeShim::Spending { derivation } => {
                        println!("       Purpose: spending");
                        if let Some(d) = derivation {
                            println!(
                                "       Seed fingerprint: {}",
                                hex::encode(d.seed_fingerprint().to_bytes())
                            );
                            println!(
                                "       Account index: {}",
                                u32::from(d.account_index())
                            );
                        }
                    }
                    AccountPurposeShim::ViewOnly => {
                        println!("       Purpose: view-only");
                    }
                }
                if let Some(ks) = key_source {
                    println!("       Key source: {}", ks);
                }
            }
        }
    }
    Ok(())
}

// Re-export pattern names so the match above reads cleanly. Keeps the
// long backend type out of the function body.
use zcash_client_backend::data_api::AccountPurpose as AccountPurposeShim;

pub fn cmd_init(
    port: Option<&str>,
    datadir_override: Option<&str>,
    account: u32,
    network: &str,
    birthday: Option<u32>,
    name: &str,
) -> Result<()> {
    let net = config::Network::parse(network)?;
    let datadir = Config::resolve_datadir(datadir_override)?;
    let cfg = Config::load_or_init(datadir, net)?;
    cfg.ensure_dirs()?;

    println!("Reading Orchard FVK from device (account {})...", account);
    let fvk = fetch_device_orchard_fvk(port, account)?;

    // Try to fetch the seed fingerprint too. If the firmware supports
    // OP_GET_SEED_FINGERPRINT (commits >= the one that added it), we
    // record the account as `Spending { derivation }` (with seed
    // fingerprint + account index). Otherwise fall back to ViewOnly —
    // matches our pre-fingerprint behaviour for older firmware.
    let seed_fingerprint = match fetch_device_seed_fingerprint(port) {
        Ok(Some(fp)) => {
            println!("Seed fingerprint: {}", hex::encode(fp));
            Some(fp)
        }
        Ok(None) => {
            println!(
                "Note: device firmware predates OP_GET_SEED_FINGERPRINT; \
                 account will be view-only (no derivation recorded)."
            );
            None
        }
        Err(e) => {
            println!("Warning: seed fingerprint fetch failed: {:#}; falling back to view-only.", e);
            None
        }
    };

    let net_type = match cfg.network.as_consensus() {
        Network::MainNetwork => zcash_protocol::consensus::NetworkType::Main,
        Network::TestNetwork => zcash_protocol::consensus::NetworkType::Test,
    };
    let ufvk_str = wallet::ufvk_string_from_orchard_fvk(net_type, &fvk)?;
    println!("UFVK: {}", ufvk_str);

    let params = cfg.network.as_consensus();
    let ufvk = wallet::parse_ufvk(&params, &ufvk_str)?;

    let mut db = wallet::open_wallet_db(&cfg)?;
    wallet::init_wallet_db(&mut db)?;
    wallet::init_block_db(&cfg)?;

    println!("Connecting to lightwalletd at {}...", cfg.server);
    let runtime = rt()?;
    let birthday = runtime.block_on(async {
        let mut client = lwd_connect(&cfg.server).await?;
        let tip: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await
            .context("get_latest_block")?
            .into_inner()
            .height
            .try_into()
            .map_err(|_| anyhow!("Invalid chain tip height"))?;
        let target = birthday.unwrap_or_else(|| tip.saturating_sub(100));
        println!("Chain tip: {}, using birthday: {}", tip, target);
        let request = service::BlockId {
            height: u64::from(target).saturating_sub(1),
            hash: vec![],
        };
        let treestate = client
            .get_tree_state(request)
            .await
            .context("get_tree_state")?
            .into_inner();
        AccountBirthday::from_treestate(treestate, Some(tip.into()))
            .map_err(|e| anyhow!("Invalid tree state: {:?}", debug_birthday_err(&e)))
    })?;

    wallet::import_account_ufvk_with_derivation(
        &mut db,
        name,
        &ufvk,
        &birthday,
        seed_fingerprint.as_ref(),
        seed_fingerprint.map(|_| account),
    )?;

    if let Some(addr) = db
        .get_account_ids()?
        .into_iter()
        .next()
        .and_then(|aid| {
            db.get_last_generated_address_matching(aid, UnifiedAddressRequest::AllAvailableKeys)
                .ok()
                .flatten()
        })
    {
        println!("Account address: {}", addr.encode(&params));
    }

    println!(
        "Wallet initialised at {} (network={:?}, birthday={})",
        cfg.datadir.display(),
        cfg.network,
        birthday.height(),
    );
    Ok(())
}

fn debug_birthday_err(e: &zcash_client_backend::data_api::BirthdayError) -> String {
    match e {
        zcash_client_backend::data_api::BirthdayError::HeightInvalid(_) => "height invalid".into(),
        zcash_client_backend::data_api::BirthdayError::Decode(io) => format!("decode: {}", io),
    }
}

// =============================================================================
// balance
// =============================================================================

pub fn cmd_balance(datadir_override: Option<&str>) -> Result<()> {
    let cfg = config::load_existing(datadir_override)?;
    let params = cfg.network.as_consensus();
    let db = wallet::open_wallet_db(&cfg)?;

    let account_ids = db.get_account_ids()?;
    let account_id = match account_ids.as_slice() {
        [] => bail!("Wallet contains no accounts. Run `zao wallet init` first."),
        [aid] => *aid,
        _ => bail!("Multiple accounts present; balance only supports a single account."),
    };

    let address =
        db.get_last_generated_address_matching(account_id, UnifiedAddressRequest::AllAvailableKeys)?;
    if let Some(addr) = &address {
        println!("Address: {}", addr.encode(&params));
    }

    let summary_opt = db
        .get_wallet_summary(ConfirmationsPolicy::default())
        .map_err(|e| anyhow!("get_wallet_summary: {:?}", e))?;
    let summary = match summary_opt {
        Some(s) => s,
        None => {
            println!("Insufficient information to build a wallet summary. Try `zao wallet sync`.");
            return Ok(());
        }
    };

    let balance = summary
        .account_balances()
        .get(&account_id)
        .ok_or_else(|| anyhow!("Missing balance for account"))?;

    println!("Chain tip:  {}", summary.chain_tip_height());
    let scan = summary.progress().scan();
    println!(
        "Synced:     {}",
        format_progress(*scan.numerator(), *scan.denominator())
    );
    if let Some(rec) = summary.progress().recovery() {
        println!(
            "Recovered:  {}",
            format_progress(*rec.numerator(), *rec.denominator())
        );
    }
    let total = balance.total();
    let orchard_spendable = balance.orchard_balance().spendable_value();
    let sapling_spendable = balance.sapling_balance().spendable_value();
    println!("Total:      {} zatoshi", u64::from(total));
    println!("Orchard:    {} zatoshi spendable", u64::from(orchard_spendable));
    println!("Sapling:    {} zatoshi spendable", u64::from(sapling_spendable));

    Ok(())
}

// =============================================================================
// guide
// =============================================================================

pub fn cmd_guide(topic: Option<&str>) -> Result<()> {
    let topic = topic.map(|t| t.to_lowercase());
    let want = |t: &str| topic.is_none() || topic.as_deref() == Some(t);
    let mut printed = false;

    if want("setup") {
        if printed { println!(); }
        print!("{}", GUIDE_SETUP);
        printed = true;
    }
    if want("wallet") {
        if printed { println!(); }
        print!("{}", GUIDE_WALLET);
        printed = true;
    }
    if want("send") {
        if printed { println!(); }
        print!("{}", GUIDE_SEND);
        printed = true;
    }
    if want("pipeline") {
        if printed { println!(); }
        print!("{}", GUIDE_PIPELINE);
        printed = true;
    }
    if want("inspect") {
        if printed { println!(); }
        print!("{}", GUIDE_INSPECT);
        printed = true;
    }
    if want("troubleshoot") {
        if printed { println!(); }
        print!("{}", GUIDE_TROUBLESHOOT);
        printed = true;
    }

    if !printed {
        bail!(
            "Unknown topic '{}'. Try: setup | wallet | send | pipeline | inspect | troubleshoot \
             (or omit to print all)",
            topic.unwrap_or_default()
        );
    }
    Ok(())
}

const GUIDE_SETUP: &str = "\
SETUP — get a seed onto the device
══════════════════════════════════
  zao baochip ping                    # confirm device responds
  zao baochip config                  # show protocol version + seed status + network
  zao baochip generate-mnemonic       # OR import-mnemonic
  zao baochip import-mnemonic         # interactive prompt; input is hidden
  zao baochip status                  # confirm signing readiness
  zao baochip address [--account N]   # device's Orchard receiver
  zao baochip fvk [--account N]       # device's 96-byte Orchard FVK (hex)
  zao baochip qr [--account N]        # show address as QR

Notes
  • dabao seed is volatile — re-import after every reboot.
  • mnemonic input is hidden; the terminal prints `[N words received]`.
";

const GUIDE_WALLET: &str = "\
WALLET — initialise + sync + balance
═══════════════════════════════════
  zao wallet init [--network main|test] [--birthday H] [--account N] [--name S]
                                          # build wallet.sqlite from device's UFVK.
                                          # On first run, picks chain tip-100 if no birthday.
  zao wallet sync [--batch-size N]   # scan blocks via lightwalletd
  zao wallet balance                 # address + spendable balance
  zao wallet info                    # everything: paths, UFVK, birthday, sync state

Data lives in $ZAO_DATADIR (default ~/.zao):
  config.toml      — network + lightwalletd URL
  wallet.sqlite    — view-only wallet (UFVK, notes, txs)
  blocks/          — local block cache

Override: --datadir <path> on any command.
";

const GUIDE_SEND: &str = "\
SEND — one-shot pipeline
════════════════════════
  zao wallet send --to <ua> --amount <zat> [--memo TEXT] [--account N]

Runs end-to-end: propose -> create -> prove -> sign-on-device
-> combine -> send (extract+broadcast). Prints the txid on success.

For step-by-step inspection or air-gapped flows, use the granular
pipeline (see: zao guide pipeline).
";

const GUIDE_PIPELINE: &str = "\
PIPELINE — granular send (one stage at a time)
══════════════════════════════════════════════
Each stage writes a file artifact you can inspect, archive, or move
between machines. Mirrors zcash-devtool's `pczt {…}` surface.

  1. zao pczt propose --to <ua> --amount <zat> [--memo TEXT]
                                              # outputs proposal.pb
       Note selection + Zip-317 fee. Pure host, no device, no network.

  2. zao pczt create --proposal proposal.pb
                                              # outputs unsigned.pczt
       Build the unsigned PCZT. Pure host.

  3. zao pczt prove --pczt unsigned.pczt
                                              # outputs proved.pczt
       Add Orchard ZK proofs. ~30s, pure CPU. No secrets needed.

  4. zao pczt sign --unsigned unsigned.pczt
                                              # outputs signed.pczt
       Send unsigned PCZT to device. Device displays summary, signs,
       redacts; outputs the device's signed (skeleton + sig) PCZT.
       Sign sees the unsigned input ONLY — proofs stay on the host.

  5. zao pczt combine --proved proved.pczt --signed signed.pczt
                                              # outputs combined.pczt
       Merge proved + signed into a complete PCZT.

  6. zao pczt send --pczt combined.pczt
       Extract raw transaction, store in wallet DB, broadcast via
       lightwalletd. Prints txid. (Mirrors zcash-devtool's `pczt send`.)

  Optional output paths: -o <path> on stages that produce files.
  Defaults are written to the current working directory.

Air-gapped variant
  Steps 1–3 + 5–6 (no device) can run on an online machine.
  Move unsigned.pczt to the device-attached machine, run step 4 (no
  network), move signed.pczt back. Run step 5 (combine) and 6 (send)
  on the online machine.
";

const GUIDE_INSPECT: &str = "\
INSPECT — human-readable report at any stage
════════════════════════════════════════════
  zao pczt inspect --proposal proposal.pb
  zao pczt inspect --pczt unsigned.pczt
  zao pczt inspect --pczt proved.pczt
  zao pczt inspect --pczt signed.pczt
  zao pczt inspect --pczt combined.pczt
  zao pczt inspect --tx tx.hex

Useful sanity checks
  • Proposal:  fee + change + recipient + step count
  • PCZT:      action count, in/out values, sighash, has-proofs?, has-sigs?
  • Tx:        version + hex digest + sighash
";

const GUIDE_TROUBLESHOOT: &str = "\
TROUBLESHOOT — common failure modes
═══════════════════════════════════
  Synced: 100% but Total: 0
      Wallet birthday is past your funding tx height. Re-init with
      an earlier --birthday. Find the right height with:
          zcash-devtool wallet -w <other-wallet> list-tx
      or any block explorer.

  Could not automatically determine the process-level CryptoProvider
      Build is missing tonic's tls-ring feature. Should not happen
      on current builds — pull and rebuild.

  No seed loaded (0x08) on init
      Run `zao baochip import-mnemonic` (or `baochip generate-mnemonic`) first.

  Failed to parse signed PCZT (DeserializeBadOption)
      Firmware is older than commit c08aa3d3 (\"redact proprietary
      maps in signed PCZT response\"). Reflash with the latest xous.uf2.
      On failure, the proved + signed PCZTs are dumped to
      /tmp/zao-proved.pczt and /tmp/zao-signed.pczt for
      post-mortem.

  Sighash mismatch (STATUS_ERR_SIGHASH_MISMATCH, 0x0D)
      The device computed a different shielded sighash from the PCZT
      than the host claimed. Indicates host bug, version skew, or
      tampering. The device will not sign; the request was correctly
      refused.
";

// =============================================================================
// info
// =============================================================================

pub fn cmd_info(datadir_override: Option<&str>) -> Result<()> {
    let cfg = config::load_existing(datadir_override)?;
    let params = cfg.network.as_consensus();
    let db = wallet::open_wallet_db(&cfg)?;

    println!("Data dir:   {}", cfg.datadir.display());
    println!("Wallet db:  {}", cfg.wallet_db_path().display());
    println!("Blocks dir: {}", cfg.blocks_dir().display());
    println!("Network:    {}", match cfg.network {
        config::Network::Main => "mainnet",
        config::Network::Test => "testnet",
    });
    println!("Server:     {}", cfg.server);
    println!();

    let account_ids = db
        .get_account_ids()
        .map_err(|e| anyhow!("get_account_ids: {:?}", e))?;
    let account_id = match account_ids.as_slice() {
        [] => {
            println!("Wallet has no accounts. Run `zao wallet init`.");
            return Ok(());
        }
        [aid] => *aid,
        many => {
            println!("Wallet has {} accounts (multi-account not supported by this command)",
                many.len());
            return Ok(());
        }
    };

    let account = db
        .get_account(account_id)
        .map_err(|e| anyhow!("get_account: {:?}", e))?
        .ok_or_else(|| anyhow!("Account missing"))?;

    println!("Account ID:   {:?}", account_id);
    if let Some(name) = account.name() {
        println!("Account name: {}", name);
    }

    let address = db
        .get_last_generated_address_matching(account_id, UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| anyhow!("get_last_generated_address_matching: {:?}", e))?;
    if let Some(addr) = &address {
        println!("Address:      {}", addr.encode(&params));
    }

    if let Some(ufvk) = account.ufvk() {
        let encoded = ufvk.encode(&params);
        println!("UFVK:         {}", encoded);
    }

    let birthday = account.birthday_height();
    println!("Birthday:     {}", birthday);

    let summary_opt = db
        .get_wallet_summary(ConfirmationsPolicy::default())
        .map_err(|e| anyhow!("get_wallet_summary: {:?}", e))?;
    match summary_opt {
        Some(s) => {
            println!("Chain tip:    {}", s.chain_tip_height());
            println!("Fully scanned: {}", s.fully_scanned_height());
            let scan = s.progress().scan();
            println!(
                "Scan progress: {}",
                format_progress(*scan.numerator(), *scan.denominator())
            );
            if let Some(rec) = s.progress().recovery() {
                println!(
                    "Recovery progress: {}",
                    format_progress(*rec.numerator(), *rec.denominator())
                );
            }
            if let Some(bal) = s.account_balances().get(&account_id) {
                println!();
                println!(
                    "Total balance: {} zatoshi",
                    u64::from(bal.total())
                );
                println!(
                    "  Orchard spendable: {}",
                    u64::from(bal.orchard_balance().spendable_value())
                );
                println!(
                    "  Sapling spendable: {}",
                    u64::from(bal.sapling_balance().spendable_value())
                );
            }
        }
        None => {
            println!("Chain tip:    (never synced — run `zao wallet sync`)");
        }
    }

    Ok(())
}

// =============================================================================
// sync
// =============================================================================

pub fn cmd_sync(datadir_override: Option<&str>, batch_size: u32) -> Result<()> {
    let cfg = config::load_existing(datadir_override)?;
    let runtime = rt()?;
    runtime.block_on(crate::sync::run_sync(&cfg, batch_size))
}

// =============================================================================
// send
// =============================================================================

pub fn cmd_send(
    port: Option<&str>,
    datadir_override: Option<&str>,
    account: u32,
    to: &str,
    amount: u64,
    memo: Option<&str>,
) -> Result<()> {
    let cfg = config::load_existing(datadir_override)?;
    crate::send::run_send(&cfg, port, account, to, amount, memo)
}
