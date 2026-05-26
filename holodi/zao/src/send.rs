//! Pipeline-stage commands for the companion-wallet send flow.
//!
//! Each clap subcommand in `main.rs` (`propose`, `create-pczt`, `prove`,
//! `sign`, `extract`, `broadcast`, `inspect`) maps to a `cmd_*` handler in
//! this module. The pipeline operates on file artifacts so each stage can
//! be inspected, audited, or moved between machines (air-gapped flows):
//!
//!     wallet.sqlite ─► proposal.pb ─► unsigned.pczt ─► proved.pczt
//!                       (host)         (host)            (host)
//!     proved.pczt   ─► signed.pczt (combined) ─► tx.hex ─► txid
//!                       (device)                  (host)    (network)
//!
//! `cmd_send` keeps the original one-shot UX — it pipes the stages above
//! through `tempfile::NamedTempFile`s.

use std::{
    fs,
    io::Write,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use pczt::{
    roles::{combiner::Combiner, prover::Prover, signer::Signer, verifier::Verifier},
    Pczt,
};
use prost::Message;
use rand::rngs::OsRng;
use tokio::runtime::Runtime;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_pczt_from_proposal, extract_and_store_transaction_from_pczt,
            input_selection::GreedyInputSelector, propose_transfer, ConfirmationsPolicy,
        },
        Account as _, WalletRead,
    },
    fees::{standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule},
    proto::{proposal as proposal_proto, service},
    proposal::Proposal,
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{util::SystemClock, AccountUuid, WalletDb};
use zcash_primitives::transaction::Transaction;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::BranchId,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
    ShieldedProtocol,
};
use zip321::{Payment, TransactionRequest};

use crate::{
    config::Config,
    transport::{Transport, STATUS_ERR_NO_SEED, STATUS_ERR_REJECTED, STATUS_OK},
    OP_SIGN_PCZT,
};

const TARGET_NOTE_COUNT: usize = 4;
const MIN_SPLIT_OUTPUT_VALUE: u64 = 10_000_000;

// =============================================================================
// Default output paths
// =============================================================================

pub const DEFAULT_PROPOSAL_PATH: &str = "proposal.pb";
pub const DEFAULT_UNSIGNED_PCZT_PATH: &str = "unsigned.pczt";
pub const DEFAULT_PROVED_PCZT_PATH: &str = "proved.pczt";
pub const DEFAULT_SIGNED_PCZT_PATH: &str = "signed.pczt";
pub const DEFAULT_COMBINED_PCZT_PATH: &str = "combined.pczt";
#[allow(dead_code)]
pub const DEFAULT_TX_HEX_PATH: &str = "tx.hex";

// =============================================================================
// Helpers shared across stages
// =============================================================================

/// Open the companion-wallet DB and return the unique account id, after
/// confirming it carries a UFVK suitable for PCZT construction.
fn open_db_and_account(
    cfg: &Config,
) -> Result<(
    WalletDb<rusqlite::Connection, zcash_protocol::consensus::Network, SystemClock, OsRng>,
    AccountUuid,
)> {
    let params = cfg.network.as_consensus();
    let db = WalletDb::for_path(cfg.wallet_db_path(), params, SystemClock, OsRng)?;
    let account_ids = db
        .get_account_ids()
        .map_err(|e| anyhow!("get_account_ids: {:?}", e))?;
    let account_id = match account_ids.as_slice() {
        [] => bail!("Wallet contains no accounts. Run `zao wallet init` first."),
        [aid] => *aid,
        _ => bail!("Multiple accounts present; send only supports a single account."),
    };
    let account_meta = db
        .get_account(account_id)
        .map_err(|e| anyhow!("get_account: {:?}", e))?
        .ok_or_else(|| anyhow!("Account missing"))?;
    if account_meta.ufvk().is_none() {
        bail!("Account does not have a UFVK; cannot create a PCZT");
    }
    Ok((db, account_id))
}

fn read_pczt_file<P: AsRef<Path>>(path: P) -> Result<Pczt> {
    let path_ref = path.as_ref();
    let bytes = fs::read(path_ref)
        .with_context(|| format!("Reading PCZT file {}", path_ref.display()))?;
    Pczt::parse(&bytes).map_err(|e| {
        anyhow!(
            "Failed to parse PCZT at {}: {:?} ({} bytes)",
            path_ref.display(),
            e,
            bytes.len()
        )
    })
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::File::create(path)
        .with_context(|| format!("Creating output file {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("Writing to {}", path.display()))?;
    Ok(())
}

fn out_path(opt: Option<&str>, default: &str) -> PathBuf {
    PathBuf::from(opt.unwrap_or(default))
}

// =============================================================================
// Stage 1: propose
// =============================================================================

/// Build a payment proposal. Pure host operation against the wallet DB.
pub fn propose(
    cfg: &Config,
    db: &mut WalletDb<rusqlite::Connection, zcash_protocol::consensus::Network, SystemClock, OsRng>,
    account_id: AccountUuid,
    to: &str,
    amount: u64,
    memo: Option<&str>,
) -> Result<Proposal<StandardFeeRule, zcash_client_sqlite::ReceivedNoteId>> {
    let params = cfg.network.as_consensus();

    let payment = Payment::new(
        ZcashAddress::from_str(to).map_err(|_| anyhow!("Invalid Zcash address: {}", to))?,
        Some(Zatoshis::from_u64(amount).map_err(|_| anyhow!("Invalid amount {}", amount))?),
        memo.map(Memo::from_str)
            .transpose()
            .map_err(|e| anyhow!("Invalid memo: {}", e))?
            .map(MemoBytes::from),
        None,
        None,
        vec![],
    )
    .map_err(|e| anyhow!("Failed to build Payment: {:?}", e))?;
    let request = TransactionRequest::new(vec![payment])
        .map_err(|e| anyhow!("Invalid transaction request: {:?}", e))?;

    let change_strategy = MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedProtocol::Orchard,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(TARGET_NOTE_COUNT).expect("4 != 0"),
            Zatoshis::from_u64(MIN_SPLIT_OUTPUT_VALUE)?,
        ),
    );
    let input_selector = GreedyInputSelector::new();

    let proposal = propose_transfer::<_, _, _, _, zcash_client_sqlite::error::SqliteClientError>(
        db,
        &params,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::default(),
        None,
    )
    .map_err(|e| anyhow!("propose_transfer: {}", e))?;

    Ok(proposal)
}

/// Encode a proposal as the protobuf bytes used on disk.
pub fn serialize_proposal_pb<NoteRef>(proposal: &Proposal<StandardFeeRule, NoteRef>) -> Vec<u8> {
    proposal_proto::Proposal::from_standard_proposal(proposal).encode_to_vec()
}

/// Parse a proposal protobuf back into the in-memory representation, using
/// the wallet DB as an `InputSource` for note resolution.
pub fn parse_proposal_pb(
    bytes: &[u8],
    db: &WalletDb<rusqlite::Connection, zcash_protocol::consensus::Network, SystemClock, OsRng>,
) -> Result<Proposal<StandardFeeRule, zcash_client_sqlite::ReceivedNoteId>> {
    let proto = proposal_proto::Proposal::decode(bytes)
        .map_err(|e| anyhow!("Failed to decode proposal protobuf: {}", e))?;
    proto
        .try_into_standard_proposal::<_, zcash_client_sqlite::error::SqliteClientError>(db)
        .map_err(|e| anyhow!("Proposal does not validate against this wallet: {:?}", e))
}

pub fn cmd_propose(
    datadir: Option<&str>,
    _account: u32,
    to: &str,
    amount: u64,
    memo: Option<&str>,
    output: Option<&str>,
) -> Result<()> {
    let cfg = crate::config::load_existing(datadir)?;
    let (mut db, account_id) = open_db_and_account(&cfg)?;

    println!("Proposing transfer of {} zatoshi to {}...", amount, to);
    let proposal = propose(&cfg, &mut db, account_id, to, amount, memo)?;
    print_proposal_summary(&proposal);

    let bytes = serialize_proposal_pb(&proposal);
    let path = out_path(output, DEFAULT_PROPOSAL_PATH);
    write_bytes(&path, &bytes)?;
    println!("Wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

// =============================================================================
// Stage 2: create-pczt
// =============================================================================

/// Build an unsigned PCZT from the given proposal.
pub fn create_pczt(
    cfg: &Config,
    db: &mut WalletDb<rusqlite::Connection, zcash_protocol::consensus::Network, SystemClock, OsRng>,
    account_id: AccountUuid,
    proposal: &Proposal<StandardFeeRule, zcash_client_sqlite::ReceivedNoteId>,
) -> Result<Pczt> {
    let params = cfg.network.as_consensus();
    create_pczt_from_proposal::<
        _,
        _,
        zcash_client_sqlite::error::SqliteClientError,
        _,
        std::convert::Infallible,
        _,
    >(db, &params, account_id, OvkPolicy::Sender, proposal)
        .map_err(|e| anyhow!("create_pczt_from_proposal: {}", e))
}

pub fn cmd_create_pczt(
    datadir: Option<&str>,
    _account: u32,
    proposal_path: &str,
    output: Option<&str>,
) -> Result<()> {
    let cfg = crate::config::load_existing(datadir)?;
    let (mut db, account_id) = open_db_and_account(&cfg)?;

    let proposal_bytes = fs::read(proposal_path)
        .with_context(|| format!("Reading proposal file {}", proposal_path))?;
    println!(
        "Loaded proposal protobuf from {} ({} bytes)",
        proposal_path,
        proposal_bytes.len()
    );

    let proposal = parse_proposal_pb(&proposal_bytes, &db)?;
    print_proposal_summary(&proposal);

    println!("Creating PCZT from proposal...");
    let pczt = create_pczt(&cfg, &mut db, account_id, &proposal)?;
    let bytes = pczt.serialize();

    let path = out_path(output, DEFAULT_UNSIGNED_PCZT_PATH);
    write_bytes(&path, &bytes)?;
    println!("Wrote {} ({} bytes, unsigned, no proof)", path.display(), bytes.len());
    Ok(())
}

// =============================================================================
// Stage 3: prove
// =============================================================================

/// Add the Orchard zero-knowledge proof to a PCZT. Pure host operation;
/// requires no secrets and no wallet.
pub fn prove(unsigned: Pczt) -> Result<Pczt> {
    Ok(Prover::new(unsigned)
        .create_orchard_proof(&orchard::circuit::ProvingKey::build())
        .map_err(|e| anyhow!("create_orchard_proof: {:?}", e))?
        .finish())
}

/// Compute the shielded sighash that will be used by the device signer.
pub fn shielded_sighash(pczt: &Pczt) -> Result<[u8; 32]> {
    Ok(Signer::new(pczt.clone())
        .map_err(|e| anyhow!("Signer::new: {:?}", e))?
        .shielded_sighash())
}

pub fn cmd_prove(pczt_path: &str, output: Option<&str>) -> Result<()> {
    let unsigned = read_pczt_file(pczt_path)?;
    println!("Generating Orchard proof on host (no secrets required)...");
    let proved = prove(unsigned)?;
    let sighash = shielded_sighash(&proved)?;
    let bytes = proved.serialize();
    let path = out_path(output, DEFAULT_PROVED_PCZT_PATH);
    write_bytes(&path, &bytes)?;
    println!(
        "Wrote {} ({} bytes); shielded sighash: {}",
        path.display(),
        bytes.len(),
        hex::encode(sighash)
    );
    Ok(())
}

// =============================================================================
// Stage 4: sign (device round-trip + Combiner)
// =============================================================================

/// Send the **unsigned** PCZT to the device for signing. Returns the
/// device's signed (and redacted) PCZT — not yet combined with the
/// proofs. To produce a fully signed-and-proven PCZT for extract,
/// pipe through `combine(proved, signed)`.
///
/// This matches zcash-devtool's `pczt sign` exactly:
///
///   pczt -w wallet sign --identity keys.age < pczt.created > pczt.signed
///   pczt combine -i pczt.proven -i pczt.signed > pczt.combined
///   pczt -w view-wallet send -s zecrocks      < pczt.combined
///
/// Sign takes only the unsigned input. Proving and signing are
/// parallel branches over that same input; neither depends on the
/// other's output. The host then merges them with Combiner.
/// Send the unsigned PCZT to the device for signing. The device returns
/// raw signature material — `[n_actions: u8][(has_sig: u8, sig: [u8; 64]) * n]`
/// (Path 2b wire format) — and the host applies the signatures to the
/// unsigned PCZT locally via the vendored `set_spend_auth_sig` setter.
///
/// We do NOT have the device serialize a PCZT response. The
/// on-device `Pczt::serialize` path produces deterministic 512-byte-
/// stride corruption on RV32 (allocator-independent — confirmed by
/// running on linked_list_allocator with a panic probe and observing
/// the same corruption pattern as dlmalloc-rs). See
/// `zcashapp_multi_recv_corruption.md`.
pub fn sign(port: Option<&str>, account: u32, mut unsigned: Pczt) -> Result<Pczt> {
    let sighash = shielded_sighash(&unsigned)?;
    let unsigned_bytes = unsigned.serialize();
    println!(
        "Sending unsigned PCZT to device for signing ({} bytes, sighash {})...",
        unsigned_bytes.len(),
        hex::encode(sighash)
    );
    let resp = device_sign_pczt(port, account, &sighash, &unsigned_bytes)?;

    // Wire response (after STATUS_OK was stripped by `device_sign_pczt`):
    //   [n_actions: u8] [(has_sig: u8, sig: [u8; 64]) * n_actions]
    // Total = 1 + 65 * n_actions bytes.
    if resp.is_empty() {
        bail!("Empty sign response from device");
    }
    let n = resp[0] as usize;
    let expected_len = 1 + 65 * n;
    if resp.len() != expected_len {
        bail!(
            "Malformed sign response: got {} bytes, expected {} ({} actions, 1 + 65 each)",
            resp.len(),
            expected_len,
            n,
        );
    }
    let unsigned_actions = unsigned.orchard().actions().len();
    if unsigned_actions != n {
        bail!(
            "Action count mismatch: unsigned PCZT has {} actions, device returned sigs for {}",
            unsigned_actions,
            n,
        );
    }

    let mut signed_count = 0usize;
    for idx in 0..n {
        let base = 1 + idx * 65;
        let has_sig = resp[base];
        if has_sig != 0 {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&resp[base + 1..base + 65]);
            unsigned.orchard_mut().set_spend_auth_sig(idx, sig);
            signed_count += 1;
        }
    }
    if signed_count == 0 {
        bail!("Device returned no signatures (none of the actions matched the device's spending key)");
    }
    println!(
        "Device returned {} signature(s) ({} bytes wire). Applied locally.",
        signed_count,
        resp.len()
    );
    // The "unsigned" PCZT now has spend_auth_sig set on the signed actions.
    // Downstream Combiner merges this with the proved PCZT.
    Ok(unsigned)
}

/// Combine a proved PCZT (host) with a signed PCZT (device output) to
/// produce a fully-signed-and-proven PCZT ready for extract+broadcast.
/// Mirrors zcash-devtool's `pczt combine`.
pub fn combine(proved: Pczt, signed: Pczt) -> Result<Pczt> {
    Combiner::new(vec![proved, signed])
        .combine()
        .map_err(|e| anyhow!("Combiner::combine: {:?}", e))
}

pub fn cmd_sign(
    port: Option<&str>,
    account: u32,
    unsigned_path: &str,
    output: Option<&str>,
) -> Result<()> {
    let unsigned = read_pczt_file(unsigned_path)?;
    let signed = sign(port, account, unsigned)?;
    let bytes = signed.serialize();
    let path = out_path(output, DEFAULT_SIGNED_PCZT_PATH);
    write_bytes(&path, &bytes)?;
    println!("Wrote {} ({} bytes, signed only — combine with proved before extract)", path.display(), bytes.len());
    Ok(())
}

pub fn cmd_combine(
    proved_path: &str,
    signed_path: &str,
    output: Option<&str>,
) -> Result<()> {
    let proved = read_pczt_file(proved_path)?;
    let signed = read_pczt_file(signed_path)?;
    let combined = combine(proved, signed)?;
    let bytes = combined.serialize();
    let path = out_path(output, DEFAULT_COMBINED_PCZT_PATH);
    write_bytes(&path, &bytes)?;
    println!("Wrote {} ({} bytes, proved + signed)", path.display(), bytes.len());
    Ok(())
}

fn device_sign_pczt(
    port: Option<&str>,
    account: u32,
    sighash: &[u8; 32],
    pczt_bytes: &[u8],
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(4 + 32 + pczt_bytes.len());
    payload.extend_from_slice(&account.to_le_bytes());
    payload.extend_from_slice(sighash);
    payload.extend_from_slice(pczt_bytes);

    let mut t = Transport::open(port)?;
    let (status, resp) = t.command(OP_SIGN_PCZT, &payload)?;
    match status {
        STATUS_OK => Ok(resp),
        STATUS_ERR_REJECTED => bail!("Signing rejected by user on device"),
        STATUS_ERR_NO_SEED => bail!("Device has no seed loaded"),
        other => bail!(
            "Device error: {} (0x{:02x})",
            crate::transport::status_message(other),
            other
        ),
    }
}

// =============================================================================
// Stage 5: extract (combined PCZT → raw tx, store in wallet DB)
// =============================================================================

/// Run the PCZT transaction extractor against the wallet DB. Returns the
/// raw consensus-encoded transaction bytes; the wallet DB is also updated
/// to record the transaction.
pub fn extract(
    db: &mut WalletDb<rusqlite::Connection, zcash_protocol::consensus::Network, SystemClock, OsRng>,
    combined: Pczt,
) -> Result<Vec<u8>> {
    let prover = LocalTxProver::bundled();
    let (spend_vk, output_vk) = prover.verifying_keys();

    let txid = extract_and_store_transaction_from_pczt::<_, ()>(
        db,
        combined,
        Some((&spend_vk, &output_vk)),
        Some(&orchard::circuit::VerifyingKey::build()),
    )
    .map_err(|e| anyhow!("extract_and_store_transaction_from_pczt: {:?}", e))?;

    let tx = db
        .get_transaction(txid)
        .map_err(|e| anyhow!("get_transaction: {:?}", e))?
        .ok_or_else(|| anyhow!("Stored transaction not found"))?;
    let mut buf = Vec::new();
    tx.write(&mut buf).context("transaction serialization")?;
    Ok(buf)
}

// (Removed `cmd_extract` and `cmd_broadcast` standalone wrappers in the
// CLI reorg — `pczt send` now extracts + broadcasts in one call,
// matching zcash-devtool's surface. The lower-level `extract()` and
// `broadcast_async()` functions are kept for use by `cmd_pczt_send`.)

fn read_hex_tx_file(path: &str) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Reading tx hex file {}", path))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("Tx hex file {} is empty", path);
    }
    hex::decode(trimmed.trim_start_matches("0x"))
        .with_context(|| format!("Decoding hex from {}", path))
}

pub async fn broadcast_async(server: &str, raw_tx: &[u8]) -> Result<String> {
    let mut client = crate::commands::lwd_connect(server).await?;
    let mut req = service::RawTransaction::default();
    req.data.extend_from_slice(raw_tx);
    let response = client
        .send_transaction(req)
        .await
        .context("send_transaction")?
        .into_inner();
    if response.error_code != 0 {
        bail!(
            "Broadcast failed (code {}): {}",
            response.error_code,
            response.error_message
        );
    }
    // The raw bundle of the returned transaction is the txid (32 bytes, BE on the wire).
    // For a friendly form, re-derive the txid from the parsed tx (V5 carries its own
    // branch id; V4 uses Nu5 as a reasonable fallback for display).
    let mut cursor = std::io::Cursor::new(raw_tx);
    let txid = match Transaction::read(&mut cursor, BranchId::Nu5) {
        Ok(tx) => tx.txid().to_string(),
        Err(_) => "<unparseable>".to_string(),
    };
    Ok(txid)
}

/// `pczt send` — extract+broadcast a combined PCZT in one call.
/// Mirrors zcash-devtool's `pczt send` exactly: takes a combined
/// (proved + signed) PCZT, calls `extract_and_store_transaction_from_pczt`
/// (stores in wallet DB), then broadcasts via lightwalletd. Returns
/// the txid on success.
pub fn cmd_pczt_send(datadir: Option<&str>, combined_path: &str) -> Result<()> {
    let cfg = crate::config::load_existing(datadir)?;
    let (mut db, _account_id) = open_db_and_account(&cfg)?;
    let combined = read_pczt_file(combined_path)?;

    println!("Extracting and storing transaction from combined PCZT...");
    let raw_tx = extract(&mut db, combined)?;
    println!("      raw tx: {} bytes", raw_tx.len());

    println!("Broadcasting to {}...", cfg.server);
    let runtime = Runtime::new().context("Tokio runtime")?;
    let txid = runtime.block_on(broadcast_async(&cfg.server, &raw_tx))?;
    println!("      txid: {}", txid);
    println!("Broadcast successful");
    Ok(())
}

/// `pczt redact` — apply the firmware's redactor closure to a PCZT (host-side),
/// stripping optional fields. Mirrors zcash-devtool's `pczt redact`.
/// Useful for development / inspection: see what the device-bound payload
/// looks like before sending, or strip a proved PCZT down to its skeleton.
pub fn cmd_pczt_redact(input_path: &str, output: Option<&str>) -> Result<()> {
    use pczt::roles::redactor::Redactor;
    let pczt = read_pczt_file(input_path)?;
    let redacted = Redactor::new(pczt)
        .redact_global_with(|mut g| { g.clear_proprietary(); })
        .redact_orchard_with(|mut r| {
            r.redact_actions(|mut ar| {
                ar.clear_spend_recipient();
                ar.clear_spend_value();
                ar.clear_spend_rho();
                ar.clear_spend_rseed();
                ar.clear_spend_fvk();
                ar.clear_spend_witness();
                ar.clear_spend_alpha();
                ar.clear_spend_zip32_derivation();
                ar.clear_spend_dummy_sk();
                ar.clear_output_recipient();
                ar.clear_output_value();
                ar.clear_output_rseed();
                ar.clear_output_ock();
                ar.clear_output_zip32_derivation();
                ar.clear_output_user_address();
                ar.clear_spend_proprietary();
                ar.clear_output_proprietary();
                ar.clear_rcv();
            });
            r.clear_zkproof();
            r.clear_bsk();
        })
        .finish();
    let bytes = redacted.serialize();
    let path = out_path(output, "redacted.pczt");
    write_bytes(&path, &bytes)?;
    println!("Wrote {} ({} bytes, redacted)", path.display(), bytes.len());
    Ok(())
}

#[allow(dead_code)]
pub fn cmd_broadcast(datadir: Option<&str>, tx_path: &str) -> Result<()> {
    let cfg = crate::config::load_existing(datadir)?;
    let raw_tx = read_hex_tx_file(tx_path)?;
    println!(
        "Broadcasting {} bytes to {}...",
        raw_tx.len(),
        cfg.server
    );
    let runtime = Runtime::new().context("Tokio runtime")?;
    let txid = runtime.block_on(broadcast_async(&cfg.server, &raw_tx))?;
    println!("Broadcast successful: txid {}", txid);
    Ok(())
}

// =============================================================================
// inspect (proposal | pczt | tx)
// =============================================================================

pub fn cmd_inspect_proposal(path: &str) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("Reading proposal {}", path))?;
    let proto = proposal_proto::Proposal::decode(bytes.as_slice())
        .map_err(|e| anyhow!("Failed to decode proposal protobuf: {}", e))?;
    println!("Proposal protobuf ({} bytes from {})", bytes.len(), path);
    println!("  proto_version: {}", proto.proto_version);
    println!("  fee_rule: {:?}", proto.fee_rule());
    println!("  min_target_height: {}", proto.min_target_height);
    println!("  steps: {}", proto.steps.len());
    for (i, step) in proto.steps.iter().enumerate() {
        println!("  step {}:", i);
        println!("    transaction_request: {}", step.transaction_request);
        println!("    anchor_height: {}", step.anchor_height);
        println!("    inputs: {}", step.inputs.len());
        for (j, inp) in step.inputs.iter().enumerate() {
            match &inp.value {
                Some(proposal_proto::proposed_input::Value::ReceivedOutput(r)) => println!(
                    "      [{}] received: {} zatoshi (pool {:?}) txid {} idx {}",
                    j,
                    r.value,
                    r.value_pool(),
                    hex::encode(&r.txid),
                    r.index
                ),
                Some(proposal_proto::proposed_input::Value::PriorStepOutput(p)) => println!(
                    "      [{}] prior step output: step {} payment {}",
                    j, p.step_index, p.payment_index
                ),
                Some(proposal_proto::proposed_input::Value::PriorStepChange(p)) => println!(
                    "      [{}] prior step change: step {} change {}",
                    j, p.step_index, p.change_index
                ),
                None => println!("      [{}] (empty input)", j),
            }
        }
        println!("    payment_output_pools: {}", step.payment_output_pools.len());
        for pop in &step.payment_output_pools {
            println!(
                "      - payment {} → pool {:?}",
                pop.payment_index,
                pop.value_pool()
            );
        }
        if let Some(balance) = &step.balance {
            println!("    fee_required: {} zatoshi", balance.fee_required);
            println!("    proposed_change: {}", balance.proposed_change.len());
            for (k, c) in balance.proposed_change.iter().enumerate() {
                println!(
                    "      [{}] {} zatoshi to pool {:?}{}{}",
                    k,
                    c.value,
                    c.value_pool(),
                    if c.is_ephemeral { " (ephemeral)" } else { "" },
                    match &c.memo {
                        Some(m) if !m.value.is_empty() => format!(" memo {} bytes", m.value.len()),
                        _ => "".into(),
                    }
                );
            }
        } else {
            println!("    balance: <missing>");
        }
        println!("    is_shielding: {}", step.is_shielding);
    }
    Ok(())
}

pub fn cmd_inspect_pczt(path: &str) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("Reading PCZT {}", path))?;
    let pczt = Pczt::parse(&bytes).map_err(|e| anyhow!("Failed to parse PCZT: {:?}", e))?;
    println!("PCZT ({} bytes from {})", bytes.len(), path);
    print_pczt_inspection(&pczt);
    Ok(())
}

pub fn cmd_inspect_tx(path: &str) -> Result<()> {
    let raw = read_hex_tx_file(path)?;
    println!("Transaction ({} raw bytes from {})", raw.len(), path);
    let mut cursor = std::io::Cursor::new(&raw[..]);
    match Transaction::read(&mut cursor, BranchId::Nu5) {
        Ok(tx) => {
            println!("  TxID: {}", tx.txid());
            println!("  Version: {:?}", tx.version());
            println!("  Lock time: {}", tx.lock_time());
            println!("  Expiry height: {}", u32::from(tx.expiry_height()));
            if let Some(b) = tx.transparent_bundle() {
                println!(
                    "  Transparent: {} inputs, {} outputs",
                    b.vin.len(),
                    b.vout.len()
                );
            }
            if let Some(b) = tx.sapling_bundle() {
                println!(
                    "  Sapling: {} spends, {} outputs",
                    b.shielded_spends().len(),
                    b.shielded_outputs().len()
                );
            }
            if let Some(b) = tx.orchard_bundle() {
                println!("  Orchard: {} actions", b.actions().len());
            }
        }
        Err(e) => {
            println!("  (failed to parse as Zcash transaction: {})", e);
            println!("  hex: {}", hex::encode(&raw));
        }
    }
    Ok(())
}

fn print_proposal_summary<NoteRef>(p: &Proposal<StandardFeeRule, NoteRef>) {
    println!(
        "Proposal: fee_rule={:?}, min_target_height={}, steps={}",
        p.fee_rule(),
        u32::from(p.min_target_height()),
        p.steps().len()
    );
    for (i, step) in p.steps().iter().enumerate() {
        println!(
            "  step {}: t_inputs={} shielded_inputs={} prior_step_inputs={} change_outputs={} fee={}",
            i,
            step.transparent_inputs().len(),
            step.shielded_inputs().map(|s| s.notes().len()).unwrap_or(0),
            step.prior_step_inputs().len(),
            step.balance().proposed_change().len(),
            u64::from(step.balance().fee_required()),
        );
    }
}

fn print_pczt_inspection(pczt: &Pczt) {
    let mut transparent_inputs = 0usize;
    let mut transparent_outputs = 0usize;
    let mut sapling_spends = 0usize;
    let mut sapling_outputs = 0usize;
    let mut orchard_actions: Vec<(Option<u64>, Option<u64>)> = vec![];

    let _ = Verifier::new(pczt.clone())
        .with_transparent::<(), _>(|bundle| {
            transparent_inputs = bundle.inputs().len();
            transparent_outputs = bundle.outputs().len();
            Ok(())
        })
        .map_err(|e| println!("  (transparent verifier error: {:?})", e))
        .and_then(|v| {
            v.with_sapling::<(), _>(|bundle| {
                sapling_spends = bundle.spends().len();
                sapling_outputs = bundle.outputs().len();
                Ok(())
            })
            .map_err(|e| println!("  (sapling verifier error: {:?})", e))
        })
        .and_then(|v| {
            v.with_orchard::<(), _>(|bundle| {
                orchard_actions = bundle
                    .actions()
                    .iter()
                    .map(|a| (a.spend().value().map(|v| v.inner()), a.output().value().map(|v| v.inner())))
                    .collect();
                Ok(())
            })
            .map_err(|e| println!("  (orchard verifier error: {:?})", e))
        });

    println!(
        "  Transparent: {} inputs, {} outputs",
        transparent_inputs, transparent_outputs
    );
    println!(
        "  Sapling: {} spends, {} outputs",
        sapling_spends, sapling_outputs
    );
    println!("  Orchard: {} actions", orchard_actions.len());
    for (i, (spend, output)) in orchard_actions.iter().enumerate() {
        println!(
            "    [{}] spend={} output={}",
            i,
            spend
                .map(|v| if v == 0 { "0 (dummy)".to_string() } else { format!("{} zatoshi", v) })
                .unwrap_or_else(|| "<encrypted>".to_string()),
            output
                .map(|v| if v == 0 { "0 (dummy)".to_string() } else { format!("{} zatoshi", v) })
                .unwrap_or_else(|| "<encrypted>".to_string()),
        );
    }

    // sighash + txid (best effort — may not be available pre-prove)
    match Signer::new(pczt.clone()) {
        Ok(s) => println!("  Shielded sighash: {}", hex::encode(s.shielded_sighash())),
        Err(e) => println!("  (no sighash available: {:?})", e),
    }
    match pczt.clone().into_effects() {
        Ok(tx_data) => {
            use zcash_primitives::transaction::txid::{to_txid, TxIdDigester};
            let parts = tx_data.digest(TxIdDigester);
            let txid = to_txid(tx_data.version(), tx_data.consensus_branch_id(), &parts);
            println!("  Effects TxID: {}", txid);
            println!("  Effects version: {:?}", tx_data.version());
        }
        Err(e) => println!("  (cannot derive effects: {:?})", e),
    }
}

// =============================================================================
// `send`: convenience wrapper that pipes the stages above through tempfiles.
// =============================================================================

/// Run the full pipeline. Mirrors the previous one-shot behavior but
/// goes through the stage functions individually so behavior tracks
/// the granular subcommands.
pub fn run_send(
    cfg: &Config,
    port: Option<&str>,
    account: u32,
    to: &str,
    amount: u64,
    memo: Option<&str>,
) -> Result<()> {
    use tempfile::NamedTempFile;

    let (mut db, account_id) = open_db_and_account(cfg)?;

    println!("[1/7] Propose: transferring {} zatoshi to {}", amount, to);
    let proposal = propose(cfg, &mut db, account_id, to, amount, memo)?;
    print_proposal_summary(&proposal);

    let proposal_bytes = serialize_proposal_pb(&proposal);
    let proposal_tmp = NamedTempFile::new().context("temp file (proposal)")?;
    write_bytes(proposal_tmp.path(), &proposal_bytes)?;

    // Round-trip through the on-disk format so the convenience wrapper
    // exercises the same code path as the standalone subcommands.
    let proposal = parse_proposal_pb(&fs::read(proposal_tmp.path())?, &db)?;

    println!("[2/7] Create PCZT: building unsigned PCZT from proposal");
    let unsigned = create_pczt(cfg, &mut db, account_id, &proposal)?;
    let unsigned_tmp = NamedTempFile::new().context("temp file (unsigned)")?;
    write_bytes(unsigned_tmp.path(), &unsigned.serialize())?;
    println!("      unsigned: {} bytes", unsigned.serialize().len());

    println!("[3/7] Prove: generating Orchard proof on host (no secrets needed)");
    let proved = prove(read_pczt_file(unsigned_tmp.path())?)?;
    let proved_tmp = NamedTempFile::new().context("temp file (proved)")?;
    write_bytes(proved_tmp.path(), &proved.serialize())?;
    let sighash = shielded_sighash(&proved)?;
    println!(
        "      proved: {} bytes; sighash: {}",
        proved.serialize().len(),
        hex::encode(sighash)
    );

    println!("[4/7] Sign: forwarding unsigned PCZT to device");
    let signed = sign(port, account, read_pczt_file(unsigned_tmp.path())?)?;
    let signed_tmp = NamedTempFile::new().context("temp file (signed)")?;
    write_bytes(signed_tmp.path(), &signed.serialize())?;
    println!("      signed: {} bytes (signed only)", signed.serialize().len());

    println!("[5/7] Combine: merging proved + signed");
    let combined = combine(
        read_pczt_file(proved_tmp.path())?,
        read_pczt_file(signed_tmp.path())?,
    )?;
    let combined_tmp = NamedTempFile::new().context("temp file (combined)")?;
    write_bytes(combined_tmp.path(), &combined.serialize())?;
    println!("      combined: {} bytes (proved + signed)", combined.serialize().len());

    println!("[6/7] Extract: pulling raw transaction from combined PCZT");
    let raw_tx = extract(&mut db, read_pczt_file(combined_tmp.path())?)?;
    println!("      raw tx: {} bytes", raw_tx.len());

    println!("[7/7] Broadcast: sending to {}", cfg.server);
    let runtime = Runtime::new().context("Tokio runtime")?;
    let txid = runtime.block_on(broadcast_async(&cfg.server, &raw_tx))?;
    println!("      txid: {}", txid);
    println!("Broadcast successful");
    Ok(())
}

// =============================================================================
// Tests (pure host stages only)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_path_uses_default_when_none() {
        let p = out_path(None, "default.bin");
        assert_eq!(p, PathBuf::from("default.bin"));
    }

    #[test]
    fn out_path_honours_override() {
        let p = out_path(Some("/tmp/custom.bin"), "default.bin");
        assert_eq!(p, PathBuf::from("/tmp/custom.bin"));
    }

    #[test]
    fn read_hex_tx_strips_whitespace_and_prefix() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "0xdeadbeef\n").unwrap();
        let bytes = read_hex_tx_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn read_hex_tx_rejects_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "   \n\t").unwrap();
        let err = read_hex_tx_file(tmp.path().to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn read_hex_tx_rejects_non_hex() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "not hex at all").unwrap();
        assert!(read_hex_tx_file(tmp.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn write_bytes_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("out.bin");
        write_bytes(&path, b"\x01\x02\x03").unwrap();
        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, b"\x01\x02\x03");
    }

    #[test]
    fn proposal_proto_round_trip_preserves_fee_rule_field() {
        // Pure protobuf round-trip — we don't need a real proposal to exercise
        // the encode/decode path of our protobuf helper.
        let mut original = proposal_proto::Proposal::default();
        original.proto_version = 1;
        original.set_fee_rule(proposal_proto::FeeRule::Zip317);
        original.min_target_height = 1234567;
        let bytes = original.encode_to_vec();
        let decoded =
            proposal_proto::Proposal::decode(bytes.as_slice()).expect("decode round-trip");
        assert_eq!(decoded.proto_version, 1);
        assert_eq!(decoded.fee_rule(), proposal_proto::FeeRule::Zip317);
        assert_eq!(decoded.min_target_height, 1234567);
    }

    #[test]
    fn pczt_parse_rejects_short_input() {
        // Sanity that our error path on read_pczt_file is reachable.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"PCZT").unwrap(); // too short, missing version
        let err = read_pczt_file(tmp.path()).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("pczt"));
    }
}
