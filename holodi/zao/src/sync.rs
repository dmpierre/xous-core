//! lightwalletd block-scan loop. Modelled on zcash-devtool's sync command,
//! stripped of transparent UTXO handling and Tor/SOCKS — our Orchard-only
//! UFVK never needs them.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use futures_util::TryStreamExt;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use rand::rngs::OsRng;
use tokio::{fs::File, io::AsyncWriteExt};
use tonic::transport::Channel;
use tracing::info;

use zcash_client_backend::{
    data_api::{
        chain::{
            error::Error as ChainError, scan_cached_blocks, BlockSource, ChainState,
            CommitmentTreeRoot,
        },
        scanning::{ScanPriority, ScanRange},
        wallet::ConfirmationsPolicy,
        WalletCommitmentTrees, WalletRead, WalletWrite,
    },
    proto::compact_formats::CompactBlock,
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient, BlockId},
};
use zcash_client_sqlite::{
    chain::BlockMeta, util::SystemClock, FsBlockDb, FsBlockDbError, WalletDb,
};
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::{BlockHeight, Network};

use crate::config::Config;

const BLOCKS_FOLDER: &str = "blocks";

pub async fn run_sync(cfg: &Config, batch_size: u32) -> Result<()> {
    let params = cfg.network.as_consensus();
    // FsBlockDb keeps `blockmeta.sqlite` at the root and writes block files into a
    // `blocks/` subdir; we use `cfg.datadir` as that root.
    let fsblockdb_root = cfg.datadir.clone();
    std::fs::create_dir_all(fsblockdb_root.join(BLOCKS_FOLDER))
        .with_context(|| format!("Creating {}", fsblockdb_root.display()))?;

    let mut db_cache = FsBlockDb::for_path(&fsblockdb_root)
        .map_err(|e| anyhow!("Opening block cache: {:?}", e))?;
    let mut db_data = WalletDb::for_path(cfg.wallet_db_path(), params, SystemClock, OsRng)?;

    let mut client = crate::commands::lwd_connect(&cfg.server).await?;

    update_subtree_roots(&mut client, &mut db_data).await?;

    while running(&mut client, &params, &fsblockdb_root, &mut db_cache, &mut db_data, batch_size)
        .await?
    {}

    Ok(())
}

async fn running(
    client: &mut CompactTxStreamerClient<Channel>,
    params: &Network,
    fsblockdb_root: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
    batch_size: u32,
) -> Result<bool> {
    let _chain_tip = update_chain_tip(client, db_data).await?;

    info!("Fetching scan ranges");
    let mut scan_ranges = db_data
        .suggest_scan_ranges()
        .map_err(|e| anyhow!("suggest_scan_ranges: {:?}", e))?;
    info!("Fetched {} scan ranges", scan_ranges.len());

    // Verification pass.
    loop {
        match scan_ranges.first() {
            Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
                let block_meta = download_blocks(client, fsblockdb_root, db_cache, scan_range).await?;
                let chain_state =
                    download_chain_state(client, scan_range.block_range().start - 1).await?;

                let scan_ranges_updated =
                    scan_blocks(params, fsblockdb_root, db_cache, db_data, &chain_state, scan_range)?;

                delete_cached_blocks(fsblockdb_root, block_meta).await;

                if scan_ranges_updated {
                    scan_ranges = db_data
                        .suggest_scan_ranges()
                        .map_err(|e| anyhow!("suggest_scan_ranges: {:?}", e))?;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    // Main scan over remaining ranges.
    let scan_ranges = db_data
        .suggest_scan_ranges()
        .map_err(|e| anyhow!("suggest_scan_ranges: {:?}", e))?;
    for scan_range in scan_ranges.into_iter().flat_map(|r| {
        // Limit how many blocks we download/scan at once.
        (0..).scan(r, move |acc, _| {
            if acc.is_empty() {
                None
            } else if let Some((cur, next)) = acc.split_at(acc.block_range().start + batch_size) {
                *acc = next;
                Some(cur)
            } else {
                let cur = acc.clone();
                let end = acc.block_range().end;
                *acc = ScanRange::from_parts(end..end, acc.priority());
                Some(cur)
            }
        })
    }) {
        let block_meta = download_blocks(client, fsblockdb_root, db_cache, &scan_range).await?;
        let chain_state =
            download_chain_state(client, scan_range.block_range().start - 1).await?;

        let scan_ranges_updated =
            scan_blocks(params, fsblockdb_root, db_cache, db_data, &chain_state, &scan_range)?;

        delete_cached_blocks(fsblockdb_root, block_meta).await;

        if scan_ranges_updated {
            return Ok(true);
        }
    }

    if let Some(summary) = db_data
        .get_wallet_summary(ConfirmationsPolicy::default())
        .map_err(|e| anyhow!("get_wallet_summary: {:?}", e))?
    {
        info!(
            "Sync complete; chain tip {}",
            summary.chain_tip_height(),
        );
    }
    Ok(false)
}

async fn update_subtree_roots(
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
) -> Result<()> {
    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Sapling);
    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = sapling::Node::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await?;
    info!("Sapling tree has {} subtrees", sapling_roots.len());
    db_data
        .put_sapling_subtree_roots(0, &sapling_roots)
        .map_err(|e| anyhow!("put_sapling_subtree_roots: {:?}", e))?;

    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Orchard);
    let orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>> = client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = MerkleHashOrchard::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await?;
    info!("Orchard tree has {} subtrees", orchard_roots.len());
    db_data
        .put_orchard_subtree_roots(0, &orchard_roots)
        .map_err(|e| anyhow!("put_orchard_subtree_roots: {:?}", e))?;

    Ok(())
}

async fn update_chain_tip(
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
) -> Result<BlockHeight> {
    let tip_height: BlockHeight = client
        .get_latest_block(service::ChainSpec::default())
        .await?
        .get_ref()
        .height
        .try_into()
        .map_err(|_| anyhow!("Invalid chain tip height"))?;

    info!("Latest block height is {}", tip_height);
    db_data
        .update_chain_tip(tip_height)
        .map_err(|e| anyhow!("update_chain_tip: {:?}", e))?;

    Ok(tip_height)
}

fn block_path(fsblockdb_root: &Path, meta: &BlockMeta) -> std::path::PathBuf {
    meta.block_file_path(&fsblockdb_root.join(BLOCKS_FOLDER))
}

async fn download_blocks(
    client: &mut CompactTxStreamerClient<Channel>,
    fsblockdb_root: &Path,
    db_cache: &FsBlockDb,
    scan_range: &ScanRange,
) -> Result<Vec<BlockMeta>> {
    info!("Fetching {}", scan_range);
    let mut start = service::BlockId::default();
    start.height = scan_range.block_range().start.into();
    let mut end = service::BlockId::default();
    end.height = (scan_range.block_range().end - 1).into();
    let range = service::BlockRange {
        start: Some(start),
        end: Some(end),
        pool_types: Default::default(),
    };
    let block_meta_stream = client
        .get_block_range(range)
        .await
        .map_err(anyhow::Error::from)?
        .into_inner()
        .and_then(|block| async move {
            let (sapling_outputs_count, orchard_actions_count) = block
                .vtx
                .iter()
                .map(|tx| (tx.outputs.len() as u32, tx.actions.len() as u32))
                .fold((0, 0), |(sap, orch), (s, o)| (sap + s, orch + o));

            let meta = BlockMeta {
                height: block.height(),
                block_hash: block.hash(),
                block_time: block.time,
                sapling_outputs_count,
                orchard_actions_count,
            };

            let encoded = block.encode_to_vec();
            let mut block_file = File::create(block_path(fsblockdb_root, &meta)).await?;
            block_file.write_all(&encoded).await?;

            Ok(meta)
        });
    tokio::pin!(block_meta_stream);

    let mut block_meta = vec![];
    while let Some(block) = block_meta_stream.try_next().await? {
        block_meta.push(block);
    }

    db_cache
        .write_block_metadata(&block_meta)
        .map_err(|e| anyhow!("write_block_metadata: {:?}", e))?;

    Ok(block_meta)
}

async fn download_chain_state(
    client: &mut CompactTxStreamerClient<Channel>,
    block_height: BlockHeight,
) -> Result<ChainState> {
    let tree_state = client
        .get_tree_state(BlockId {
            height: block_height.into(),
            hash: vec![],
        })
        .await?;

    Ok(tree_state
        .into_inner()
        .to_chain_state()
        .map_err(|e| anyhow!("to_chain_state: {}", e))?)
}

async fn delete_cached_blocks(fsblockdb_root: &Path, block_meta: Vec<BlockMeta>) {
    for meta in block_meta {
        if let Err(e) = tokio::fs::remove_file(block_path(fsblockdb_root, &meta)).await {
            tracing::warn!("Failed to remove cached block {:?}: {}", meta, e);
        }
    }
}

fn scan_blocks(
    params: &Network,
    fsblockdb_root: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WalletDb<rusqlite::Connection, Network, SystemClock, OsRng>,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
) -> Result<bool> {
    info!("Scanning {}", scan_range);
    let scan_result = scan_cached_blocks(
        params,
        db_cache,
        db_data,
        scan_range.block_range().start,
        initial_chain_state,
        scan_range.len(),
    );

    match scan_result {
        Err(ChainError::Scan(err)) if err.is_continuity_error() => {
            let rewind_height = err.at_height().saturating_sub(10);
            info!(
                "Chain reorg detected at {}, rewinding to {}",
                err.at_height(),
                rewind_height,
            );
            db_data
                .truncate_to_height(rewind_height)
                .map_err(|e| anyhow!("truncate_to_height: {:?}", e))?;
            db_cache
                .with_blocks(Some(rewind_height + 1), None, |block: CompactBlock| {
                    let meta = BlockMeta {
                        height: block.height(),
                        block_hash: block.hash(),
                        block_time: block.time,
                        sapling_outputs_count: 0,
                        orchard_actions_count: 0,
                    };
                    std::fs::remove_file(block_path(fsblockdb_root, &meta))
                        .map_err(|e| ChainError::<(), _>::BlockSource(FsBlockDbError::Fs(e)))
                })
                .map_err(|e| anyhow!("with_blocks: {:?}", e))?;
            db_cache
                .truncate_to_height(rewind_height)
                .map_err(|e| anyhow!("truncate cache: {:?}", e))?;
            Ok(true)
        }
        Ok(_) => {
            // After scanning, see whether a higher-priority range was discovered.
            let latest_ranges = db_data
                .suggest_scan_ranges()
                .map_err(|e| anyhow!("suggest_scan_ranges: {:?}", e))?;
            Ok(if let Some(range) = latest_ranges.first() {
                range.priority() > scan_range.priority()
            } else {
                false
            })
        }
        Err(e) => Err(anyhow!("scan_cached_blocks: {:?}", e)),
    }
}
