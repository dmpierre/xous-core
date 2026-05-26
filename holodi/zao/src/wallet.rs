//! View-only companion wallet built around the device's UFVK.
//!
//! The Baochip-1x holds the seed and exposes only the 96-byte raw Orchard
//! Full Viewing Key. We wrap that into a single-component Unified Full
//! Viewing Key, persist it in `wallet.sqlite`, and treat the account as
//! view-only — every spend goes back to the device for signing.

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use zcash_address::unified::{self, Encoding};
use zcash_client_backend::data_api::{AccountBirthday, AccountPurpose, WalletWrite, Zip32Derivation};
use zcash_client_sqlite::{util::SystemClock, WalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{self, Parameters};
use zip32::fingerprint::SeedFingerprint;

use crate::config::Config;

/// Construct a Unified Full Viewing Key string from a raw 96-byte Orchard FVK.
pub fn ufvk_string_from_orchard_fvk(
    network: consensus::NetworkType,
    orchard_fvk: &[u8],
) -> Result<String> {
    let raw: [u8; 96] = orchard_fvk
        .try_into()
        .map_err(|_| anyhow!("Expected 96-byte Orchard FVK, got {} bytes", orchard_fvk.len()))?;
    let item = unified::Fvk::Orchard(raw);
    let ufvk = unified::Ufvk::try_from_items(vec![item])
        .map_err(|e| anyhow!("Failed to assemble UFVK: {:?}", e))?;
    Ok(ufvk.encode(&network))
}

/// Parse a UFVK string into a typed `UnifiedFullViewingKey` for the given params.
pub fn parse_ufvk<P: Parameters>(params: &P, encoded: &str) -> Result<UnifiedFullViewingKey> {
    UnifiedFullViewingKey::decode(params, encoded).map_err(|e| anyhow!("Invalid UFVK: {}", e))
}

pub type SqliteWalletDb = WalletDb<rusqlite::Connection, consensus::Network, SystemClock, OsRng>;

/// Open the wallet sqlite db at `cfg.wallet_db_path()`. Does NOT initialise schema.
pub fn open_wallet_db(cfg: &Config) -> Result<SqliteWalletDb> {
    let path = cfg.wallet_db_path();
    WalletDb::for_path(&path, cfg.network.as_consensus(), SystemClock, OsRng)
        .with_context(|| format!("Opening wallet db at {}", path.display()))
}

/// Initialise the wallet sqlite schema if needed.
pub fn init_wallet_db(db: &mut SqliteWalletDb) -> Result<()> {
    use zcash_client_sqlite::wallet::init::init_wallet_db;
    init_wallet_db(db, None).map_err(|e| anyhow!("Failed to init wallet db: {:?}", e))
}

/// Initialise the FsBlockDb. Its sqlite metadata file lives at `<datadir>/blockmeta.sqlite`
/// and the per-block files live at `<datadir>/blocks/`.
pub fn init_block_db(cfg: &Config) -> Result<()> {
    use zcash_client_sqlite::chain::init::init_blockmeta_db;
    use zcash_client_sqlite::FsBlockDb;
    std::fs::create_dir_all(cfg.blocks_dir())?;
    let mut db_cache = FsBlockDb::for_path(&cfg.datadir)
        .map_err(|e| anyhow!("Opening block cache at {}: {:?}", cfg.datadir.display(), e))?;
    init_blockmeta_db(&mut db_cache).map_err(|e| anyhow!("init_blockmeta_db: {:?}", e))?;
    Ok(())
}

/// Import the UFVK as a view-only account. Kept for ad-hoc test use;
/// production paths now go through `import_account_ufvk_with_derivation`
/// so the seed fingerprint + account index can be recorded.
#[allow(dead_code)]
pub fn import_view_only_account(
    db: &mut SqliteWalletDb,
    name: &str,
    ufvk: &UnifiedFullViewingKey,
    birthday: &AccountBirthday,
) -> Result<()> {
    db.import_account_ufvk(name, ufvk, birthday, AccountPurpose::ViewOnly, None)
        .map_err(|e| anyhow!("import_account_ufvk failed: {:?}", e))?;
    Ok(())
}

/// Import a UFVK with an optional ZIP-32 derivation (seed fingerprint
/// + HD account index). Mirrors zcash-devtool's `wallet init-fvk`:
///
/// - Both seed_fingerprint AND hd_account_index provided →
///   `AccountPurpose::Spending { derivation: Some(...) }`. The wallet
///   knows the spending key exists somewhere (e.g. on a Baochip-1x);
///   future PCZTs will carry zip32_derivation that the signer can use
///   to identify "yes, this is mine".
/// - Neither provided → `AccountPurpose::ViewOnly`. Pure observer.
/// - Mismatched (only one) → error; both must be supplied together.
pub fn import_account_ufvk_with_derivation(
    db: &mut SqliteWalletDb,
    name: &str,
    ufvk: &UnifiedFullViewingKey,
    birthday: &AccountBirthday,
    seed_fingerprint: Option<&[u8; 32]>,
    hd_account_index: Option<u32>,
) -> Result<()> {
    let purpose = match (seed_fingerprint, hd_account_index) {
        (Some(sf), Some(idx)) => AccountPurpose::Spending {
            derivation: Some(Zip32Derivation::new(
                SeedFingerprint::from_bytes(*sf),
                zip32::AccountId::try_from(idx)
                    .map_err(|e| anyhow!("invalid hd_account_index: {:?}", e))?,
            )),
        },
        (None, None) => AccountPurpose::ViewOnly,
        _ => bail!(
            "Need either both (for spending) or neither (for view-only) of \
             seed_fingerprint and hd_account_index"
        ),
    };
    db.import_account_ufvk(name, ufvk, birthday, purpose, None)
        .map_err(|e| anyhow!("import_account_ufvk failed: {:?}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derive the 96-byte raw Orchard FVK that the device firmware would
    /// expose for the canonical 12-word "abandon ... about" test mnemonic
    /// at coin_type=133, account=0. This mirrors the firmware's
    /// `crypto::seed_from_mnemonic + derive_spending_key + fvk_to_bytes`
    /// path (verified to match by the firmware's
    /// `test_address_pinned_for_test_mnemonic` regression fence).
    fn test_orchard_fvk_bytes() -> [u8; 96] {
        use hmac::Hmac;
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;
        let mnemonic =
            b"abandon abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon about";
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2::<HmacSha512>(mnemonic, b"mnemonic", 2048, &mut seed).unwrap();
        let account = zip32::AccountId::try_from(0u32).unwrap();
        let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, 133, account).unwrap();
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        fvk.to_bytes()
    }

    #[test]
    fn ufvk_string_rejects_wrong_length() {
        let err =
            ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &[0u8; 95]).unwrap_err();
        assert!(err.to_string().contains("96"));
        assert!(ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &[]).is_err());
        assert!(
            ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &[0u8; 97]).is_err()
        );
    }

    #[test]
    fn ufvk_string_mainnet_starts_with_uview() {
        let fvk = test_orchard_fvk_bytes();
        let s = ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &fvk).unwrap();
        // Mainnet UFVK HRP is "uview".
        assert!(
            s.starts_with("uview"),
            "expected 'uview' HRP for mainnet UFVK, got: {}",
            &s[..s.len().min(16)],
        );
    }

    #[test]
    fn ufvk_string_testnet_uses_distinct_hrp() {
        let fvk = test_orchard_fvk_bytes();
        let main = ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &fvk).unwrap();
        let test = ufvk_string_from_orchard_fvk(consensus::NetworkType::Test, &fvk).unwrap();
        assert_ne!(main, test, "main and test UFVKs must encode differently");
        // Testnet UFVK HRP is "uviewtest".
        assert!(
            test.starts_with("uviewtest"),
            "expected 'uviewtest' HRP for testnet, got: {}",
            &test[..test.len().min(16)],
        );
    }

    #[test]
    fn ufvk_string_round_trips_through_parse() {
        let fvk = test_orchard_fvk_bytes();
        let encoded =
            ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &fvk).unwrap();
        let parsed = parse_ufvk(&consensus::Network::MainNetwork, &encoded).unwrap();
        // Re-encoding the parsed UFVK must match the original (canonical encoding).
        let reencoded = parsed.encode(&consensus::Network::MainNetwork);
        assert_eq!(encoded, reencoded);
    }

    #[test]
    fn ufvk_construction_is_deterministic() {
        let fvk = test_orchard_fvk_bytes();
        let a = ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &fvk).unwrap();
        let b = ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &fvk).unwrap();
        assert_eq!(a, b, "UFVK encoding must be deterministic");
    }

    #[test]
    fn parse_ufvk_rejects_garbage() {
        assert!(parse_ufvk(&consensus::Network::MainNetwork, "not-a-ufvk").is_err());
        assert!(parse_ufvk(&consensus::Network::MainNetwork, "").is_err());
        // Mainnet-encoded UFVK must not parse as testnet.
        let fvk = test_orchard_fvk_bytes();
        let mainnet_str =
            ufvk_string_from_orchard_fvk(consensus::NetworkType::Main, &fvk).unwrap();
        assert!(parse_ufvk(&consensus::Network::TestNetwork, &mainnet_str).is_err());
    }

    /// Open + init a fresh wallet sqlite, confirming `init_wallet_db` is
    /// idempotent (calling it twice on the same db must succeed).
    #[test]
    fn open_and_init_wallet_db_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = Config {
            datadir: tmp.path().to_path_buf(),
            network: crate::config::Network::Test,
            server: "https://example:443".to_string(),
        };
        let mut db = open_wallet_db(&cfg).expect("open wallet db");
        init_wallet_db(&mut db).expect("first init should succeed");
        // Second init on the same db must succeed too (it short-circuits
        // when the schema is already up to date).
        init_wallet_db(&mut db).expect("second init must be idempotent");
        assert!(cfg.wallet_db_path().exists());
    }

    #[test]
    fn init_block_db_creates_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = Config {
            datadir: tmp.path().to_path_buf(),
            network: crate::config::Network::Test,
            server: "https://example:443".to_string(),
        };
        init_block_db(&cfg).unwrap();
        assert!(cfg.blocks_dir().is_dir());
        // FsBlockDb metadata file is "blockmeta.sqlite" by convention.
        assert!(tmp.path().join("blockmeta.sqlite").exists());
    }
}
