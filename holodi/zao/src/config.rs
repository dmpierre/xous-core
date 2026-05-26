//! Companion-wallet configuration: data directory, network, lightwalletd server.
//!
//! Persisted as TOML at `$DATADIR/config.toml`. Loaded on every wallet
//! command; created with sensible defaults on first `init`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use zcash_protocol::consensus;

const CONFIG_FILE: &str = "config.toml";
const WALLET_DB: &str = "wallet.sqlite";
const BLOCKS_DIR: &str = "blocks";

/// Lightwalletd defaults; can be overridden in `config.toml`.
const DEFAULT_LWD_MAINNET: &str = "https://zec.rocks:443";
const DEFAULT_LWD_TESTNET: &str = "https://testnet.zec.rocks:443";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Main,
    Test,
}

impl Network {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "main" | "mainnet" => Ok(Network::Main),
            "test" | "testnet" => Ok(Network::Test),
            other => Err(anyhow!("Unsupported network: {}", other)),
        }
    }

    pub fn as_consensus(self) -> consensus::Network {
        match self {
            Network::Main => consensus::Network::MainNetwork,
            Network::Test => consensus::Network::TestNetwork,
        }
    }

    pub fn default_lwd(self) -> &'static str {
        match self {
            Network::Main => DEFAULT_LWD_MAINNET,
            Network::Test => DEFAULT_LWD_TESTNET,
        }
    }
}

/// On-disk representation. Fields are optional so partial files still work.
#[derive(Debug, Default, Deserialize, Serialize)]
struct ConfigFile {
    network: Option<String>,
    server: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub datadir: PathBuf,
    pub network: Network,
    pub server: String,
}

impl Config {
    /// Resolve the datadir from CLI override, env var, or default `~/.zao/`.
    /// Falls back to the legacy `~/.zcashcli/` directory if it exists and the
    /// new default has not been created — this lets users keep their existing
    /// wallet without renaming the directory after the `zcashcli` → `zao` rename.
    pub fn resolve_datadir(cli_override: Option<&str>) -> Result<PathBuf> {
        if let Some(p) = cli_override {
            return Ok(PathBuf::from(p));
        }
        if let Ok(p) = std::env::var("ZAO_DATADIR") {
            if !p.is_empty() {
                return Ok(PathBuf::from(p));
            }
        }
        // Backward-compat: respect the old env var if explicitly set.
        if let Ok(p) = std::env::var("ZCASHCLI_DATADIR") {
            if !p.is_empty() {
                return Ok(PathBuf::from(p));
            }
        }
        let home = dirs_next::home_dir()
            .ok_or_else(|| anyhow!("Cannot determine home directory; set ZAO_DATADIR"))?;
        let new_dir = home.join(".zao");
        let legacy_dir = home.join(".zcashcli");
        // Prefer the new directory; fall back to the legacy one if it's the
        // only wallet present (a one-time grace period until the user renames).
        if !new_dir.exists() && legacy_dir.exists() {
            return Ok(legacy_dir);
        }
        Ok(new_dir)
    }

    /// Load `config.toml` from the datadir, or return an error if missing.
    pub fn load(datadir: PathBuf) -> Result<Self> {
        let path = datadir.join(CONFIG_FILE);
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("Reading config file {}", path.display()))?;
        let file: ConfigFile = toml::from_str(&raw)
            .with_context(|| format!("Parsing config file {}", path.display()))?;

        let network = file
            .network
            .as_deref()
            .map(Network::parse)
            .transpose()?
            .unwrap_or(Network::Main);
        let server = file
            .server
            .unwrap_or_else(|| network.default_lwd().to_string());

        Ok(Self { datadir, network, server })
    }

    /// Load the config if present; otherwise create one with defaults at `datadir`.
    pub fn load_or_init(datadir: PathBuf, network: Network) -> Result<Self> {
        let path = datadir.join(CONFIG_FILE);
        if path.exists() {
            return Self::load(datadir);
        }
        std::fs::create_dir_all(&datadir)
            .with_context(|| format!("Creating data directory {}", datadir.display()))?;
        let file = ConfigFile {
            network: Some(match network {
                Network::Main => "main".to_string(),
                Network::Test => "test".to_string(),
            }),
            server: Some(network.default_lwd().to_string()),
        };
        let serialized = toml::to_string(&file).context("Serializing default config")?;
        std::fs::write(&path, serialized)
            .with_context(|| format!("Writing config file {}", path.display()))?;
        Self::load(datadir)
    }

    pub fn wallet_db_path(&self) -> PathBuf {
        self.datadir.join(WALLET_DB)
    }

    pub fn blocks_dir(&self) -> PathBuf {
        self.datadir.join(BLOCKS_DIR)
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.datadir)
            .with_context(|| format!("Creating {}", self.datadir.display()))?;
        std::fs::create_dir_all(self.blocks_dir())
            .with_context(|| format!("Creating {}", self.blocks_dir().display()))?;
        Ok(())
    }
}

/// Convenience: load the config from a CLI-provided datadir override.
/// Errors if the wallet has not been initialised (no config file found).
pub fn load_existing(datadir_override: Option<&str>) -> Result<Config> {
    let datadir = Config::resolve_datadir(datadir_override)?;
    if !datadir.join(CONFIG_FILE).exists() {
        return Err(anyhow!(
            "No wallet found at {}. Run `zao wallet init` first.",
            datadir.display()
        ));
    }
    Config::load(datadir)
}

#[allow(dead_code)]
pub fn config_file_path(datadir: &Path) -> PathBuf {
    datadir.join(CONFIG_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_parse_accepts_main_aliases() {
        assert_eq!(Network::parse("main").unwrap(), Network::Main);
        assert_eq!(Network::parse("mainnet").unwrap(), Network::Main);
    }

    #[test]
    fn network_parse_accepts_test_aliases() {
        assert_eq!(Network::parse("test").unwrap(), Network::Test);
        assert_eq!(Network::parse("testnet").unwrap(), Network::Test);
    }

    #[test]
    fn network_parse_rejects_unknown() {
        assert!(Network::parse("regtest").is_err());
        assert!(Network::parse("MAIN").is_err()); // case-sensitive
        assert!(Network::parse("").is_err());
    }

    #[test]
    fn network_default_lwd_distinguishes_chains() {
        let main_default = Network::Main.default_lwd();
        let test_default = Network::Test.default_lwd();
        assert_ne!(main_default, test_default);
        assert!(main_default.starts_with("https://"));
        assert!(test_default.starts_with("https://"));
        // Sanity: testnet endpoint must contain "testnet" in its hostname.
        assert!(test_default.to_lowercase().contains("testnet"));
    }

    #[test]
    fn network_as_consensus_round_trip() {
        // Sanity that the consensus mapping is total — the call must not
        // panic for either variant.
        let _ = Network::Main.as_consensus();
        let _ = Network::Test.as_consensus();
    }

    /// Snapshot+restore both env vars around a call so the home-dir
    /// fallthrough logic isn't masked by an inherited environment.
    fn with_clean_datadir_env<F: FnOnce() -> R, R>(f: F) -> R {
        let prev_zao = std::env::var("ZAO_DATADIR").ok();
        let prev_old = std::env::var("ZCASHCLI_DATADIR").ok();
        std::env::remove_var("ZAO_DATADIR");
        std::env::remove_var("ZCASHCLI_DATADIR");
        let r = f();
        match prev_zao {
            Some(p) => std::env::set_var("ZAO_DATADIR", p),
            None => std::env::remove_var("ZAO_DATADIR"),
        }
        match prev_old {
            Some(p) => std::env::set_var("ZCASHCLI_DATADIR", p),
            None => std::env::remove_var("ZCASHCLI_DATADIR"),
        }
        r
    }

    #[test]
    fn resolve_datadir_cli_override_wins() {
        with_clean_datadir_env(|| {
            std::env::set_var("ZAO_DATADIR", "/tmp/from-env");
            let resolved = Config::resolve_datadir(Some("/tmp/from-cli")).unwrap();
            std::env::remove_var("ZAO_DATADIR");
            assert_eq!(resolved, PathBuf::from("/tmp/from-cli"));
        });
    }

    #[test]
    fn resolve_datadir_zao_env_used_when_no_cli() {
        with_clean_datadir_env(|| {
            std::env::set_var("ZAO_DATADIR", "/tmp/from-zao-env");
            let resolved = Config::resolve_datadir(None).unwrap();
            std::env::remove_var("ZAO_DATADIR");
            assert_eq!(resolved, PathBuf::from("/tmp/from-zao-env"));
        });
    }

    #[test]
    fn resolve_datadir_legacy_env_still_honoured() {
        with_clean_datadir_env(|| {
            std::env::set_var("ZCASHCLI_DATADIR", "/tmp/from-legacy-env");
            let resolved = Config::resolve_datadir(None).unwrap();
            std::env::remove_var("ZCASHCLI_DATADIR");
            assert_eq!(resolved, PathBuf::from("/tmp/from-legacy-env"));
        });
    }

    #[test]
    fn resolve_datadir_empty_env_falls_through_to_home() {
        with_clean_datadir_env(|| {
            std::env::set_var("ZAO_DATADIR", "");
            std::env::set_var("ZCASHCLI_DATADIR", "");
            let resolved = Config::resolve_datadir(None);
            std::env::remove_var("ZAO_DATADIR");
            std::env::remove_var("ZCASHCLI_DATADIR");
            // Empty env must be treated as unset → home-dir logic.
            // Result is ~/.zao OR (legacy fallback) ~/.zcashcli, depending on
            // what already exists in the test runner's home.
            if let Ok(p) = resolved {
                let last = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                assert!(
                    last == ".zao" || last == ".zcashcli",
                    "expected .zao or legacy .zcashcli, got {:?}",
                    p
                );
                assert_ne!(p, PathBuf::from(""));
            }
        });
    }

    /// Note: env-var tests in this module are NOT parallel-safe (they share
    /// process global state). They run serially because they all touch
    /// `ZAO_DATADIR` / `ZCASHCLI_DATADIR`. If you add more tests that mutate
    /// either var, either go through `with_clean_datadir_env` or collapse
    /// the new scenarios into the existing tests.
    fn isolated_datadir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create tempdir")
    }

    #[test]
    fn load_or_init_creates_fresh_mainnet_config() {
        let tmp = isolated_datadir();
        let cfg = Config::load_or_init(tmp.path().to_path_buf(), Network::Main).unwrap();
        assert_eq!(cfg.network, Network::Main);
        assert_eq!(cfg.server, Network::Main.default_lwd().to_string());
        assert_eq!(cfg.datadir, tmp.path());
        assert!(tmp.path().join(CONFIG_FILE).exists());
    }

    #[test]
    fn load_or_init_creates_fresh_testnet_config() {
        let tmp = isolated_datadir();
        let cfg = Config::load_or_init(tmp.path().to_path_buf(), Network::Test).unwrap();
        assert_eq!(cfg.network, Network::Test);
        assert_eq!(cfg.server, Network::Test.default_lwd().to_string());
    }

    #[test]
    fn load_or_init_is_idempotent_and_preserves_existing_file() {
        let tmp = isolated_datadir();
        // Create a custom config with a non-default server.
        let path = tmp.path().join(CONFIG_FILE);
        std::fs::write(&path, "network = \"test\"\nserver = \"https://custom:443\"\n").unwrap();
        // Calling load_or_init with Main should NOT overwrite — the existing
        // file decides the network/server.
        let cfg = Config::load_or_init(tmp.path().to_path_buf(), Network::Main).unwrap();
        assert_eq!(cfg.network, Network::Test);
        assert_eq!(cfg.server, "https://custom:443");
    }

    #[test]
    fn load_partial_config_uses_defaults() {
        // No `network` field → defaults to Main; no `server` → default LWD.
        let tmp = isolated_datadir();
        let path = tmp.path().join(CONFIG_FILE);
        std::fs::write(&path, "").unwrap();
        let cfg = Config::load(tmp.path().to_path_buf()).unwrap();
        assert_eq!(cfg.network, Network::Main);
        assert_eq!(cfg.server, Network::Main.default_lwd().to_string());
    }

    #[test]
    fn load_explicit_server_overrides_default() {
        let tmp = isolated_datadir();
        std::fs::write(
            tmp.path().join(CONFIG_FILE),
            "network = \"test\"\nserver = \"https://override:443\"\n",
        )
        .unwrap();
        let cfg = Config::load(tmp.path().to_path_buf()).unwrap();
        assert_eq!(cfg.network, Network::Test);
        assert_eq!(cfg.server, "https://override:443");
    }

    #[test]
    fn load_invalid_toml_errors() {
        let tmp = isolated_datadir();
        std::fs::write(tmp.path().join(CONFIG_FILE), "this is not = valid = toml = !!!").unwrap();
        let err = Config::load(tmp.path().to_path_buf()).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("parsing"));
    }

    #[test]
    fn load_unknown_network_errors() {
        let tmp = isolated_datadir();
        std::fs::write(tmp.path().join(CONFIG_FILE), "network = \"regtest\"\n").unwrap();
        assert!(Config::load(tmp.path().to_path_buf()).is_err());
    }

    #[test]
    fn paths_are_relative_to_datadir() {
        let tmp = isolated_datadir();
        let cfg = Config::load_or_init(tmp.path().to_path_buf(), Network::Main).unwrap();
        assert_eq!(cfg.wallet_db_path(), tmp.path().join(WALLET_DB));
        assert_eq!(cfg.blocks_dir(), tmp.path().join(BLOCKS_DIR));
        assert_eq!(config_file_path(tmp.path()), tmp.path().join(CONFIG_FILE));
    }

    #[test]
    fn ensure_dirs_creates_blocks_subdir() {
        let tmp = isolated_datadir();
        let cfg = Config::load_or_init(tmp.path().to_path_buf(), Network::Main).unwrap();
        // Blocks dir is created lazily on ensure_dirs().
        assert!(!cfg.blocks_dir().exists());
        cfg.ensure_dirs().unwrap();
        assert!(cfg.blocks_dir().is_dir());
    }

    #[test]
    fn load_existing_errors_when_uninitialized() {
        let tmp = isolated_datadir();
        let err =
            load_existing(Some(tmp.path().to_str().unwrap())).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("init"));
    }

    /// Round-trip: serialize ConfigFile → parse back → fields equal.
    #[test]
    fn config_file_toml_round_trip() {
        let cf = ConfigFile {
            network: Some("test".to_string()),
            server: Some("https://example.com:443".to_string()),
        };
        let s = toml::to_string(&cf).unwrap();
        let parsed: ConfigFile = toml::from_str(&s).unwrap();
        assert_eq!(parsed.network.as_deref(), Some("test"));
        assert_eq!(parsed.server.as_deref(), Some("https://example.com:443"));
    }
}
