// Version priority (mirrors beth/zao):
//   1. HOLODI_VERSION env var (set by Guix / Nix release builds)
//   2. `git describe --always --dirty --tags` (dev builds in a checkout)
//   3. CARGO_PKG_VERSION from Cargo.toml (fallback, also picked up by
//      `option_env!` in src/main.rs if this script is skipped)

fn main() {
    let version = std::env::var("HOLODI_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::process::Command::new("git")
                .args(["describe", "--always", "--dirty", "--tags"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
        });

    println!("cargo:rustc-env=HOLODI_VERSION={}", version);
    // Re-run if HEAD moves so the version stays in sync with the
    // checkout. Path is package-relative — this crate lives at
    // `holodi/cli/`, so `.git/` is two levels up at the xous-core
    // repo root.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
