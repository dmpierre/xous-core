// Capture `git describe` at build time so the `zec version` subcommand
// can print the firmware commit. Mirrors the pattern used by
// holodi/zao/build.rs and
// services/bao-console/build.rs.

fn main() {
    let version = std::env::var("DABAO_CONSOLE_VERSION")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::process::Command::new("git")
                .args(["describe", "--always", "--dirty", "--long", "--tags", "--abbrev=9"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
        });
    println!("cargo:rustc-env=DABAO_CONSOLE_VERSION={}", version);
    // Re-run when HEAD or refs change so the embedded version stays current
    // without requiring a clean build.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-env-changed=DABAO_CONSOLE_VERSION");
}
