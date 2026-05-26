//! beth — thin binary shim. The real entry point lives in the
//! library crate so `holodi` can link it directly via
//! `beth::run_from_argv` (no exec spawn).

fn main() -> anyhow::Result<()> {
    beth::run()
}
