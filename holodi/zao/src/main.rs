//! zao — thin binary shim. The real entry point lives in the
//! library crate so `holodi` can link it directly via
//! `zao::run_from_argv` (no exec spawn).

fn main() -> anyhow::Result<()> {
    zao::run()
}
