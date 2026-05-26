# zcashapp - Zcash Shielded Hardware Wallet for Xous

Zcash Orchard signing service for Baochip-1x running Xous OS. The
device holds the spending key and signs shielded transactions with
RedPallas; the host handles blockchain sync, note selection, ZK proof
generation, and broadcast.

**Host CLI:**

- `holodi zec …` — unified host CLI entry (recommended). Device-general
  commands (`ping`, `firmware-version`, `status`, `seed …`) live at the
  `holodi` top level and are shared with `holodi eth`. Coin-specific
  Zcash commands live under `holodi zec`.
- `zao …` — standalone Zcash-only binary. Same coin-specific subcommand
  tree as `holodi zec`. Use it when you don't want the holodi wrapper;
  the device-general / seed-mgmt verbs are intentionally absent here.

Seed material is held in `services/bao-seed` (Pattern A —
sign-inside-vault). zcashapp formats Orchard signing requests and calls
into bao-seed via Xous IPC; PCZT parsing, sighash computation, and
RedPallas signing are coin-specific and live in zcashapp.

**Status:** Developer preview. Full end-to-end Keystone-style flow
validated on real hardware against mainnet (first successful tx
2026-05-06). Not yet audited for production use.

## Architecture

```
HOST (untrusted)                       DEVICE (trusted)
+----------------------------+         +---------------------------+
| holodi zec / zao           |         | zcashapp (Xous service)   |
|  - blockchain sync         |         |  - PCZT parsing + display |
|  - note selection          |         |  - sighash recomputation  |
|  - ZK proof generation     |  USB    |    (ZIP-244, V5 Orchard)  |
|  - sighash computation     |<------->|  - calls bao-seed for     |
|  - transaction broadcast   | serial  |    RedPallas signing      |
+----------------------------+         +---------------------------+
                                                |  Xous IPC
                                                v
                                        +---------------------+
                                        | bao-seed            |
                                        |  - master seed      |
                                        |  - ZIP-32 derivation|
                                        |  - RedPallas sign() |
                                        +---------------------+
```

Hardware holds the seed; the host gets only the UFVK (read-only
viewing key). The device receives a fully-proved PCZT, recomputes the
shielded sighash locally, asks bao-seed to sign the Orchard spends with
RedPallas, redacts non-essential fields to shrink the response, and
returns. The host merges the device's sparse signed PCZT with its own
retained proved PCZT via the pczt `Combiner` role, extracts the final
transaction, and broadcasts.

### PCZT signing flow

1. `holodi zec wallet init` — fetches the device's 96-byte Orchard FVK
   and constructs a UFVK; creates `wallet.sqlite` as a view-only account
2. `holodi zec wallet sync` — scans blocks via lightwalletd
3. `holodi zec wallet send` runs the full pipeline:
   1. `propose_transfer` (note selection + fee)
   2. `create_pczt_from_proposal` (build unsigned PCZT)
   3. `Prover::create_orchard_proof` (add ZK proofs — no secrets needed)
   4. Compute shielded sighash, send PCZT to device
   5. Device signs Orchard actions, redacts non-essential fields, returns
   6. `Combiner::combine` merges the proved + signed PCZTs
   7. Extract the final `Transaction`, store in wallet, broadcast

For air-gapped or step-by-step inspection, each stage is also exposed
as a separate subcommand under `pczt`: `propose`, `create`, `prove`,
`sign`, `combine`, `send`, `inspect`, `redact`. See the granular
pipeline section below.

## Building

### Prerequisites

Enter the Nix dev shell (provides Rust toolchain, cross-compilation
sysroots, and vendored dependencies — including the host wallet
stack):

```bash
nix develop
xous-vendor-setup
```

### Build device firmware

```bash
# From the repo root — includes both ethapp and zcashapp:
xous-build dabao
```

zcashapp is built with `dev-mode` and `autoapprove` features on
dabao (see Cargo features below).

### Build host CLI

The `holodi/` workspace contains three crates: `cli` (the unified
`holodi` binary, package name `holodi`), `beth` (Ethereum-only), and
`zao` (Zcash-only). All are vendored via the flake.

```bash
nix build .#holodi      # binary at result/bin/holodi
nix build .#zao         # standalone zao binary at result/bin/zao
# or
cargo build --release --manifest-path holodi/Cargo.toml --package holodi
cargo build --release --manifest-path holodi/Cargo.toml --package zao
```

### Run unit tests

```bash
# Firmware tests (host-side; pure Rust modules — crypto, serial, signing):
cargo test --target x86_64-unknown-linux-gnu -p zcashapp

# zao tests (host CLI — transport framing, config, wallet, pczt_builder, send):
cargo test --manifest-path holodi/Cargo.toml --package zao
```

Together these exercise ~100 host-side tests covering BIP-39/ZIP-32
derivation, PCZT redaction, RedPallas signing, 0xE8 framing, UFVK
construction, and the granular send pipeline.

### Run on-device IPC tests (emulator)

```bash
cargo xtask dabao-emu zcashapp-test
```

Runs 11 IPC tests on the dabao hosted-mode emulator: ping, config,
seed management, key derivation, signing, cleanup.

## Host CLI

Commands shown below use the canonical `holodi zec …` form. The
standalone `zao …` form accepts the same coin-specific subcommands;
substitute `zao` for `holodi zec` if you're using the standalone
binary. Device-general / seed-mgmt verbs (`ping`, `firmware-version`,
`status`, `seed …`) are only available under `holodi` directly — they
were intentionally removed from `zao`.

### Device connection

Both CLIs auto-detect the Baochip-1x USB serial port (VID `0x1209`,
PID `0x3613`). Override with `--port /dev/ttyACM0` if needed.

### Device-general commands (holodi only)

```bash
# Health check
holodi ping

# Device firmware version (git describe of the xous-core commit)
holodi firmware-version

# Device firmware semver + protocol byte + feature flags
holodi config

# Dashboard: reachability + firmware + seed presence
holodi status

# Seed lifecycle (bao-seed vault — shared across eth + zec)
holodi seed status
holodi seed hasseed
holodi seed generate
holodi seed import       # interactive prompt; avoids shell history
holodi seed wipe
```

### Zcash key derivation

```bash
# Get Orchard shielded address (43 bytes, hex)
holodi zec baochip address --account 0

# Get Orchard Full Viewing Key (96 bytes, hex)
holodi zec baochip fvk --account 0

# Display address as a QR code in the terminal
holodi zec baochip qr --account 0

# 32-byte ZIP-32 seed fingerprint (matches what `wallet init` records)
holodi zec baochip seed-fingerprint

# Device-side signing readiness check
holodi zec baochip status

# Device firmware version (Zcash-app build identifier; distinct from
# the general `holodi firmware-version`)
holodi zec baochip version
```

### Companion wallet (one-shot pipeline)

```bash
# Initialise the wallet from the device's UFVK
holodi zec wallet init [--account 0] [--network main|test] [--birthday <h>] [--name device]

# Initialise a view-only wallet from a UFVK string (no device contact)
holodi zec wallet init-fvk --fvk uview1... [--name view] [--network main|test] \
    [--seed-fingerprint <hex>] [--hd-account-index N]

# List every account in the wallet DB (UFVK + derivation info)
holodi zec wallet list-accounts

# Sync against lightwalletd
holodi zec wallet sync [--batch-size 10000]

# Show balance
holodi zec wallet balance

# Print wallet info (paths, network, server, account, UFVK, birthday, sync state)
holodi zec wallet info

# Build, prove, sign on device, broadcast — all in one
holodi zec wallet send --to <ua> --amount <zat> [--memo <text>] [--account 0]
```

`init` requires the device to have a seed loaded (run
`holodi seed generate` or `holodi seed import` first). It reads the
device's Orchard FVK, builds a UFVK, and creates
`~/.zao/wallet.sqlite` (override with `--datadir` on `holodi zec` or
`$ZAO_DATADIR`; the legacy `$ZCASHCLI_DATADIR` is still honoured).

### Companion wallet (granular pipeline)

Each stage of `send` can also be run on its own; artifacts are
persisted as files so you can inspect, audit, or move between
machines (air-gapped flows):

```bash
# 1. Build proposal (note selection + fee calc)
holodi zec pczt propose --to <ua> --amount 1000 [-o proposal.pb]
holodi zec pczt inspect --proposal proposal.pb

# 2. Build unsigned PCZT
holodi zec pczt create --proposal proposal.pb [-o unsigned.pczt]
holodi zec pczt inspect --pczt unsigned.pczt

# 3. Add Orchard zk-proofs (pure host op; no device or secrets needed)
holodi zec pczt prove --pczt unsigned.pczt [-o proved.pczt]

# 4. Send unsigned PCZT to device for signing; output is the device's
#    signatures wrapped in a redacted PCZT skeleton.
holodi zec pczt sign --unsigned unsigned.pczt [-o signed.pczt]

# 5. Combine the proved PCZT (host-retained) with the signed PCZT
#    (device output) into a fully-signed-and-proven PCZT.
holodi zec pczt combine --proved proved.pczt --signed signed.pczt \
    [-o combined.pczt]

# 6. Extract the final transaction from the combined PCZT and broadcast
#    to lightwalletd (single step).
holodi zec pczt send --pczt combined.pczt

# Optional: apply the firmware's redactor closure to a PCZT host-side
holodi zec pczt redact --pczt some.pczt [-o redacted.pczt]
```

`inspect` accepts `--proposal | --pczt | --tx` and prints a
human-readable report.

### Manual PCZT signing (low-level)

```bash
# Sign a PCZT supplied as hex or file (e.g. for testing or
# interoperating with other wallet stacks)
holodi zec baochip sign-pczt --sighash <64-hex> --hex <pczt-hex>
holodi zec baochip sign-pczt --sighash <64-hex> --file tx.pczt
```

### Command reference

Device-general (under `holodi`, not `holodi zec` — shared with eth):

| Command | Talks to device? | Purpose |
|---|---|---|
| `holodi ping` | yes | Health check |
| `holodi firmware-version` | yes | Device firmware version |
| `holodi config` | yes | Firmware semver + protocol + flags |
| `holodi status` | yes | Reachability + firmware + seed |
| `holodi seed status` | yes | Seed presence + protocol version |
| `holodi seed generate` | yes | New 24-word mnemonic on device |
| `holodi seed import` | yes | Restore wallet (interactive) |
| `holodi seed wipe` | yes | Wipe seed from device |

Zcash-specific (under `holodi zec …` or standalone `zao …`):

| Command | Talks to device? | Talks to lightwalletd? | Purpose |
|---|---|---|---|
| `baochip address` | yes | — | Orchard shielded address |
| `baochip fvk` | yes | — | Orchard Full Viewing Key |
| `baochip qr` | yes (or --address) | — | Address as QR |
| `baochip status` | yes | — | Signing readiness |
| `baochip version` | yes | — | Zcash-app build identifier |
| `baochip seed-fingerprint` | yes | — | 32-byte ZIP-32 seed fingerprint |
| `baochip sign-pczt` | yes | — | Manual PCZT signing |
| `wallet init` | yes | yes | Create wallet.sqlite from device UFVK |
| `wallet init-fvk` | — | — | Create view-only wallet from UFVK string |
| `wallet list-accounts` | — | — | List accounts + UFVKs |
| `wallet sync` | — | yes | Scan blocks |
| `wallet balance` | — | — | Show balance |
| `wallet info` | — | — | Wallet metadata + sync state |
| `wallet send` | yes | yes | Full pipeline |
| `pczt propose` | — | — | Note selection + fee plan |
| `pczt create` | — | — | Build unsigned PCZT |
| `pczt prove` | — | — | Add Orchard zk-proofs |
| `pczt sign` | yes | — | Device-sign (returns redacted signed PCZT) |
| `pczt combine` | — | — | Merge proved + signed PCZTs |
| `pczt send` | — | yes | Extract + broadcast |
| `pczt inspect` | — | — | Human-readable report |
| `pczt redact` | — | — | Apply firmware redactor host-side |

## zcashapp — Device service

### Features

- **Key derivation**: ZIP-32 Orchard (`SpendingKey -> FullViewingKey -> Address`),
  performed inside `bao-seed` (Pattern A). zcashapp never sees the spending key.
- **Seed management**: Delegated to `bao-seed`. Coin-app seed opcodes
  (`GenerateMnemonic` / `ImportMnemonic` / `ClearSeed`) still exist for
  the test-sign path but the canonical entry point is `holodi seed …`,
  which targets bao-seed through ethapp's USB transport.
- **PCZT signing**: Parse PCZT, recompute sighash (ZIP-244, V5
  Orchard-only), extract display info, ask bao-seed to sign Orchard
  spends, apply signatures to the bundle.
- **Low-level signer**: Uses pczt `low_level_signer` role (pure Rust, no C deps)
- **RedPallas signatures**: `orchard::pczt::Action::sign()` with `SpendAuthorizingKey`
- **Response redaction**: After signing, strips secret/witness/proof/proprietary
  fields to keep the response small and avoid serialization round-trip pitfalls.
  The host's `Combiner` merges the signed-and-redacted response with the proved
  PCZT it retained.

### Cargo features

| Feature | Purpose | Security |
|---|---|---|
| `dev-mode` | Ephemeral test seed, mnemonic echoed over serial | INSECURE |
| `autoapprove` | Skip user confirmation on display | INSECURE |
| `board-dabao` | Dabao dev board target | - |
| `hosted-dabao` | Host-emulated dabao (for `dabao-emu`) | - |
| `testnet` | Use mainnet `coin_type=133` overridden to testnet `coin_type=1` for ZIP-32 | dev only |

### Key derivation

Performed inside `services/bao-seed`. zcashapp asks bao-seed for the
FullViewingKey (which it forwards to the host for note discovery) and
for per-action RedPallas signatures; the SpendingKey and
SpendAuthorizingKey never leave bao-seed.

```
Master Seed (64 bytes, from BIP39 mnemonic) — held in bao-seed
    |
    v
SpendingKey (ZIP-32, coin_type=133, account=N)
    |
    +---> FullViewingKey (96 bytes) ---> shared with the host (UFVK)
    |         |
    |         +---> Address (43 bytes, diversifier index 0)
    |
    +---> SpendAuthorizingKey ---> signs PCZT actions (inside bao-seed)
```

### Source files

| File | Purpose |
|---|---|
| `src/main.rs` | Service loop, IPC dispatch |
| `src/handlers.rs` | Command handlers (seed, keys, signing) |
| `src/crypto.rs` | ZIP-32 key derivation |
| `src/signing.rs` | PCZT parsing, display extraction, RedPallas signing, post-sign redaction |
| `src/serial.rs` | 0xE8 USB CDC-ACM serial framing |
| `src/state.rs` | Service state, display helpers |
| `src/platform.rs` | Platform abstraction (autoapprove, display) |

## Wire protocol

USB CDC-ACM serial at 115200 baud.

```
Request:  [0xE8] [length: u16 LE] [opcode: u8] [payload...]
Response: [0xE8] [length: u16 LE] [status: u8] [payload...]
```

The `0xE8` magic byte distinguishes zcashapp frames from ethapp
(`0xE7`). Both coexist on the same USB serial.

### Opcodes

| Opcode | Name | Payload | Response |
|---|---|---|---|
| `0xFF` | Ping | (none) | status |
| `0x90` | GetConfig | (none) | version(u32 LE) + has_seed(u8) + network(u8) |
| `0x92` | GetOrchardAddress | account(u32 LE) | 43-byte address |
| `0x93` | GetOrchardFVK | account(u32 LE) | 96-byte FVK |
| `0x94` | SignPczt | account(u32 LE) + sighash(32) + pczt_bytes | signed-and-redacted PCZT — note: the device recomputes the sighash from the PCZT (ZIP-244, V5 Orchard-only) and rejects requests whose `sighash` disagrees with the local computation (`SighashMismatch`, code `0x0D`). The companion-supplied `sighash` is treated as a sanity-check only. |
| `0x95` | GetPcztStatus | (none) | ready(u8) |
| `0xA0` | GenerateMnemonic | (none) | mnemonic words (dev-mode only) |
| `0xA1` | ImportMnemonic | UTF-8 mnemonic | status |
| `0xA2` | ClearSeed | (none) | status |

### Status codes

| Code | Meaning |
|---|---|
| `0x00` | OK |
| `0x01` | Rejected by user |
| `0x02` | Invalid opcode |
| `0x03` | Invalid parameter |
| `0x04` | Invalid data / invalid PCZT |
| `0x05` | Unsupported |
| `0x06` | Internal error |
| `0x07` | Crypto error |
| `0x08` | No seed loaded |
| `0x0D` | Sighash mismatch (host-claimed sighash disagrees with the device's recomputed ZIP-244 digest) |

## Dependencies

Zcash crates (versions pinned to keep host and device in sync):

- `pczt` 0.6 — PCZT parsing, serialization, signer/redactor/combiner roles
- `orchard` 0.13 — Orchard protocol types, RedPallas, key derivation
- `pasta_curves` — Pallas/Vesta curves
- `reddsa` — RedPallas/RedJubjub signatures
- `zip32` — ZIP-32 hierarchical key derivation

A workspace-level `[patch.crates-io.orchard]` unifies the orchard
instance between pczt (registry dep) and zcashapp (git dep).

zao additionally depends on `zcash_client_backend` 0.22 +
`zcash_client_sqlite` 0.20 (with `transparent-inputs`, `unstable`,
`serde` features) for the wallet stack, and `tonic` 0.14 with
`tls-ring` for lightwalletd HTTPS.

## Security considerations

This is a developer preview. Key gaps before production use:

1. **Sighash trust:** ✅ The device recomputes the V5 shielded sighash
   locally via `src/zip244.rs` (a small ZIP-244 implementation that
   re-uses `blake2b_simd`) and rejects PCZTs whose host-claimed sighash
   doesn't match. The companion-supplied `sighash` parameter is now a
   sanity-check only; signatures are produced with the locally-computed
   value. Limited to Orchard-only V5 PCZTs (transparent + sapling
   bundles must be empty).
2. **No trusted display on dabao:** dev board has no screen — uses
   `autoapprove`. Production hardware (baosec) supports a physical
   confirmation prompt.
3. **No PIN protection:** the seed is accessible without authentication.
4. **Ephemeral seed on dabao:** no persistent storage. Re-import the
   mnemonic after each reboot (`holodi seed import`).
5. **Dev-mode mnemonic echo:** in `dev-mode`, `holodi seed generate`
   echoes the mnemonic over serial. Never use for real funds.
