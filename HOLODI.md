# Baochip-1x Hardware Wallet

Entry point for the hardware-wallet stack on Xous: one device-side
seed vault, two coin apps, one unified host CLI.

**Status:** Developer preview. ETH (secp256k1 / EIP-1559) and Zcash
Orchard (RedPallas) sign end-to-end on real Baochip-1x hardware. Not
yet audited; not production-ready. See
[`services/ethapp/STATUS.md`](services/ethapp/STATUS.md) for the
detailed security assessment — most of it applies to the whole stack.

## Architecture

```
HOST (untrusted)                          DEVICE (trusted)
+----------------------------+            +---------------------------+
| holodi (unified CLI)       |   USB      | ethapp (Xous service)     |
|  - holodi {ping,           |   0xE7 ----|   - RLP / EIP-1559 parse  |
|     firmware-version,      |  frames    |   - sighash computation   |
|     status, seed …}        |            +-----------|---------------+
|  - holodi eth … (= beth)   |                        |  Xous IPC
|  - holodi zec … (= zao)    |   USB      +-----------v---------------+
|                            |   0xE8     | bao-seed (Xous service)   |
|                            |  frames    |   - master seed (vault)   |
|                            |   ---------|   - HD derivation         |
|                            |            |   - secp256k1 / RedPallas |
|                            |            |     signing primitives    |
|                            |            +-----------^---------------+
|                            |                        |  Xous IPC
|                            |   USB      +-----------|---------------+
|                            |   0xE8 ----| zcashapp (Xous service)   |
|                            |  frames    |   - PCZT parse + redact   |
|                            |            |   - ZIP-244 sighash       |
+----------------------------+            +---------------------------+
```

**Pattern A — sign-inside-vault.** `bao-seed` is the single source of
truth for the BIP-39 master seed. Coin apps (`ethapp`, `zcashapp`)
hold no seed material; they format coin-specific signing requests
(sighashes, BIP-32 / ZIP-32 paths) and call into bao-seed over Xous
IPC. Private keys never leave bao-seed's address space.

## Components

| Component | Path | Role |
|---|---|---|
| **holodi** (unified host CLI) | [`holodi/cli`](holodi/cli) | Device-general commands (`ping`, `firmware-version`, `config`, `status`, `seed …`) and routes coin-specific subtrees to beth / zao. |
| **beth** (Ethereum host CLI) | [`holodi/beth`](holodi/beth) | Standalone Ethereum-only binary. Same subcommand tree as `holodi eth …`. |
| **zao** (Zcash host CLI) | [`holodi/zao`](holodi/zao) | Standalone Zcash-only binary. Same subcommand tree as `holodi zec …`. Holds the companion wallet (sqlite) and lightwalletd client. |
| **bao-seed** (vault) | [`services/bao-seed`](services/bao-seed) | Master seed, HD derivation, signing primitives. See its [README](services/bao-seed/README.md) for the wire protocol and extension guidance (incl. post-quantum). |
| **ethapp** (Ethereum coin app) | [`services/ethapp`](services/ethapp) | RLP / EIP-1559 / EIP-2930 / EIP-155 parsing, sighash, ERC-20 clear signing. See [README](services/ethapp/README.md), [STATUS](services/ethapp/STATUS.md), [ATTESTATION](services/ethapp/ATTESTATION.md), [ENCRYPTED-IMPORT](services/ethapp/ENCRYPTED-IMPORT.md). |
| **zcashapp** (Zcash coin app) | [`services/zcashapp`](services/zcashapp) | PCZT parsing, ZIP-244 sighash recomputation, RedPallas signing, response redaction. See [README](services/zcashapp/README.md). |

## Quickstart

### 1. Build the device firmware

From a Nix dev shell at the repo root:

```bash
cargo xtask dabao dabao-console --no-verify
```

This produces a dabao firmware image bundling `bao-seed`, `ethapp`,
`zcashapp`, and the text console. dabao builds use `dev-mode` +
`autoapprove` (displayless dev board — no on-device confirmation).
Output is a `.uf2` file under `target/`.

### 2. Flash the device

Hold the BOOT button while plugging the dabao into USB; it appears as
a USB mass-storage device. Copy the `.uf2` onto it; the device
reboots into the new firmware.

### 3. Build the host CLI

```bash
nix build .#holodi      # binary at result/bin/holodi
```

Or, for the coin-specific standalone binaries:

```bash
nix build .#beth        # Ethereum-only
nix build .#zao         # Zcash-only
```

### 4. Load a seed

```bash
holodi ping              # confirm reachability
holodi firmware-version  # confirm flashed firmware version

# Either generate a fresh seed on-device:
holodi seed generate

# Or import an existing BIP-39 mnemonic (interactive — no shell history):
holodi seed import

# Confirm:
holodi status            # reachability + firmware + seed presence
```

### 5. Use it

```bash
# Ethereum
holodi eth address --index 0
holodi eth balance --rpc-url https://ethereum-sepolia-rpc.publicnode.com
holodi eth send-token --token 0xA0b8...USDC 0xRecipient 1000000 \
    --rpc-url https://... --broadcast

# Zcash
holodi zec wallet init --network main
holodi zec wallet sync
holodi zec wallet send --to u1... --amount 100000
```

See the per-coin READMEs for the full command surface, air-gapped
flows, attestation, encrypted mnemonic import, and the PCZT pipeline.

## Where to go next

- **Architecture deep-dive** — [`services/bao-seed/README.md`](services/bao-seed/README.md) (Pattern A, opcode blocks, post-quantum extension)
- **Ethereum** — [`services/ethapp/README.md`](services/ethapp/README.md) + [`STATUS.md`](services/ethapp/STATUS.md) (security gaps), [`ATTESTATION.md`](services/ethapp/ATTESTATION.md) (per-device co-signature, proof-of-concept), [`ENCRYPTED-IMPORT.md`](services/ethapp/ENCRYPTED-IMPORT.md) (source-device → Baochip mnemonic transfer, receiver-side only)
- **Zcash** — [`services/zcashapp/README.md`](services/zcashapp/README.md) (PCZT pipeline, wallet stack, opcodes)
- **Production gaps** — see C1–C6 in [`services/ethapp/STATUS.md`](services/ethapp/STATUS.md). The single largest gap is the missing trusted display on dabao; production target is a display-equipped board (baosec) with `dev-mode`/`autoapprove` removed.

## Board strategy

- **dabao** — dev / testnet only. No display, so on-device confirmation
  is stubbed (`autoapprove`). Mainnet ETH signing is blocked by a
  firmware guard; override per-session with `holodi eth dangerous-mode`
  at your own risk.
- **baosec** (or equivalent display-equipped board) — production target.
  Wire up the trusted-display path in `ethapp::platform.rs` and
  `zcashapp::platform.rs`, drop `autoapprove`, enable persistent seed
  storage (PDDB), then revisit STATUS.md.
