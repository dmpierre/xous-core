# ethapp - Ethereum Hardware Wallet for Xous

Ethereum signing service for Baochip-1x running Xous OS.

**Host CLI:**

- `holodi eth …` — unified host CLI entry (recommended). Device-general
  commands (`ping`, `firmware-version`, `status`, `seed …`) live at the
  `holodi` top level and are shared with `holodi zec`. Coin-specific
  Ethereum commands live under `holodi eth`.
- `beth …` — standalone Ethereum-only binary. Same coin-specific
  subcommand tree as `holodi eth`. Use it when you don't want the holodi
  wrapper; the device-general / seed-mgmt verbs are intentionally absent
  here.

Seed material is held in `services/bao-seed` (Pattern A —
sign-inside-vault). ethapp formats secp256k1 signing requests and calls
into bao-seed via Xous IPC; transaction parsing, sighash computation,
and message formatting are coin-specific and live in ethapp.

**Status:** Developer preview. See [STATUS.md](STATUS.md) for security
assessment and production gaps.

## Architecture

```
HOST (untrusted)                    DEVICE (trusted)
+--------------------------+       +------------------------+
| holodi eth / beth        |       | ethapp (Xous service)  |
|  - builds unsigned txs   |       |  - RLP / EIP-1559 parse|
|  - JSON-RPC queries      | USB   |  - sighash computation |
|  - broadcasts signed txs |<----->|  - calls bao-seed for  |
|                          | serial|    secp256k1 signing   |
+--------------------------+       +------------------------+
                                            |  Xous IPC
                                            v
                                    +---------------------+
                                    | bao-seed            |
                                    |  - master seed      |
                                    |  - BIP32/BIP44      |
                                    |  - secp256k1 sign() |
                                    +---------------------+
```

The device holds the seed (inside `bao-seed`) and signs; the host
builds transactions and talks to the chain. Keys never leave the
device.

## Building

### Prerequisites

Install [Guix](https://guix.gnu.org/). All dependencies (Rust
toolchain, libudev, cross-compilation sysroots) are provided by the
reproducible Guix shell.

### Enter the dev shell

```bash
make -C guix shell
```

This drops you into a reproducible environment with all build tools
available. All commands below assume you are inside this shell.

### Build host CLI

The `holodi/` workspace contains three crates: `cli` (the unified
`holodi` binary, package name `holodi`), `beth` (Ethereum-only), and
`zao` (Zcash-only). All are vendored via the flake.

```bash
nix build .#holodi      # binary at result/bin/holodi
nix build .#beth        # standalone beth binary at result/bin/beth
# or
cargo build --release --manifest-path holodi/Cargo.toml --package holodi
cargo build --release --manifest-path holodi/Cargo.toml --package beth
```

### Build device firmware

```bash
# From the repo root:
cargo xtask dabao ethapp-test --no-verify
```

This produces the dabao firmware image with ethapp and the test suite.

### Reproducible builds via Guix (alternative)

```bash
# beth (host binary):
make -C guix beth

# dabao firmware with ethapp:
make -C guix dabao-ethapp

# Pin the output so it survives garbage collection:
make -C guix beth ROOT=beth
```

## Host CLI

Commands shown below use the canonical `holodi eth …` form. The
standalone `beth …` form accepts the same coin-specific subcommands;
substitute `beth` for `holodi eth` if you're using the standalone
binary. Device-general / seed-mgmt verbs (`ping`, `firmware-version`,
`status`, `seed …`) are only available under `holodi` directly — they
were intentionally removed from `beth`.

### Device connection

Both CLIs auto-detect the Baochip-1x USB serial port. Override with
`--port /dev/ttyACM0` if needed.

### Commands

#### Device-general (holodi only)

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

#### Addresses

```bash
# Get address at default index (m/44'/60'/0'/0/0)
holodi eth address

# Get address at specific index
holodi eth address --index 3

# List first 10 addresses
holodi eth accounts --count 10
```

#### Balances

```bash
# ETH balance (device address)
holodi eth balance --rpc-url https://ethereum-sepolia-rpc.publicnode.com

# ETH balance (arbitrary address, no device needed)
holodi eth balance --rpc-url https://... --address 0x1234...

# ERC-20 token balance
holodi eth token-balance --token 0xA0b8...USDC --rpc-url https://... \
  --decimals 6 --symbol USDC

# Token balance for arbitrary address (no device needed)
holodi eth token-balance --token 0xA0b8... --rpc-url https://... \
  --address 0x1234... --decimals 6 --symbol USDC
```

#### Sending ETH

Three workflows are supported:

**1. Online all-in-one** (simplest):

```bash
# Fetch chain state (nonce, gas, fees, balance)
holodi eth tx-info --rpc-url https://... --to 0xRecipient --value 1000000000000000000

# Build, sign, and get raw tx hex (legacy EIP-155)
holodi eth gen-tx 0xRecipient 1000000000000000000 \
  --nonce 0 --chain-id 11155111 --gas-price 1000000000 --gas-limit 21000

# Broadcast
holodi eth publish 0xRawSignedHex --rpc-url https://... --wait
```

**2. Air-gapped** (most secure):

```bash
# On online machine: build unsigned tx
holodi eth build-tx 0xRecipient 1000000000000000000 \
  --nonce 0 --chain-id 11155111 --gas-price 1000000000 --gas-limit 21000

# Transfer the unsigned hex to a device-connected machine

# On device-connected machine: sign
holodi eth sign-tx 0xUnsignedHex --index 0

# Transfer signed hex back, then broadcast
holodi eth publish 0xSignedHex --rpc-url https://...
```

**3. Manual**: build the RLP externally, pass to `sign-tx`.

#### Sending ERC-20 tokens

```bash
# Send 100 USDC (6 decimals, so 100000000 smallest units)
# Uses EIP-1559 by default, auto-fetches nonce/gas/fees
holodi eth send-token --token 0xA0b8...USDC 0xRecipient 100000000 \
  --rpc-url https://... --index 0

# Send and broadcast in one step
holodi eth send-token --token 0xA0b8... 0xRecipient 100000000 \
  --rpc-url https://... --broadcast

# Force legacy transaction
holodi eth send-token --token 0xA0b8... 0xRecipient 100000000 \
  --rpc-url https://... --legacy

# Override gas/nonce
holodi eth send-token --token 0xA0b8... 0xRecipient 100000000 \
  --rpc-url https://... --nonce 5 --gas-limit 80000
```

The `amount` argument is always in the token's smallest unit (e.g.,
for USDC with 6 decimals: 1000000 = 1 USDC, 100000000 = 100 USDC).

#### Message signing

```bash
# Sign an EIP-191 personal message
holodi eth sign-message "Hello Ethereum" --index 0

# Sign a raw RLP-encoded transaction (any type: legacy, EIP-2930, EIP-1559)
holodi eth sign-tx 0xRlpHex --index 0
```

#### Device attestation

Prove that a transaction was signed on a specific Baochip device.
See [ATTESTATION.md](ATTESTATION.md) for the trust model. **Status:**
proof-of-concept — dev-mode uses TOFU / witnessed-setup trust;
production needs a real firmware signing key + manufacturer
certificate chain (neither exists yet).

```bash
# One-time: generate attestation identity on device
holodi eth init-attestation

# Export the attestation public key (share with verifiers)
holodi eth get-attestation-key
# -> 0x02abc...

# Sign a transaction with attestation co-signature
holodi eth attest-sign-tx 0xUnsignedRlp --index 0
# -> tx: v=37 r=... s=...
# -> attest: v=27 r=... s=...
# -> raw: 0x...  (broadcastable signed tx)

# Offline verification (no device needed)
holodi eth verify-attestation \
  --pubkey 0x02abc... \
  --sign-hash 0xdef... \
  --tx-v 37 --tx-r ... --tx-s ... \
  --attest-v 27 --attest-r ... --attest-s ...
# -> VALID: attestation matches device pubkey 0x02abc...
```

#### Encrypted mnemonic import

For transferring a mnemonic from a trusted source device (e.g.
Precursor) without exposing it to the host. See
[ENCRYPTED-IMPORT.md](ENCRYPTED-IMPORT.md) for the protocol.
**Status:** receiver-side implementation only — no source-device
sender exists yet, so the cross-device flow is unexercised.

```bash
holodi eth init-import-key      # one-time
holodi eth get-import-key       # share pubkey with source device
holodi eth import-encrypted     # paste encrypted payload
```

#### Dangerous mode

On displayless dev boards (dabao), mainnet signing is blocked by default
to prevent accidental fund loss. To override for a single session:

```bash
holodi eth dangerous-mode  # alias: holodi eth yolo
# Type "I ACCEPT THE RISK" when prompted. Resets on reboot.
```

### Command reference

Device-general (under `holodi`, not `holodi eth` — shared with zec):

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

Ethereum-specific (under `holodi eth …` or standalone `beth …`):

| Command | Device | RPC | Purpose |
|---|---|---|---|
| `address` | yes | no | Derive address |
| `accounts` | yes | no | List addresses |
| `qr` | yes (or --address) | no | Address as QR |
| `dangerous-mode` | yes | no | Enable mainnet on dev boards |
| `sign-message` | yes | no | EIP-191 sign |
| `sign-tx` | yes | no | Sign any RLP tx |
| `balance` | opt | yes | ETH balance |
| `token-balance` | opt | yes | ERC-20 balance |
| `tx-info` | yes | yes | Chain state for tx building |
| `gen-tx` | yes | no | Build + sign legacy tx |
| `build-tx` | no | no | Offline unsigned RLP |
| `send-token` | yes | yes | Build + sign + broadcast ERC-20 transfer |
| `publish` | no | yes | Broadcast signed tx |
| `init-attestation` | yes | no | Generate device attestation key (PoC) |
| `get-attestation-key` | yes | no | Print attestation pubkey |
| `attest-sign-tx` | yes | no | Sign tx with attestation co-sig |
| `verify-attestation` | no | no | Offline attestation verification |
| `init-import-key` | yes | no | Initialise encrypted-import keypair |
| `get-import-key` | yes | no | Print encrypted-import pubkey |
| `import-encrypted` | yes | no | Decrypt + import an ECIES mnemonic payload |
| `guide` | no | no | Print a step-by-step USDC funding guide |
| `ui` | yes | no | Open the chat-style slash-command TUI |

## ethapp - Device Service

### Features

- **Key derivation**: BIP32/BIP44 hierarchical (`m/44'/60'/account'/change/index`)
- **Seed management**: generate mnemonic, import mnemonic, import raw seed, wipe
- **Transaction signing**: Legacy (EIP-155), EIP-2930, EIP-1559
- **Message signing**: EIP-191 personal messages, EIP-712 typed data
- **Clear signing**: ERC-20 `transfer()` and `approve()` decoded for display
- **Token metadata**: Cached token info (ticker, decimals) for clear-signed display
- **Device attestation** (PoC): Per-device secp256k1 identity co-signs transactions
- **Encrypted mnemonic import** (PoC): ECIES receiver for source-device → Baochip transfer
- **Persistent storage**: Optional PDDB integration (encrypted at rest)

### Cargo features

| Feature | Purpose | Security |
|---|---|---|
| `dev-mode` | Ephemeral test seed, mnemonic over serial | INSECURE |
| `autoapprove` | Skip user confirmation | INSECURE |
| `blind-signing` | Allow pre-hashed EIP-712 | Reduces visibility |
| `board-dabao` | Dabao dev board target | - |
| `hosted-dabao` | Host-emulated dabao | - |

### Transaction types

The device parses and signs all three Ethereum transaction types:

| Type | Byte | Description |
|---|---|---|
| Legacy | (none) | Pre-EIP-2718, `v = chainId * 2 + 35 + recoveryId` |
| EIP-2930 | `0x01` | Access list, `v = recoveryId` |
| EIP-1559 | `0x02` | Fee market (maxFee/priorityFee), `v = recoveryId` |

### Clear signing

When the device receives a transaction whose calldata matches a known
ERC-20 method (`transfer` or `approve`), it decodes the calldata and
displays a human-readable summary:

```
Type:      ERC-20 Transfer
Chain ID:  1
Token:     0xA0b8...3c4d
To:        0xRecipient...
Amount:    100 [UNVERIFIED] USDC
Gas Limit: 65000
Gas Price: 12.5 Gwei
```

If token metadata (ticker, decimals) has been provided via the
`ProvideErc20TokenInfo` opcode, the amount is formatted with the
correct decimals and ticker. Otherwise it shows raw values with `???`.

**Warning**: Token metadata is currently accepted without signature
verification (CRITICAL-04). The ticker is prefixed with `[UNVERIFIED]`
to indicate this. See STATUS.md for details.

## Wire protocol

Communication over USB CDC-ACM serial at 115200 baud.

```
Request:  [0xE7] [length: u16 LE] [opcode: u8] [payload...]
Response: [0xE7] [length: u16 LE] [status: u8] [payload...]
```

The `0xE7` magic byte allows beth frames to coexist with the text
console — non-`0xE7` bytes flow to the keyboard injection path, so
`tio` and `beth` work simultaneously.

## Security considerations

This is a developer preview. Key gaps before production use:

1. **No trusted display on hardware** (C1) - the single biggest gap
2. **Token metadata unverified** (C2) - attacker can spoof tickers
3. **No PIN protection** (C4)

Device attestation is implemented as a proof-of-concept. In developer
mode, it relies on trust-on-first-use. Production requires a secret
firmware signing key. See [ATTESTATION.md](ATTESTATION.md) for the
full trust model and [STATUS.md](STATUS.md) for the production roadmap.
