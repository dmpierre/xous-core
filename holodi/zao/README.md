# zao — host CLI for the Baochip-1x Zcash hardware wallet

`zao` is the companion wallet for the [zcashapp](../../) firmware service
running on a Baochip-1x. The hardware holds the seed; this CLI handles
everything else — blockchain sync, note selection, ZK proof generation,
transaction broadcast — and consults the device only for the final
signature.

For project overview, architecture, and the full opcode reference, see
[`services/zcashapp/README.md`](../../README.md). This README focuses on
building and using the CLI.

## Build

```bash
# Inside the Nix dev shell, from the repo root:
nix build .#zao                            # binary at result/bin/zao
# or
cargo build --release --manifest-path holodi/Cargo.toml --package zao
```

`zao` is a member of the `holodi/` host workspace, at `holodi/zao/`.

## Command surface

`zao` mirrors zcash-devtool's command structure, with three subgroups:

| Group | Purpose |
|---|---|
| `zao baochip ...` | direct device commands (mnemonic, address, FVK, QR) |
| `zao wallet ...`  | wallet lifecycle (init, sync, balance, info, send, list-accounts) |
| `zao pczt ...`    | granular send pipeline (propose / create / prove / sign / combine / send / inspect) |

Run `zao guide` for an annotated walkthrough of each surface, including
flag-by-flag explanations and the air-gapped variant.

## Quick start (mainnet, real device)

The device connects over USB CDC-ACM (VID `0x1209`, PID `0x3613`).
Auto-detected by default; override with `--port /dev/ttyACM0` if needed.

```bash
# 1. Load a mnemonic on the device (dabao seed is volatile — wipes on reboot)
zao baochip import-mnemonic         # interactive, no shell history

# 2. Build a wallet from the device's UFVK
zao wallet init                     # default: mainnet, birthday=tip-100

# 3. Sync from lightwalletd (default https://zec.rocks:443)
zao wallet sync

# 4. Show balance + receive address
zao wallet balance

# 5. Send to self for round-trip testing
zao wallet send --to <ua-address> --amount 1000   # 1000 zatoshi
```

For testnet:

```bash
zao wallet init --network test --birthday <h>
```

## Granular send pipeline

Each stage of `wallet send` is a standalone subcommand operating on file
artifacts. Useful for debugging, audit, or air-gapped flows where the
device-attached machine never has lightwalletd network access.

```bash
# Pure host (no device, no network):
zao pczt propose --to <ua> --amount 1000 [-o proposal.pb]
zao pczt inspect --proposal proposal.pb

zao pczt create --proposal proposal.pb [-o unsigned.pczt]
zao pczt inspect --pczt unsigned.pczt

zao pczt prove --pczt unsigned.pczt [-o proved.pczt]    # ~30s; pure CPU

# Device:
zao pczt sign --unsigned unsigned.pczt [-o signed.pczt]

# Pure host:
zao pczt combine --proved proved.pczt --signed signed.pczt [-o combined.pczt]

# Network:
zao pczt send --pczt combined.pczt                      # prints txid
```

Default output paths are in the current directory. Override with `-o`.

## View-only wallet (air-gapped)

Mirrors zcash-devtool's `wallet init-fvk`: an online machine can hold a
view-only wallet built from the device's UFVK and prepare PCZTs without
the device ever being online.

```bash
zao wallet list-accounts                                 # on device-attached machine
# copy the UFVK + seed fingerprint shown
zao wallet init-fvk --fvk <ufvk> --seed-fingerprint <fp> --hd-account-index 0 \
    --birthday <h> --datadir /path/to/view-only-wallet
```

## Data directory

Default: `~/.zao/`. Override with `--datadir <path>` (per invocation) or
`$ZAO_DATADIR` (session). The legacy `$ZCASHCLI_DATADIR` env var and
`~/.zcashcli/` directory are still honoured for backward compat — if
`~/.zao/` does not exist and `~/.zcashcli/` does, the latter is used.

Contents after `zao wallet init`:

| File | Purpose |
|---|---|
| `config.toml` | network, lightwalletd URL |
| `wallet.sqlite` | view-only wallet (account UFVK, notes, txs) |
| `blocks/` | local block cache (FsBlockDb) |

## Logging

`zao` installs a tracing subscriber at INFO on stderr by default. The
`wallet sync` command emits per-batch progress; the send pipeline emits
per-stage status.

## Tests

```bash
cargo test --manifest-path holodi/Cargo.toml --package zao
```

Covers: 0xE8 framing (head/tail/middle, chunk-boundary reassembly,
malformed frames), config TOML round-trip + datadir resolution, UFVK
construction (mainnet + testnet), PCZT builder, send pipeline helpers
(proposal proto round-trip, hex tx parsing).

Tests requiring real hardware or lightwalletd are intentionally not
included — see the project test plan in
[`services/zcashapp/README.md`](../../README.md).

## Troubleshooting

**`Could not automatically determine the process-level CryptoProvider from Rustls`**
during init / sync / send: build is missing the `tls-ring` feature on
`tonic`. Should not occur in current builds; if it does, rebuild from
the latest revision.

**`No seed loaded (0x08)`** during `wallet init`: run
`zao baochip import-mnemonic` or `zao baochip generate-mnemonic` first.

**`wallet sync` shows `Synced: NaN%`** with zero balance: cosmetic
display issue when the wallet has no notes yet (numerator/denominator
both zero). Not a bug.

**Sync finishes immediately with `Fetched 0 scan ranges`**: birthday is
past your funding tx height. Re-run `wallet init --birthday <h>` with an
earlier height. Use `zcash-devtool wallet -w <other-wallet> list-tx` or
a block explorer to find the right height.

**`Failed to parse signed PCZT: DeserializeBadOption`** during send:
firmware is older than commit `c08aa3d3` ("redact proprietary maps").
Reflash with the latest `xous.uf2`.
