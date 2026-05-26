# bao-seed — Device-Level Seed Vault for Baochip-1x

bao-seed is the **single source of truth** for the BIP-39 master seed
on a Baochip-1x device. Coin apps (`ethapp`, `zcashapp`) hold no
seed material themselves; they format coin-specific signing requests
(sighashes, BIP-32 paths) and call into bao-seed via Xous IPC. This
is **Pattern A — sign-inside-vault**: private keys never leave
bao-seed's address space.

**Status:** Production for ETH (secp256k1 / EIP-1559) and Zcash
Orchard (RedPallas) on Baochip-1x hardware. Migrated off legacy
in-coin-app seed storage on `bao-seed` branch (2026-05-14).

## Architecture

```
+--------------------+         +--------------------+
| ethapp / zcashapp  |  IPC    | bao-seed           |
|  - PCZT / RLP      |<------->|  - seed storage    |
|  - sighash         |         |  - HD derivation   |
|  - serial frames   |         |  - signing primitives
+---------|----------+         +--------------------+
          | 0xE7 / 0xE8                  ^
          v                              |
        USB CDC-ACM                  signing
                                     primitives
                                          per scheme:
                                            secp256k1.rs (ETH)
                                            orchard.rs   (ZEC)
                                            …
```

The coin app is the only thing exposed over USB; bao-seed is reached
exclusively over Xous IPC. Host tooling (`holodi seed …`) hits the
USB transport on the coin app, which proxies to bao-seed.

## Current signature schemes

| Module             | Curve / Scheme | Used by                |
|--------------------|----------------|------------------------|
| `src/secp256k1.rs` | secp256k1 ECDSA| ethapp (EIP-1559, EIP-191) |
| `src/orchard.rs`   | Pallas / RedPallas | zcashapp (Orchard PCZT) |

Each module:

- derives keys from the master seed via the scheme's HD method
  (BIP-32 for secp256k1; ZIP-32 for Orchard);
- exposes a `sign(account, sighash) -> Signature` function;
- never returns the private key over IPC, only signatures.

The coin app does parsing/sighash/serialization; bao-seed does
derivation + signing. Splitting at the sighash boundary keeps bao-seed
small (no PCZT or RLP parsers in the vault) and lets each side iterate
independently.

## Adding a new signature scheme

The natural home is a sibling module in `src/`. Steps:

1. **Derivation.** Add a `derive_key(seed, account)` that consumes
   the master seed and a 32-bit account index. Use the scheme's
   standard HD method if one exists. If not (true for all PQ
   schemes — see below), use `HKDF-Expand(seed, "bao-seed/<scheme>/" || account_le_bytes)`
   to fill the scheme's KeyGen randomness.
2. **Signing.** `sign(account, sighash, …) -> Signature`. Never
   expose the secret key.
3. **Opcode + IPC.** Add an opcode in `libs/bao-seed-common/src/opcodes.rs`
   and a typed request/response in `types.rs`. Add a client method
   in `libs/bao-seed-api/src/client.rs`. Keep big signatures (>~50 B)
   on the memory-message path; only fingerprint-sized data fits in
   `scalar2`.
4. **Wire it from the coin app(s)** that need it. Existing call
   sites in `services/ethapp/src/handlers.rs` and
   `services/zcashapp/src/handlers.rs` are the template — the coin
   app prepares the sighash, calls `bao_seed.<scheme>_sign(…)`,
   and applies the returned signature to its own tx format.

### Post-quantum signatures (ML-DSA / SLH-DSA / Falcon)

The seed pipeline (BIP-39 → PBKDF2 → ZIP-32/BIP-32 HMAC derivation)
is symmetric crypto and quantum-resistant — Grover gives at most a
quadratic speedup, so a 24-word (256-bit) seed has ~128 bits of
post-quantum security. **The signature schemes hanging off the seed
are the vulnerable part** (secp256k1, RedPallas, Ed25519 are all
elliptic-curve discrete log → broken by Shor).

When (and only when) a chain you support defines a PQ tx-type, add the
scheme here:

```
src/pq/
  mod.rs
  mldsa.rs              ML-DSA-65 (NIST level 3, ~3.3 KB sig) — first choice
  slhdsa.rs             SLH-DSA (SPHINCS+, hash-based, ~7.8 KB sig) — optional
```

Use a vetted Rust crate (e.g. RustCrypto's `ml-dsa`, the `pqcrypto`
suite, or Falcon's reference port) rather than rolling your own.
Coin apps then call `bao_seed.mldsa_sign(account, sighash)` exactly
like they call `bao_seed.secp256k1_sign(…)` today.

#### HD derivation for PQ

BIP-32 leverages secp256k1's group homomorphism (`xpub` can derive
child public keys without secret material). Lattice/hash PQ schemes
have no such homomorphism, so a BIP-32 analog doesn't exist. Derive
per-account keypairs by:

```
prf_input = HKDF-Expand-SHA256(
    salt   = "bao-seed/pq/<scheme>/derive",
    ikm    = master_seed,
    info   = account.to_le_bytes(),
    okm    = <scheme's KeyGen seed length>
)
let (pk, sk) = Scheme::keygen(prf_input);
```

This is per-scheme and there is no IETF standard for it — pick a
domain-separation string and stick to it forever (changing it
invalidates every derived key). Document the choice in the module
header.

#### Code-size budget

PQ signing libraries are large:

- ML-DSA reference: 50–100 KB.
- SLH-DSA reference: 200+ KB.
- Falcon reference: 50–100 KB, plus floating-point or fixed-point
  emulation depending on impl.

**If you ship one scheme**, inline it under `bao-seed/src/pq/` and
accept the code-size hit.

**If you ship a menu** (ML-DSA + Falcon + SLH-DSA so a chain or user
can pick), promote `pq/` to a sibling service `services/bao-pqsign/`
so the firmware image doesn't carry dead code for unused schemes.
The cost is splitting the "single source of seed" abstraction across
two services — keep that for a future re-org, not the first PQ
landing.

**Default recommendation:** start with ML-DSA-65 inlined in bao-seed.
Split into its own service only when a second PQ scheme has a
concrete use case.

## Wire protocol

Opcodes are declared in `libs/bao-seed-common/src/opcodes.rs` in
disjoint blocks:

| Block      | Purpose                              |
|------------|--------------------------------------|
| `0x00–0x0F`| Lifecycle (init, generate, import, wipe, fingerprint) |
| `0x10–0x1F`| secp256k1 (derive, sign)             |
| `0x20–0x2F`| Orchard / Pallas (derive FVK, sign)  |
| `0x40–0x4F`| **(reserved for PQ schemes)**        |

Client library: `libs/bao-seed-api` — typed wrapper around the IPC
opcodes. Use this from coin apps; don't construct raw IPC messages.
