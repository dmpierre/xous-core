//! secp256k1 derivation + signing (BIP-32 → ECDSA).
//!
//! Internal to bao-seed; never returns raw private keys. Callers go
//! through `ServiceState::secp256k1_get_pubkey` and `secp256k1_sign`,
//! which derive on demand and discard the private key after use.

use bao_seed_common::{BaoSeedError, CompressedPubkey, Secp256k1Signature, HARDENED};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey};

use crate::seed::Seed;

extern crate alloc;

/// Derive a secp256k1 `SigningKey` at the given BIP-32 path.
///
/// `path` components use the standard convention: bit 31 set ⇒ hardened.
/// Empty path returns the root key.
pub fn derive_signing_key(seed: &Seed, path: &[u32]) -> Result<SigningKey, BaoSeedError> {
    use bip32::{ChildNumber, XPrv};

    let mut xprv = XPrv::new(seed.as_bytes()).map_err(|_| BaoSeedError::CryptoError)?;

    for &component in path {
        let (idx, hardened) = if component & HARDENED != 0 {
            (component & !HARDENED, true)
        } else {
            (component, false)
        };
        let child =
            ChildNumber::new(idx, hardened).map_err(|_| BaoSeedError::CryptoError)?;
        xprv = xprv.derive_child(child).map_err(|_| BaoSeedError::CryptoError)?;
    }

    let bytes = xprv.private_key().to_bytes();
    SigningKey::from_bytes((&bytes[..]).into()).map_err(|_| BaoSeedError::CryptoError)
}

/// Derive the compressed SEC1 public key at the given path.
pub fn derive_compressed_pubkey(
    seed: &Seed,
    path: &[u32],
) -> Result<CompressedPubkey, BaoSeedError> {
    let sk = derive_signing_key(seed, path)?;
    let vk = sk.verifying_key();
    let encoded = vk.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(BaoSeedError::CryptoError);
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Sign a 32-byte digest with the key at `path`. Produces a low-S
/// signature plus the Ethereum-style recovery id (0 or 1).
pub fn sign_hash(
    seed: &Seed,
    path: &[u32],
    hash: &[u8; 32],
) -> Result<Secp256k1Signature, BaoSeedError> {
    let sk = derive_signing_key(seed, path)?;
    let (sig, recid): (K256Signature, RecoveryId) = sk
        .sign_prehash_recoverable(hash)
        .map_err(|_| BaoSeedError::CryptoError)?;

    let bytes = sig.to_bytes();
    if bytes.len() != 64 {
        return Err(BaoSeedError::CryptoError);
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);

    Ok(Secp256k1Signature { r, s, recovery_id: recid.to_byte() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::seed_from_mnemonic;
    use hex_literal::hex;

    /// Standard BIP-44 path for Ethereum: m/44'/60'/0'/0/0
    fn eth_path(index: u32) -> alloc::vec::Vec<u32> {
        alloc::vec![44 | HARDENED, 60 | HARDENED, 0 | HARDENED, 0, index]
    }

    fn dev_seed_12() -> Seed {
        // "abandon × 11 about" — canonical empty-passphrase test mnemonic.
        seed_from_mnemonic(
            b"abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon about",
        )
    }

    /// Cross-checked against the well-known "abandon × 11 about"
    /// account-0 secp256k1 derivation at m/44'/60'/0'/0/0. The
    /// canonical Ethereum address for that mnemonic+path is
    /// 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 (widely cited in
    /// docs and test fixtures, e.g. ethers.js test vectors).
    #[test]
    fn eth_account_0_pubkey_to_address() {
        use tiny_keccak::{Hasher, Keccak};
        let seed = dev_seed_12();
        let pubkey = derive_compressed_pubkey(&seed, &eth_path(0)).expect("derive ok");

        // Decompress, then keccak256 of X||Y (skip 0x04 prefix).
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).expect("vk");
        let uncompressed = vk.to_encoded_point(false);
        let bytes = uncompressed.as_bytes();
        let mut hasher = Keccak::v256();
        hasher.update(&bytes[1..]);
        let mut h = [0u8; 32];
        hasher.finalize(&mut h);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&h[12..]);

        let expected: [u8; 20] = hex!("9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(addr, expected);
    }

    /// Sign / recovery round trip: signature recovers the same pubkey.
    #[test]
    fn sign_and_recover_roundtrip() {
        let seed = dev_seed_12();
        let path = eth_path(0);
        let hash = [0x42u8; 32];

        let sig = sign_hash(&seed, &path, &hash).expect("sign ok");
        let expected_pubkey = derive_compressed_pubkey(&seed, &path).unwrap();

        // Reconstruct k256 Signature + RecoveryId.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.r);
        sig_bytes[32..].copy_from_slice(&sig.s);
        let k_sig = k256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
        let recid = k256::ecdsa::RecoveryId::try_from(sig.recovery_id).unwrap();

        let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(&hash, &k_sig, recid)
            .expect("recover ok");
        let recovered_compressed = recovered.to_encoded_point(true);
        assert_eq!(recovered_compressed.as_bytes(), &expected_pubkey[..]);
    }

    /// Hardened-only path also works (no leaf-level non-hardened).
    #[test]
    fn hardened_only_path() {
        let seed = dev_seed_12();
        let path: alloc::vec::Vec<u32> = alloc::vec![44 | HARDENED, 60 | HARDENED, 0 | HARDENED];
        let _ = derive_compressed_pubkey(&seed, &path).expect("hardened-only ok");
    }

    /// Empty path returns root pubkey deterministically.
    #[test]
    fn empty_path_returns_root() {
        let seed = dev_seed_12();
        let pk1 = derive_compressed_pubkey(&seed, &[]).unwrap();
        let pk2 = derive_compressed_pubkey(&seed, &[]).unwrap();
        assert_eq!(pk1, pk2);
    }

    /// Different paths yield different pubkeys.
    #[test]
    fn different_paths_yield_different_pubkeys() {
        let seed = dev_seed_12();
        let pk0 = derive_compressed_pubkey(&seed, &eth_path(0)).unwrap();
        let pk1 = derive_compressed_pubkey(&seed, &eth_path(1)).unwrap();
        assert_ne!(pk0, pk1);
    }
}
