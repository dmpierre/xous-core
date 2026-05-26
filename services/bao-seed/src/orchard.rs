//! Orchard / Pallas key derivation + RedPallas signing for Zcash.
//!
//! Mirrors `services/zcashapp/src/{crypto,signing}.rs` but lives in the
//! vault so spending keys never cross the IPC boundary. Coin app
//! (zcashapp) sends PCZT-derived `(alpha, rk)` pairs + sighash; bao-seed
//! returns raw 64-byte spend-auth signatures.

use alloc::vec::Vec;

use bao_seed_common::{BaoSeedError, OrchardActionInput, OrchardFvkBytes, OrchardSignResponse};
use orchard::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
use orchard::primitives::redpallas;
use rand_core::{CryptoRng, RngCore};
use zip32::AccountId;

use crate::seed::Seed;

extern crate alloc;

/// Derive the Orchard `SpendingKey` for (coin_type, account) from a seed.
pub fn derive_spending_key(
    seed: &Seed,
    coin_type: u32,
    account: u32,
) -> Result<SpendingKey, BaoSeedError> {
    let account_id =
        AccountId::try_from(account).map_err(|_| BaoSeedError::InvalidRequest)?;
    SpendingKey::from_zip32_seed(seed.as_bytes(), coin_type, account_id)
        .map_err(|_| BaoSeedError::CryptoError)
}

/// Derive the 96-byte Orchard FullViewingKey for (coin_type, account).
///
/// Returned to the caller — FVK is, by design, safe to share.
pub fn derive_fvk_bytes(
    seed: &Seed,
    coin_type: u32,
    account: u32,
) -> Result<OrchardFvkBytes, BaoSeedError> {
    let sk = derive_spending_key(seed, coin_type, account)?;
    let fvk = FullViewingKey::from(&sk);
    Ok(fvk.to_bytes())
}

/// Sign each provided `(alpha, rk)` pair under the spend-auth key for
/// `(coin_type, account)`. Returns one entry per input action.
///
/// For each action:
/// - Derive `rsk = ask.randomize(alpha)`.
/// - Verify `VerificationKey::from(&rsk).to_bytes() == rk`.
///   - Mismatch ⇒ this action isn't ours; return `None`.
///   - Match ⇒ produce a 64-byte RedPallas spend-auth signature on
///     `sighash`.
///
/// The `rng` argument provides randomness for the RedPallas signature
/// (redpallas signing is randomized).
pub fn sign_actions<R: RngCore + CryptoRng>(
    seed: &Seed,
    coin_type: u32,
    account: u32,
    sighash: &[u8; 32],
    actions: &[OrchardActionInput],
    mut rng: R,
) -> Result<OrchardSignResponse, BaoSeedError> {
    let sk = derive_spending_key(seed, coin_type, account)?;
    let ask = SpendAuthorizingKey::from(&sk);

    let mut out: Vec<Option<[u8; 64]>> = Vec::with_capacity(actions.len());
    for action in actions {
        let alpha = match pallas_scalar_from_bytes(&action.alpha) {
            Some(a) => a,
            None => {
                out.push(None);
                continue;
            }
        };
        let rsk = ask.randomize(&alpha);
        let derived_rk: [u8; 32] = (&redpallas::VerificationKey::from(&rsk)).into();
        if derived_rk != action.rk {
            out.push(None);
            continue;
        }
        let sig: redpallas::Signature<redpallas::SpendAuth> = rsk.sign(&mut rng, sighash);
        let sig_bytes: [u8; 64] = (&sig).into();
        out.push(Some(sig_bytes));
    }
    Ok(out)
}

fn pallas_scalar_from_bytes(bytes: &[u8; 32]) -> Option<pasta_curves::Fq> {
    use pasta_curves::group::ff::PrimeField;
    let ct = pasta_curves::Fq::from_repr(*bytes);
    Option::<pasta_curves::Fq>::from(ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::seed_from_mnemonic;

    fn dev_seed() -> Seed {
        seed_from_mnemonic(
            b"abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon abandon \
              abandon abandon abandon abandon abandon art",
        )
    }

    #[test]
    fn fvk_is_deterministic() {
        let seed = dev_seed();
        let fvk1 = derive_fvk_bytes(&seed, 133, 0).expect("fvk1");
        let fvk2 = derive_fvk_bytes(&seed, 133, 0).expect("fvk2");
        assert_eq!(fvk1, fvk2);
    }

    #[test]
    fn different_accounts_yield_different_fvks() {
        let seed = dev_seed();
        let f0 = derive_fvk_bytes(&seed, 133, 0).unwrap();
        let f1 = derive_fvk_bytes(&seed, 133, 1).unwrap();
        assert_ne!(f0, f1);
    }

    #[test]
    fn mainnet_and_testnet_yield_different_fvks() {
        let seed = dev_seed();
        let mainnet = derive_fvk_bytes(&seed, 133, 0).unwrap();
        let testnet = derive_fvk_bytes(&seed, 1, 0).unwrap();
        assert_ne!(mainnet, testnet);
    }

    #[test]
    fn sign_actions_returns_none_for_non_matching_rk() {
        // Empty/arbitrary alpha+rk should not match a real derivation.
        let seed = dev_seed();
        let actions = alloc::vec![OrchardActionInput { alpha: [1u8; 32], rk: [2u8; 32] }];
        let mut rng = rand_core::OsRng;
        let out = sign_actions(&seed, 133, 0, &[0u8; 32], &actions, &mut rng)
            .expect("call ok");
        assert_eq!(out.len(), 1);
        assert!(out[0].is_none(), "non-matching rk must return None");
    }

    #[test]
    fn sign_actions_with_real_alpha_and_rk_returns_signature() {
        // Build a real (alpha, rk) pair by deriving the ask + a random
        // alpha, then computing the expected rk from it. This is the
        // same construction the companion wallet does when building a
        // PCZT, so passing the produced pair back into sign_actions
        // exercises the happy path end-to-end.
        let seed = dev_seed();
        let sk = derive_spending_key(&seed, 133, 0).unwrap();
        let ask = SpendAuthorizingKey::from(&sk);

        // Pick a deterministic alpha for the test (non-zero).
        let mut alpha_bytes = [0u8; 32];
        alpha_bytes[0] = 7;
        let alpha = pallas_scalar_from_bytes(&alpha_bytes).expect("alpha");
        let rsk = ask.randomize(&alpha);
        let rk: [u8; 32] = (&redpallas::VerificationKey::from(&rsk)).into();

        let actions = alloc::vec![OrchardActionInput { alpha: alpha_bytes, rk }];
        let mut rng = rand_core::OsRng;
        let out = sign_actions(&seed, 133, 0, &[0x42u8; 32], &actions, &mut rng)
            .expect("sign ok");
        assert_eq!(out.len(), 1);
        let sig = out[0].expect("matching rk should sign");
        assert_eq!(sig.len(), 64);
    }
}
