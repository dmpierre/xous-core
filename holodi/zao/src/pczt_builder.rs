//! PCZT construction for testing — plays the role of the companion wallet (Zodl).
//!
//! Constructs a valid PCZT with an Orchard spend+output and computes the
//! shielded sighash, using the same key derivation as the device firmware.

use anyhow::Result;
use incrementalmerkletree::{frontier::Frontier, Hashable};
use orchard::tree::MerkleHashOrchard;
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, signer::Signer};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, PcztResult},
    fees::zip317,
};
use zcash_protocol::{consensus::MainNetwork, memo::MemoBytes, value::Zatoshis};
use zip32::AccountId;

const COIN_TYPE_ZCASH: u32 = 133;

/// Derive a 64-byte seed from mnemonic via PBKDF2, matching zcashapp firmware.
fn seed_from_mnemonic(mnemonic: &str) -> [u8; 64] {
    use hmac::Hmac;
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<HmacSha512>(mnemonic.as_bytes(), b"mnemonic", 2048, &mut seed)
        .expect("PBKDF2 output length is valid");
    seed
}

/// Result of PCZT construction.
pub struct TestPczt {
    /// Serialized PCZT bytes.
    pub pczt_bytes: Vec<u8>,
    /// 32-byte shielded sighash.
    pub sighash: [u8; 32],
    /// Hex-encoded address.
    pub address_hex: String,
}

/// Build a test PCZT for the given mnemonic and account.
pub fn build_test_pczt(mnemonic: &str, account: u32, send_amount: u64) -> Result<TestPczt> {
    let seed = seed_from_mnemonic(mnemonic);
    let account_id =
        AccountId::try_from(account).map_err(|_| anyhow::anyhow!("invalid account"))?;
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, COIN_TYPE_ZCASH, account_id)
        .map_err(|_| anyhow::anyhow!("failed to derive spending key"))?;
    let fvk = orchard::keys::FullViewingKey::from(&sk);
    let ivk = fvk.to_ivk(orchard::keys::Scope::External);
    let ovk = fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
    let address_hex = hex::encode(recipient.to_raw_address_bytes());

    // Create a fake received note
    let mut rng = rand_core::OsRng;
    let note_value = send_amount + 10_000;
    let value = orchard::value::NoteValue::from_raw(note_value);
    let note = {
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard::Anchor::empty_tree(),
        );
        orchard_builder
            .add_output(None, recipient, value, [0u8; 512])
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &ivk.prepare(), action).unwrap();
        note
    };

    // Build merkle tree with one leaf
    let (anchor, merkle_path) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut frontier = Frontier::<MerkleHashOrchard, 32>::empty();
        assert!(frontier.append(leaf));
        let root = frontier.root();
        let auth_path: Vec<MerkleHashOrchard> = frontier
            .value()
            .unwrap()
            .witness(32, |addr| Some(MerkleHashOrchard::empty_root(addr.level())))
            .unwrap();
        let auth_arr: [MerkleHashOrchard; 32] = auth_path.try_into().unwrap();
        let path = orchard::tree::MerklePath::from_parts(0, auth_arr);
        (root.into(), path)
    };

    // Build transaction
    let change_amount = note_value.checked_sub(send_amount + 10_000)
        .ok_or_else(|| anyhow::anyhow!("amount too large"))?;

    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(ovk),
            recipient,
            Zatoshis::const_from_u64(send_amount),
            MemoBytes::empty(),
        )
        .unwrap();
    if change_amount > 0 {
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(fvk.to_ovk(zip32::Scope::Internal)),
                fvk.address_at(0u32, orchard::keys::Scope::Internal),
                Zatoshis::const_from_u64(change_amount),
                MemoBytes::empty(),
            )
            .unwrap();
    }

    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(rand_core::OsRng, &zip317::FeeRule::standard())
        .unwrap();

    // Create PCZT and finalize I/O
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();

    // Compute sighash
    let full_signer = Signer::new(pczt.clone()).unwrap();
    let sighash = full_signer.shielded_sighash();

    let pczt_bytes = pczt.serialize();

    Ok(TestPczt {
        pczt_bytes,
        sighash,
        address_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pczt::Pczt;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon about";

    #[test]
    fn seed_from_mnemonic_pinned_against_bip39_vector() {
        // Same expected seed as the firmware's
        // `test_bip39_seed_vector_12_words_all_zero`. If this drifts, the
        // host and device will derive different keys.
        use hex_literal::hex;
        let seed = seed_from_mnemonic(TEST_MNEMONIC);
        let expected = hex!(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
            "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
        assert_eq!(seed, expected);
    }

    #[test]
    fn build_test_pczt_round_trips_through_parser() {
        let tp = build_test_pczt(TEST_MNEMONIC, 0, 100_000).unwrap();
        // Sighash is exactly 32 bytes.
        assert_eq!(tp.sighash.len(), 32);
        // Address is 43 bytes raw → 86 hex chars.
        assert_eq!(tp.address_hex.len(), 86);
        // PCZT bytes parse back into a valid Pczt struct.
        let pczt = Pczt::parse(&tp.pczt_bytes).unwrap();
        assert!(!pczt.orchard().actions().is_empty());
    }

    /// The host-side address derivation must match the device's. We compare
    /// against the bytes the firmware would produce via `derive_address`.
    #[test]
    fn build_test_pczt_address_matches_firmware_derivation() {
        let tp = build_test_pczt(TEST_MNEMONIC, 0, 100_000).unwrap();
        let seed = seed_from_mnemonic(TEST_MNEMONIC);
        let sk = orchard::keys::SpendingKey::from_zip32_seed(
            &seed,
            COIN_TYPE_ZCASH,
            zip32::AccountId::try_from(0u32).unwrap(),
        )
        .unwrap();
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let addr = fvk.address_at(0u32, orchard::keys::Scope::External);
        assert_eq!(tp.address_hex, hex::encode(addr.to_raw_address_bytes()));
    }

    #[test]
    fn build_test_pczt_rejects_invalid_account() {
        // zip32::AccountId is u31; passing 0x80000000 (the top bit) must
        // be rejected.
        let res = build_test_pczt(TEST_MNEMONIC, u32::MAX, 100_000);
        match res {
            Ok(_) => panic!("expected error for u32::MAX account"),
            Err(e) => assert!(e.to_string().to_lowercase().contains("account")),
        }
    }

    /// Different accounts must produce different sighashes (the addresses
    /// embedded in the bundle differ, so the sighash must too).
    #[test]
    fn build_test_pczt_account_separates_sighash() {
        let a = build_test_pczt(TEST_MNEMONIC, 0, 100_000).unwrap();
        let b = build_test_pczt(TEST_MNEMONIC, 1, 100_000).unwrap();
        assert_ne!(a.address_hex, b.address_hex);
        assert_ne!(a.sighash, b.sighash);
    }

    /// Sighash from `Signer::shielded_sighash` is deterministic across
    /// repeated PCZT serializations of the same parts. We exercise it by
    /// re-parsing and re-running the signer.
    #[test]
    fn pczt_sighash_is_recoverable_from_serialized_bytes() {
        let tp = build_test_pczt(TEST_MNEMONIC, 0, 100_000).unwrap();
        let pczt = Pczt::parse(&tp.pczt_bytes).unwrap();
        let signer = pczt::roles::signer::Signer::new(pczt).unwrap();
        let recovered = signer.shielded_sighash();
        assert_eq!(recovered, tp.sighash);
    }

    /// PCZT serialization is canonical: serialize → parse → serialize must
    /// produce identical bytes (no nondeterminism, no field reordering).
    #[test]
    fn pczt_serialization_is_canonical() {
        let tp = build_test_pczt(TEST_MNEMONIC, 0, 50_000).unwrap();
        let pczt = Pczt::parse(&tp.pczt_bytes).unwrap();
        let reserialized = pczt.serialize();
        assert_eq!(tp.pczt_bytes, reserialized);
    }

    /// Each PCZT has a fresh randomization (rcv, alpha, ephemeral_key
    /// nonces). Two builds with the same input must therefore produce
    /// different bytes — never identical, never deterministic enough to
    /// risk nonce reuse.
    #[test]
    fn build_test_pczt_outputs_are_randomized() {
        let a = build_test_pczt(TEST_MNEMONIC, 0, 100_000).unwrap();
        let b = build_test_pczt(TEST_MNEMONIC, 0, 100_000).unwrap();
        // Same address (deterministic from key), but different bytes/sighash.
        assert_eq!(a.address_hex, b.address_hex);
        assert_ne!(a.pczt_bytes, b.pczt_bytes);
        assert_ne!(a.sighash, b.sighash);
    }
}

// ---------------------------------------------------------------------------
// Diagnostic-only tests for the 12258-byte corruption bug.
//
// These read /workspace/zcashcli-{proved,signed}.pczt (the captured device
// I/O for the failing mainnet send) and confirm the corruption pattern
// described in the bug report. Marked `#[ignore]` so they don't run by
// default — they depend on absolute-path captures and are not a regression
// test for the fix. Once the fix lands the captures are obsolete; the
// host-side regression test added in `signing` (firmware crate) covers
// the fix.
//
// Run with:
//   cargo test --config .cargo/vendor-config.toml \
//     --manifest-path services/zcashapp/tools/zcashcli/Cargo.toml \
//     --release -- --ignored diagnose_
// ---------------------------------------------------------------------------
#[cfg(test)]
mod diagnose_corruption_2026_05_06 {
    use std::fs;

    /// Load the captured pair and confirm:
    ///   - sizes are 12258 (proved) and 1950 (signed-and-corrupt)
    ///   - both start with the PCZT magic + version-1
    ///   - the first 28 bytes match between the two (header + start of
    ///     global). Byte 28 onwards diverges because the device clears
    ///     the global proprietary map (legitimate redaction).
    #[test]
    #[ignore]
    fn diagnose_capture_sizes_and_header() {
        let proved = fs::read("/workspace/zcashcli-proved.pczt").unwrap();
        let signed = fs::read("/workspace/zcashcli-signed.pczt").unwrap();

        assert_eq!(proved.len(), 12258, "proved.pczt size drifted");
        assert_eq!(signed.len(), 1950, "signed.pczt size drifted");
        assert_eq!(&proved[..4], b"PCZT");
        assert_eq!(&signed[..4], b"PCZT");
        // Header + version + first part of global match. Byte 28 in proved
        // is the proprietary-map count (0x01); the device redacts it (0x00).
        assert_eq!(&proved[..28], &signed[..28]);
    }

    /// Confirm the report's central claim:
    ///
    ///   "the byte streams diverge inside action[1].output.enc_ciphertext at
    ///    byte ~289 of 580: the device bytes are spliced fragments of the
    ///    same action's cv_net + nullifier — last 18 bytes of cv_net,
    ///    followed by first 30 bytes of nullifier."
    ///
    /// We don't try to fully parse postcard here — we just locate the
    /// 18-byte cv_net suffix and the 30-byte nullifier prefix in the
    /// proved bytes (which still has correct enc_ciphertext) and confirm
    /// they appear, contiguously, inside the device's enc_ciphertext
    /// region of the signed bytes.
    #[test]
    #[ignore]
    fn diagnose_enc_ciphertext_spliced_from_same_action_fields() {
        let proved = fs::read("/workspace/zcashcli-proved.pczt").unwrap();
        let signed = fs::read("/workspace/zcashcli-signed.pczt").unwrap();

        // 18-byte cv_net suffix and 30-byte nullifier prefix as named
        // in the bug report. Bytes verbatim from the analysis.
        let cvnet_suffix: &[u8] = &[
            0xda, 0xe0, 0x31, 0xfc, 0xb4, 0xd9, 0x33, 0xc7, 0xc0, 0x00,
            0x0b, 0xf8, 0x74, 0x07, 0xaa, 0x95, 0xc3, 0x93,
        ];
        let nullifier_prefix: &[u8] = &[
            0x08, 0x23, 0xee, 0x18, 0x0f, 0x59, 0x40, 0xac, 0xe5, 0x54,
            0x8a, 0xf9, 0x4c, 0x6f, 0x40, 0x94, 0xb5, 0x90, 0x2c, 0xb4,
            0x33, 0x3b, 0xa0, 0xfd, 0x51, 0xc1, 0x08, 0xd5, 0xb9, 0x14,
        ];

        // The two fragments must each appear in the proved capture (where
        // they live in their canonical positions) and they must appear
        // *adjacently* in the signed capture (the spliced region).
        let proved_cv = find_subslice(&proved, cvnet_suffix);
        let proved_nf = find_subslice(&proved, nullifier_prefix);
        assert!(proved_cv.is_some(), "cv_net suffix not found in proved");
        assert!(proved_nf.is_some(), "nullifier prefix not found in proved");

        // In the proved bundle the nullifier follows cv_net (with intervening
        // postcard varint length), so cv_net must precede nullifier:
        assert!(
            proved_cv.unwrap() < proved_nf.unwrap(),
            "expected cv_net before nullifier in proved bytes",
        );

        // Build the spliced witness: cv_net suffix immediately followed by
        // nullifier prefix. This must NOT appear in the proved bytes (the
        // 32-byte nullifier is preceded by a 0x20 varint length and a 32-
        // byte rk before it), but it MUST appear once in the signed bytes
        // — somewhere inside the corrupted enc_ciphertext.
        let mut spliced = Vec::with_capacity(cvnet_suffix.len() + nullifier_prefix.len());
        spliced.extend_from_slice(cvnet_suffix);
        spliced.extend_from_slice(nullifier_prefix);

        assert!(
            find_subslice(&proved, &spliced).is_none(),
            "spliced pattern should not appear in proved bytes (it's the bug signature)",
        );
        assert!(
            find_subslice(&signed, &spliced).is_some(),
            "spliced pattern must appear in signed bytes (the corruption witness)",
        );
    }

    /// Confirm structural shape: 1950 - 1886 = 64 = one spend_auth_sig
    /// Some(64-byte sig) — the only legitimate size delta a successful
    /// device sign should add. We check this by counting the byte delta
    /// directly against the expected redacted-only size.
    #[test]
    #[ignore]
    fn diagnose_size_delta_is_one_spend_auth_sig() {
        let proved = fs::read("/workspace/zcashcli-proved.pczt").unwrap();
        let signed = fs::read("/workspace/zcashcli-signed.pczt").unwrap();
        // From the bug report: host applies the same redactor → 1886 bytes.
        // device returns 1950 → delta is 64 bytes.
        let delta = signed.len() as i64 - 1886i64;
        assert_eq!(delta, 64, "delta != one spend_auth_sig (64 bytes)");
        // Sanity: proved is the 12258-byte capture from the bug report.
        assert_eq!(proved.len(), 12258);
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|w| w == needle)
    }

    /// Walk the parsed PCZT and locate the wire offsets of action[1]'s
    /// cv_net, nullifier, and enc_ciphertext in the *device-signed* bytes.
    /// We do this by reading each field's value from the parsed device-
    /// signed PCZT and finding it in the wire bytes via subslice search.
    /// (For uniqueness we only locate fields that are 32 bytes and check
    /// that they appear exactly once.)
    #[test]
    #[ignore]
    fn diagnose_field_offsets_in_device_signed() {
        use pczt::Pczt;

        let signed = fs::read("/workspace/zcashcli-signed.pczt").unwrap();
        let proved = fs::read("/workspace/zcashcli-proved.pczt").unwrap();

        let psigned_res = Pczt::parse(&signed);
        eprintln!("signed parses: {:?}", psigned_res.as_ref().map(|_| ()));
        // Even if the signed parses fails, the proved must parse fine.
        let pproved = Pczt::parse(&proved).unwrap();

        // Locate action[1] cv_net & nullifier (32 bytes each) within
        // the proved bytes (where they're known correct).
        let actions = pproved.orchard().actions();
        eprintln!("proved actions = {}", actions.len());

        let cv_net_a1 = actions[1].cv_net();
        let nf_a1 = actions[1].spend().nullifier();
        let enc_a1 = actions[1].output().enc_ciphertext();

        // Locate cv_net within proved bytes
        let proved_cv_off = find_subslice(&proved, cv_net_a1).expect("cv_net in proved");
        let proved_nf_off = find_subslice(&proved, nf_a1).expect("nf in proved");
        // enc_ciphertext is 580 bytes — find its first 32 in proved
        let proved_enc_off = find_subslice(&proved, &enc_a1[..32]).expect("enc[..32] in proved");

        // Locate cv_net within the device-signed bytes
        let signed_cv_off = find_subslice(&signed, cv_net_a1);
        let signed_nf_off = find_subslice(&signed, nf_a1);
        // First 32 of correct enc_ciphertext from proved (should be ABSENT
        // in signed, because it's the corrupted field that gets garbage)
        let signed_enc_off = find_subslice(&signed, &enc_a1[..32]);

        eprintln!("PROVED  : cv_net@{} nf@{} enc@{}",
            proved_cv_off, proved_nf_off, proved_enc_off);
        eprintln!("SIGNED  : cv_net@{:?} nf@{:?} correct-enc@{:?}",
            signed_cv_off, signed_nf_off, signed_enc_off);

        // The bug claim: in signed bytes the 580-byte enc_ciphertext
        // region contains spliced bytes from cv_net+nullifier of the
        // same action. So the *correct* enc_ciphertext (from proved)
        // does NOT appear in signed. Confirm.
        assert!(
            signed_enc_off.is_none(),
            "device-signed must not contain action[1]'s correct enc_ciphertext bytes — corruption witness",
        );
    }

    /// Apply the *device's redactor* (no signing, just clear-fields-and-
    /// reserialize) to the proved PCZT, and compare byte-for-byte with the
    /// device's signed bytes. The device-signed bytes contain everything
    /// the host-redact has *plus* one spend_auth_sig (64 bytes). Locate
    /// the divergence window and print/assert it.
    ///
    /// We use this to confirm: the +64 byte delta is one spend_auth_sig
    /// inserted at a specific position; everything after that should
    /// match the host-redact stream byte-for-byte. If it doesn't, the
    /// divergence offset tells us exactly which field's bytes are wrong.
    #[test]
    #[ignore]
    fn diagnose_align_redacted_vs_signed() {
        use pczt::Pczt;
        use pczt::roles::redactor::Redactor;

        let proved = fs::read("/workspace/zcashcli-proved.pczt").unwrap();
        let signed = fs::read("/workspace/zcashcli-signed.pczt").unwrap();

        // Apply the device's redactor (mirror of `services/zcashapp/src/
        // signing.rs::sign_pczt` redaction) to the proved PCZT, with NO
        // signing. The output is the "no-sig redacted" baseline.
        let pczt = Pczt::parse(&proved).expect("proved must parse");
        let redacted = Redactor::new(pczt)
            .redact_global_with(|mut g| {
                g.clear_proprietary();
            })
            .redact_orchard_with(|mut r| {
                r.redact_actions(|mut ar| {
                    ar.clear_spend_recipient();
                    ar.clear_spend_value();
                    ar.clear_spend_rho();
                    ar.clear_spend_rseed();
                    ar.clear_spend_fvk();
                    ar.clear_spend_witness();
                    ar.clear_spend_alpha();
                    ar.clear_spend_zip32_derivation();
                    ar.clear_spend_dummy_sk();
                    ar.clear_output_recipient();
                    ar.clear_output_value();
                    ar.clear_output_rseed();
                    ar.clear_output_ock();
                    ar.clear_output_zip32_derivation();
                    ar.clear_output_user_address();
                    ar.clear_spend_proprietary();
                    ar.clear_output_proprietary();
                    ar.clear_rcv();
                });
                r.clear_zkproof();
                r.clear_bsk();
            })
            .finish();
        let redacted_bytes = redacted.serialize();
        eprintln!("host-redact-only bytes: {}", redacted_bytes.len());
        eprintln!("device-signed bytes  : {}", signed.len());

        // Find the first divergence between redacted_bytes and signed.
        // Up to that point both streams are identical.
        let common_len = redacted_bytes.len().min(signed.len());
        let first_diff = (0..common_len).find(|&i| redacted_bytes[i] != signed[i]);
        eprintln!("first divergence: {:?}", first_diff);

        let split = first_diff.unwrap_or(common_len);
        eprintln!(
            "redacted[split..split+16] = {}",
            hex::encode(&redacted_bytes[split..(split + 16).min(redacted_bytes.len())]),
        );
        eprintln!(
            "signed  [split..split+16] = {}",
            hex::encode(&signed[split..(split + 16).min(signed.len())]),
        );

        // After the +64 byte sig insertion, the remaining streams should
        // align if the on-device parse/serialize round-trip was clean. We
        // probe two offsets:
        //
        //   - off=64 — the standard "Some(64-byte sig) replaces None=0x00"
        //     differential is +63 bytes (1 byte for the option tag stays,
        //     64 bytes of sig are inserted). But signed has Some(0x01)
        //     vs redacted has None (0x00), so signed[split] differs from
        //     redacted[split]; signed[split+1..split+65] is the 64-byte
        //     sig, and signed[split+65..] should equal redacted[split+1..].
        //   - off=0 — sanity probe for a no-shift round-trip diff.
        let tail_red = &redacted_bytes[split + 1..];
        let probe_len = tail_red.len().min(64);
        let candidate_64 = if split + 1 + 64 + probe_len <= signed.len() {
            &signed[split + 1 + 64..split + 1 + 64 + probe_len]
        } else {
            &signed[split + 1 + 64..]
        };
        eprintln!(
            "tail_red       [..32]      = {}",
            hex::encode(&tail_red[..32.min(tail_red.len())]),
        );
        eprintln!(
            "signed[split+65..split+97] = {}",
            hex::encode(candidate_64),
        );

        // Track the next divergence after the sig insertion, treating
        // signed as the reference at offset (split+1+64) onwards.
        let after_sig_red = &redacted_bytes[split + 1..];
        let after_sig_dev = &signed[split + 1 + 64..];
        let common_after = after_sig_red.len().min(after_sig_dev.len());
        let next_diff = (0..common_after).find(|&i| after_sig_red[i] != after_sig_dev[i]);
        eprintln!(
            "next divergence after sig: {:?} (in absolute redacted offset: {:?})",
            next_diff,
            next_diff.map(|d| split + 1 + d),
        );
        if let Some(d) = next_diff {
            eprintln!(
                "redacted[abs..abs+16] = {}",
                hex::encode(&redacted_bytes[split + 1 + d..(split + 1 + d + 16).min(redacted_bytes.len())]),
            );
            eprintln!(
                "signed  [abs..abs+16] = {}",
                hex::encode(&signed[split + 1 + 64 + d..(split + 1 + 64 + d + 16).min(signed.len())]),
            );
        }
    }
}
