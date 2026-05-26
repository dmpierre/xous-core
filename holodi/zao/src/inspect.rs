//! Top-level `zao inspect <data>` — universal Zcash datum inspector.
//!
//! Mirrors zcash-devtool's `inspect` command for the cases this CLI's
//! users actually run into: addresses (especially multi-receiver UAs),
//! UFVK / UIVK strings, and ZIP-321 payment URIs. Hex-encoded PCZTs and
//! transactions are deliberately *not* handled here — those go through
//! `zao pczt inspect` which already understands every pipeline stage.

use anyhow::{anyhow, bail, Result};
use zcash_address::{
    unified::{self, Container, Encoding},
    ConversionError, ToAddress, ZcashAddress,
};
use zcash_protocol::{
    consensus::NetworkType,
    memo::{Memo, MemoBytes},
};

/// Top-level dispatcher. Sniffs the input format and hands off to the
/// matching formatter. Each branch is `try`-style — first one that
/// succeeds wins.
pub fn run(data: &str) -> Result<()> {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        bail!("Empty input.");
    }

    // 1. ZIP-321 payment request URI ("zcash:u1...?amount=...").
    if let Ok(req) = zip321::TransactionRequest::from_uri(trimmed) {
        return inspect_zip321(req);
    }

    // 2. Encoded Zcash address (UA, Sapling, transparent P2PKH/P2SH, TEX).
    if let Ok(addr) = ZcashAddress::try_from_encoded(trimmed) {
        return inspect_address(addr);
    }

    // 3. Unified Full Viewing Key.
    if let Ok((net, ufvk)) = unified::Ufvk::decode(trimmed) {
        return inspect_ufvk(net, ufvk);
    }

    // 4. Unified Incoming Viewing Key.
    if let Ok((net, uivk)) = unified::Uivk::decode(trimmed) {
        return inspect_uivk(net, uivk);
    }

    // 5. Hex bytes — point the user at the existing PCZT/tx inspector.
    if hex::decode(trimmed).is_ok() {
        bail!(
            "Looks like hex-encoded bytes. For PCZTs use `zao pczt inspect --pczt <file>`,\n\
             for raw transactions use `zao pczt inspect --tx <file>`."
        );
    }

    bail!("Input does not match any recognized Zcash format (address, UFVK, UIVK, ZIP-321 URI).")
}

// =============================================================================
// Addresses
// =============================================================================

/// Local mirror of zcash-devtool's address-kind discriminator. The
/// `ZcashAddress` type is opaque on purpose; we recover the variant by
/// implementing `TryFromAddress`.
#[allow(dead_code)]
enum AddressKind {
    Sprout([u8; 64]),
    Sapling([u8; 43]),
    Unified(unified::Address),
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    Tex([u8; 20]),
}

struct TypedAddress {
    net: NetworkType,
    kind: AddressKind,
}

impl zcash_address::TryFromAddress for TypedAddress {
    type Error = ();

    fn try_from_sprout(
        net: NetworkType,
        data: [u8; 64],
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        Ok(Self { net, kind: AddressKind::Sprout(data) })
    }
    fn try_from_sapling(
        net: NetworkType,
        data: [u8; 43],
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        Ok(Self { net, kind: AddressKind::Sapling(data) })
    }
    fn try_from_unified(
        net: NetworkType,
        data: unified::Address,
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        Ok(Self { net, kind: AddressKind::Unified(data) })
    }
    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        Ok(Self { net, kind: AddressKind::P2pkh(data) })
    }
    fn try_from_transparent_p2sh(
        net: NetworkType,
        data: [u8; 20],
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        Ok(Self { net, kind: AddressKind::P2sh(data) })
    }
    fn try_from_tex(
        net: NetworkType,
        data: [u8; 20],
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        Ok(Self { net, kind: AddressKind::Tex(data) })
    }
}

fn network_label(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => "main",
        NetworkType::Test => "testnet",
        NetworkType::Regtest => "regtest",
    }
}

fn inspect_address(addr: ZcashAddress) -> Result<()> {
    let typed: TypedAddress = addr
        .convert()
        .map_err(|_| anyhow!("Could not destructure address into a known variant"))?;

    println!("Zcash address");
    println!(" - Network: {}", network_label(typed.net));

    let kind_label = match typed.kind {
        AddressKind::Sprout(_) => "Sprout",
        AddressKind::Sapling(_) => "Sapling",
        AddressKind::Unified(_) => "Unified Address",
        AddressKind::P2pkh(_) => "Transparent P2PKH",
        AddressKind::P2sh(_) => "Transparent P2SH",
        AddressKind::Tex(_) => "TEX (ZIP 320)",
    };
    println!(" - Kind: {}", kind_label);

    if let AddressKind::Unified(ua) = typed.kind {
        println!(" - Receivers:");
        for receiver in ua.items() {
            match receiver {
                unified::Receiver::Orchard(data) => {
                    let single = unified::Address::try_from_items(vec![
                        unified::Receiver::Orchard(data),
                    ])
                    .map_err(|e| anyhow!("Failed to re-encode Orchard receiver: {:?}", e))?
                    .encode(&typed.net);
                    println!("   - Orchard ({})", single);
                }
                unified::Receiver::Sapling(data) => {
                    println!(
                        "   - Sapling ({})",
                        ZcashAddress::from_sapling(typed.net, data),
                    );
                }
                unified::Receiver::P2pkh(data) => {
                    println!(
                        "   - Transparent P2PKH ({})",
                        ZcashAddress::from_transparent_p2pkh(typed.net, data),
                    );
                }
                unified::Receiver::P2sh(data) => {
                    println!(
                        "   - Transparent P2SH ({})",
                        ZcashAddress::from_transparent_p2sh(typed.net, data),
                    );
                }
                unified::Receiver::Unknown { typecode, data } => {
                    println!("   - Unknown");
                    println!("     - Typecode: {}", typecode);
                    println!("     - Payload: {}", hex::encode(data));
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Viewing keys
// =============================================================================

fn inspect_ufvk(net: NetworkType, ufvk: unified::Ufvk) -> Result<()> {
    println!("Unified Full Viewing Key");
    println!(" - Network: {}", network_label(net));
    println!(" - Items:");
    for item in ufvk.items() {
        match item {
            unified::Fvk::Orchard(data) => {
                let single = unified::Ufvk::try_from_items(vec![unified::Fvk::Orchard(data)])
                    .map_err(|e| anyhow!("Failed to re-encode Orchard FVK: {:?}", e))?
                    .encode(&net);
                println!("   - Orchard ({})", single);
            }
            unified::Fvk::Sapling(data) => {
                // Don't pretend to be a Sapling extfvk if we can't construct
                // one — just print the raw item bytes, which is enough for
                // diagnostic use.
                println!("   - Sapling");
                println!("     - Payload: {}", hex::encode(data));
            }
            unified::Fvk::P2pkh(data) => {
                println!("   - Transparent P2PKH");
                println!("     - Payload: {}", hex::encode(data));
            }
            unified::Fvk::Unknown { typecode, data } => {
                println!("   - Unknown");
                println!("     - Typecode: {}", typecode);
                println!("     - Payload: {}", hex::encode(data));
            }
        }
    }
    Ok(())
}

fn inspect_uivk(net: NetworkType, uivk: unified::Uivk) -> Result<()> {
    println!("Unified Incoming Viewing Key");
    println!(" - Network: {}", network_label(net));
    println!(" - Items:");
    for item in uivk.items() {
        match item {
            unified::Ivk::Orchard(data) => {
                let single = unified::Uivk::try_from_items(vec![unified::Ivk::Orchard(data)])
                    .map_err(|e| anyhow!("Failed to re-encode Orchard IVK: {:?}", e))?
                    .encode(&net);
                println!("   - Orchard ({})", single);
            }
            unified::Ivk::Sapling(data) => {
                println!("   - Sapling");
                println!("     - Payload: {}", hex::encode(data));
            }
            unified::Ivk::P2pkh(data) => {
                println!("   - Transparent P2PKH");
                println!("     - Payload: {}", hex::encode(data));
            }
            unified::Ivk::Unknown { typecode, data } => {
                println!("   - Unknown");
                println!("     - Typecode: {}", typecode);
                println!("     - Payload: {}", hex::encode(data));
            }
        }
    }
    Ok(())
}

// =============================================================================
// ZIP-321 payment request URIs
// =============================================================================

fn inspect_zip321(request: zip321::TransactionRequest) -> Result<()> {
    println!("ZIP-321 payment request");

    let payments = request.payments();
    println!(" - Payment count: {}", payments.len());

    match request.total() {
        Ok(Some(total)) => {
            let zats = total.into_u64();
            println!(
                " - Total: {} zatoshis ({:.8} ZEC)",
                zats,
                zats as f64 / 1_0000_0000f64
            );
        }
        Ok(None) => {
            println!(" - One or more payments has no value; total cannot be computed.");
        }
        Err(e) => {
            println!(" - Error computing total: {}", e);
        }
    }

    for (&index, payment) in payments {
        println!();
        println!(" Payment #{}:", index);
        println!("   - Address: {}", payment.recipient_address());
        match payment.amount() {
            Some(amount) => {
                let zats = amount.into_u64();
                println!(
                    "   - Amount: {} zatoshis ({:.8} ZEC)",
                    zats,
                    zats as f64 / 1_0000_0000f64
                );
            }
            None => println!("   - Amount: not specified"),
        }
        if let Some(memo) = payment.memo() {
            println!("   - Memo: {}", render_memo(memo));
        }
        if let Some(label) = payment.label() {
            println!("   - Label: {}", label);
        }
        if let Some(message) = payment.message() {
            println!("   - Message: {}", message);
        }
        for (key, value) in payment.other_params() {
            println!("   - {}: {}", key, value);
        }
    }

    Ok(())
}

fn render_memo(memo_bytes: &MemoBytes) -> String {
    match Memo::try_from(memo_bytes) {
        Ok(Memo::Empty) => "empty".to_string(),
        Ok(Memo::Text(memo)) => format!("'{}'", String::from(memo)),
        Ok(memo) => format!("{:?}", memo),
        Err(e) => format!("invalid memo: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Invalid / empty input must error rather than print something
    /// misleading.
    #[test]
    fn empty_input_errors() {
        assert!(run("").is_err());
        assert!(run("   ").is_err());
    }

    #[test]
    fn unknown_input_errors() {
        let err = run("totally-not-a-zcash-thing").unwrap_err().to_string();
        assert!(
            err.contains("does not match any recognized"),
            "unexpected error: {}",
            err,
        );
    }

    #[test]
    fn hex_input_redirects_to_pczt_inspect() {
        // Any well-formed hex string should be recognised as hex and the
        // user should be redirected — we don't try to parse it here.
        let err = run("deadbeef").unwrap_err().to_string();
        assert!(
            err.contains("zao pczt inspect"),
            "unexpected error: {}",
            err,
        );
    }

    /// Mainnet Orchard-only UA derived from the canonical "abandon …
    /// about" test mnemonic (zip32 account 0). Pinned so this test
    /// doesn't depend on a network call. Same UA the firmware tests
    /// pin in `test_address_pinned_for_test_mnemonic`.
    #[test]
    fn orchard_only_mainnet_ua_inspects() {
        // Generate the UA at runtime so we don't have to hard-code a
        // long string that drifts if encodings change.
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        use zcash_address::unified::{self, Encoding};
        let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon about";
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(mnemonic, b"mnemonic", 2048, &mut seed)
            .unwrap();
        let account = zip32::AccountId::try_from(0u32).unwrap();
        let sk = SpendingKey::from_zip32_seed(&seed, 133, account).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let raw_addr = fvk.address_at(0u32, Scope::External);
        let ua = unified::Address::try_from_items(vec![unified::Receiver::Orchard(
            raw_addr.to_raw_address_bytes(),
        )])
        .unwrap()
        .encode(&NetworkType::Main);

        // We can't easily capture stdout in a unit test without extra
        // plumbing; just assert the dispatcher takes the address branch
        // (no error).
        assert!(run(&ua).is_ok());
    }

    /// Round-trip a UFVK string through the dispatcher.
    #[test]
    fn ufvk_inspects() {
        use orchard::keys::{FullViewingKey, SpendingKey};
        let mnemonic = b"abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon about";
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(mnemonic, b"mnemonic", 2048, &mut seed)
            .unwrap();
        let account = zip32::AccountId::try_from(0u32).unwrap();
        let sk = SpendingKey::from_zip32_seed(&seed, 133, account).unwrap();
        let fvk_bytes = FullViewingKey::from(&sk).to_bytes();
        let ufvk = crate::wallet::ufvk_string_from_orchard_fvk(NetworkType::Main, &fvk_bytes)
            .unwrap();
        assert!(run(&ufvk).is_ok());
    }
}
