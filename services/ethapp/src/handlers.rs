//! Message handlers for the ethapp service.
//!
//! Each handler processes a specific opcode and returns a response.
//! Handlers are responsible for:
//! - Deserializing request data
//! - Validating parameters
//! - Performing the operation
//! - Serializing and returning the response

#[cfg(target_os = "xous")]
use alloc::string::String;
#[cfg(target_os = "xous")]
use alloc::vec::Vec;

#[cfg(not(target_os = "xous"))]
use std::string::String;
#[cfg(not(target_os = "xous"))]
use std::vec::Vec;

use ethapp_common::{
    AppConfiguration, Bip32Path, EthAppError, Hash256, ProvideTokenInfoRequest,
    PublicKeyResponse, Signature, SignEip712HashedRequest, SignEip712MessageRequest,
    SignPersonalMessageRequest, SignTransactionRequest, TransactionType,
};
use rkyv::{Deserialize, Serialize};

use crate::crypto::{
    derive_private_key, format_address_checksummed, get_compressed_pubkey, keccak256,
    public_key_to_address, sign_eth, sign_eip712, sign_personal_message, get_public_key,
};
use crate::parsing::{ParsedTransaction, TransactionParser};
use crate::platform::Platform;
use crate::state::ServiceState;
use crate::ui;

// =============================================================================
// Helper Functions
// =============================================================================

/// Returns a success scalar response.
#[cfg(target_os = "xous")]
pub fn return_success(msg: xous::MessageEnvelope) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, 0)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(not(target_os = "xous"))]
pub fn return_success(_msg: ()) -> Result<(), EthAppError> {
    Ok(())
}

/// Returns an error scalar response.
#[cfg(target_os = "xous")]
pub fn return_error(msg: xous::MessageEnvelope, error: EthAppError) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, error.code() as usize)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(not(target_os = "xous"))]
pub fn return_error(_msg: (), error: EthAppError) -> Result<(), EthAppError> {
    Err(error)
}

/// Get the development seed for testing.
#[cfg(feature = "dev-mode")]
fn get_seed() -> crate::crypto::Seed {
    crate::crypto::get_dev_seed()
}

#[cfg(not(feature = "dev-mode"))]
fn get_seed() -> Result<crate::crypto::Seed, EthAppError> {
    // In production, this would load from secure storage
    Err(EthAppError::UnsupportedOperation)
}

// =============================================================================
// Configuration Handlers
// =============================================================================

/// Handle GetAppConfiguration request.
#[cfg(target_os = "xous")]
pub fn handle_get_app_configuration(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let config = state.config.clone();

    // Serialize response
    let bytes = rkyv::to_bytes::<_, 256>(&config)
        .map_err(|_| EthAppError::SerializationError)?;

    // Return via memory message
    let mut buffer = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    buffer.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_app_configuration(
    state: &mut ServiceState,
    _msg: (),
) -> Result<AppConfiguration, EthAppError> {
    Ok(state.config.clone())
}

/// Handle GetChallenge request.
#[cfg(target_os = "xous")]
pub fn handle_get_challenge(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;

    let mut challenge = [0u8; 32];
    state.platform.rng_fill_bytes(&mut challenge)?;

    let mut buffer = Buffer::into_buf(challenge.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    buffer.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_challenge(
    state: &mut ServiceState,
    _msg: (),
) -> Result<[u8; 32], EthAppError> {
    let mut challenge = [0u8; 32];
    state.platform.rng_fill_bytes(&mut challenge)?;
    Ok(challenge)
}

// =============================================================================
// Transaction Signing Handlers
// =============================================================================

/// Handle SignTransaction request.
#[cfg(target_os = "xous")]
pub fn handle_sign_transaction(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;
    use xous::Message;

    // Extract request from memory message
    let buffer = match &msg.body {
        Message::MutableBorrow(b) | Message::Borrow(b) => {
            unsafe { Buffer::from_memory_message(b) }
                .map_err(|_| EthAppError::InvalidData)?
        }
        _ => return Err(EthAppError::InvalidData),
    };

    let request: SignTransactionRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    // Process the signing request
    let signature = process_sign_transaction(state, &request)?;

    // Serialize and return signature
    let bytes = rkyv::to_bytes::<_, 128>(&signature)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    state.record_sign_success();
    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_transaction(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

/// Process a sign transaction request.
fn process_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Parse transaction
    let tx = TransactionParser::parse(&request.tx_data)
        .map_err(|_| EthAppError::InvalidTransaction)?;

    // Display transaction for user confirmation
    if !ui::display_transaction(&state.platform, &tx, false)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key
    #[cfg(feature = "dev-mode")]
    let seed = get_seed();
    #[cfg(not(feature = "dev-mode"))]
    let seed = get_seed()?;

    let signing_key = derive_private_key(&seed, &request.path)?;

    // Sign the transaction
    let signature = sign_eth(&signing_key, &tx.sign_hash, tx.chain_id, tx.tx_type)?;

    state.platform.show_info(true, "Transaction signed");

    Ok(signature)
}

/// Handle ClearSignTransaction request.
#[cfg(target_os = "xous")]
pub fn handle_clear_sign_transaction(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    // For now, delegate to regular sign transaction
    // Full implementation would use cached metadata
    handle_sign_transaction(state, msg)
}

#[cfg(not(target_os = "xous"))]
pub fn handle_clear_sign_transaction(
    state: &mut ServiceState,
    request: &SignTransactionRequest,
) -> Result<Signature, EthAppError> {
    handle_sign_transaction(state, request)
}

// =============================================================================
// Message Signing Handlers
// =============================================================================

/// Handle SignPersonalMessage request.
#[cfg(target_os = "xous")]
pub fn handle_sign_personal_message(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;
    use xous::Message;

    let buffer = match &msg.body {
        Message::MutableBorrow(b) | Message::Borrow(b) => {
            unsafe { Buffer::from_memory_message(b) }
                .map_err(|_| EthAppError::InvalidData)?
        }
        _ => return Err(EthAppError::InvalidData),
    };

    let request: SignPersonalMessageRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let signature = process_sign_personal_message(state, &request)?;

    let bytes = rkyv::to_bytes::<_, 128>(&signature)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    state.record_sign_success();
    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_sign_personal_message(
    state: &mut ServiceState,
    request: &SignPersonalMessageRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_personal_message(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_personal_message(
    state: &mut ServiceState,
    request: &SignPersonalMessageRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Validate message size
    if request.message.is_empty() || request.message.len() > 65536 {
        return Err(EthAppError::InvalidMessage);
    }

    // Display message for confirmation
    if !ui::display_personal_message(&state.platform, &request.message)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key
    #[cfg(feature = "dev-mode")]
    let seed = get_seed();
    #[cfg(not(feature = "dev-mode"))]
    let seed = get_seed()?;

    let signing_key = derive_private_key(&seed, &request.path)?;

    // Sign the message
    let signature = sign_personal_message(&signing_key, &request.message)?;

    state.platform.show_info(true, "Message signed");

    Ok(signature)
}

/// Handle SignEip712Hashed request.
#[cfg(target_os = "xous")]
pub fn handle_sign_eip712_hashed(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;
    use xous::Message;

    // Check if blind signing is enabled
    if !state.config.blind_signing_enabled {
        return Err(EthAppError::BlindSigningDisabled);
    }

    let buffer = match &msg.body {
        Message::MutableBorrow(b) | Message::Borrow(b) => {
            unsafe { Buffer::from_memory_message(b) }
                .map_err(|_| EthAppError::InvalidData)?
        }
        _ => return Err(EthAppError::InvalidData),
    };

    let request: SignEip712HashedRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let signature = process_sign_eip712_hashed(state, &request)?;

    let bytes = rkyv::to_bytes::<_, 128>(&signature)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    state.record_sign_success();
    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_sign_eip712_hashed(
    state: &mut ServiceState,
    request: &SignEip712HashedRequest,
) -> Result<Signature, EthAppError> {
    if !state.config.blind_signing_enabled {
        return Err(EthAppError::BlindSigningDisabled);
    }
    let signature = process_sign_eip712_hashed(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_eip712_hashed(
    state: &mut ServiceState,
    request: &SignEip712HashedRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Display for confirmation (blind signing warning)
    if !ui::display_eip712_hashed(&state.platform, &request.domain_hash, &request.message_hash)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key
    #[cfg(feature = "dev-mode")]
    let seed = get_seed();
    #[cfg(not(feature = "dev-mode"))]
    let seed = get_seed()?;

    let signing_key = derive_private_key(&seed, &request.path)?;

    // Sign
    let signature = sign_eip712(&signing_key, &request.domain_hash, &request.message_hash)?;

    state.platform.show_info(true, "Typed data signed");

    Ok(signature)
}

/// Handle SignEip712Message request.
#[cfg(target_os = "xous")]
pub fn handle_sign_eip712_message(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;
    use xous::Message;

    let buffer = match &msg.body {
        Message::MutableBorrow(b) | Message::Borrow(b) => {
            unsafe { Buffer::from_memory_message(b) }
                .map_err(|_| EthAppError::InvalidData)?
        }
        _ => return Err(EthAppError::InvalidData),
    };

    let request: SignEip712MessageRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let signature = process_sign_eip712_message(state, &request)?;

    let bytes = rkyv::to_bytes::<_, 128>(&signature)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    state.record_sign_success();
    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_sign_eip712_message(
    state: &mut ServiceState,
    request: &SignEip712MessageRequest,
) -> Result<Signature, EthAppError> {
    let signature = process_sign_eip712_message(state, request)?;
    state.record_sign_success();
    Ok(signature)
}

fn process_sign_eip712_message(
    state: &mut ServiceState,
    request: &SignEip712MessageRequest,
) -> Result<Signature, EthAppError> {
    // Validate path
    if !request.path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    // Validate typed data size
    if request.typed_data.is_empty() || request.typed_data.len() > 65536 {
        return Err(EthAppError::InvalidTypedData);
    }

    // Parse typed data - minimal implementation expects pre-computed hashes
    if request.typed_data.len() < 64 {
        return Err(EthAppError::InvalidTypedData);
    }

    let mut domain_hash = [0u8; 32];
    let mut message_hash = [0u8; 32];
    domain_hash.copy_from_slice(&request.typed_data[..32]);
    message_hash.copy_from_slice(&request.typed_data[32..64]);

    // Display for confirmation
    if !ui::display_eip712_message(&state.platform, &domain_hash, &message_hash)? {
        state.record_sign_rejected();
        return Err(EthAppError::RejectedByUser);
    }

    // Get seed and derive key
    #[cfg(feature = "dev-mode")]
    let seed = get_seed();
    #[cfg(not(feature = "dev-mode"))]
    let seed = get_seed()?;

    let signing_key = derive_private_key(&seed, &request.path)?;

    // Sign
    let signature = sign_eip712(&signing_key, &domain_hash, &message_hash)?;

    state.platform.show_info(true, "Typed data signed");

    Ok(signature)
}

// =============================================================================
// Metadata Handlers
// =============================================================================

/// Handle ProvideErc20TokenInfo request.
#[cfg(target_os = "xous")]
pub fn handle_provide_erc20_token_info(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;
    use xous::Message;

    let buffer = match &msg.body {
        Message::MutableBorrow(b) | Message::Borrow(b) => {
            unsafe { Buffer::from_memory_message(b) }
                .map_err(|_| EthAppError::InvalidData)?
        }
        _ => return Err(EthAppError::InvalidData),
    };

    let request: ProvideTokenInfoRequest = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    // Validate basic constraints
    if request.info.ticker.is_empty() || request.info.ticker.len() > 12 {
        return Err(EthAppError::InvalidParameter);
    }

    if request.info.decimals > 36 {
        return Err(EthAppError::InvalidParameter);
    }

    // TODO: Verify signature against trusted public key
    // For now, accept without verification (mark as unverified)

    state.cache_token_info(request.info);

    xous::return_scalar(msg.sender, 1) // accepted = true
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(not(target_os = "xous"))]
pub fn handle_provide_erc20_token_info(
    state: &mut ServiceState,
    request: &ProvideTokenInfoRequest,
) -> Result<bool, EthAppError> {
    if request.info.ticker.is_empty() || request.info.ticker.len() > 12 {
        return Err(EthAppError::InvalidParameter);
    }
    if request.info.decimals > 36 {
        return Err(EthAppError::InvalidParameter);
    }
    state.cache_token_info(request.info.clone());
    Ok(true)
}

// Stub handlers for other metadata operations
#[cfg(target_os = "xous")]
pub fn handle_provide_nft_info(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, 1)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(target_os = "xous")]
pub fn handle_provide_domain_name(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, 1)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(target_os = "xous")]
pub fn handle_load_contract_method_info(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    xous::return_scalar(msg.sender, 1)
        .map_err(|_| EthAppError::InternalError)
}

#[cfg(target_os = "xous")]
pub fn handle_by_contract_address_and_chain(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous::Message;

    // Extract chain_id and address from scalar message
    if let Message::Scalar(s) = &msg.body {
        let chain_id = ((s.arg1 as u64) << 32) | (s.arg2 as u64);
        // Address would need to be passed via memory message for full 20 bytes
        // For now, use first 8 bytes from args
        let mut address = [0u8; 20];
        address[..8].copy_from_slice(&(s.arg3 as u64).to_be_bytes());
        address[8..16].copy_from_slice(&(s.arg4 as u64).to_be_bytes());

        state.set_context(chain_id, address);
    }

    xous::return_scalar(msg.sender, 1)
        .map_err(|_| EthAppError::InternalError)
}

// =============================================================================
// Key Operation Handlers
// =============================================================================

/// Handle GetPublicKey request.
#[cfg(target_os = "xous")]
pub fn handle_get_public_key(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;
    use xous::Message;

    let buffer = match &msg.body {
        Message::MutableBorrow(b) | Message::Borrow(b) => {
            unsafe { Buffer::from_memory_message(b) }
                .map_err(|_| EthAppError::InvalidData)?
        }
        _ => return Err(EthAppError::InvalidData),
    };

    let path: Bip32Path = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let response = process_get_public_key(&path)?;

    let bytes = rkyv::to_bytes::<_, 128>(&response)
        .map_err(|_| EthAppError::SerializationError)?;

    let mut response_buf = Buffer::into_buf(bytes.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response_buf.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_public_key(
    _state: &mut ServiceState,
    path: &Bip32Path,
) -> Result<PublicKeyResponse, EthAppError> {
    process_get_public_key(path)
}

fn process_get_public_key(path: &Bip32Path) -> Result<PublicKeyResponse, EthAppError> {
    if !path.is_valid_ethereum_path() {
        return Err(EthAppError::InvalidDerivationPath);
    }

    #[cfg(feature = "dev-mode")]
    let seed = get_seed();
    #[cfg(not(feature = "dev-mode"))]
    let seed = get_seed()?;

    let signing_key = derive_private_key(&seed, path)?;
    let pubkey = get_compressed_pubkey(&signing_key);
    let address = public_key_to_address(&get_public_key(&signing_key));

    Ok(PublicKeyResponse { pubkey, address })
}

/// Handle GetAddress request.
#[cfg(target_os = "xous")]
pub fn handle_get_address(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    use xous_ipc::Buffer;
    use xous::Message;

    let buffer = match &msg.body {
        Message::MutableBorrow(b) | Message::Borrow(b) => {
            unsafe { Buffer::from_memory_message(b) }
                .map_err(|_| EthAppError::InvalidData)?
        }
        _ => return Err(EthAppError::InvalidData),
    };

    let path: Bip32Path = buffer.to_original()
        .map_err(|_| EthAppError::SerializationError)?;

    let response = process_get_public_key(&path)?;

    let mut response_buf = Buffer::into_buf(response.address.to_vec())
        .map_err(|_| EthAppError::SerializationError)?;

    response_buf.replace(msg.body)
        .map_err(|_| EthAppError::InternalError)?;

    Ok(())
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_address(
    _state: &mut ServiceState,
    path: &Bip32Path,
) -> Result<[u8; 20], EthAppError> {
    let response = process_get_public_key(path)?;
    Ok(response.address)
}

// =============================================================================
// Statistics Handler
// =============================================================================

#[cfg(target_os = "xous")]
pub fn handle_get_stats(
    state: &mut ServiceState,
    msg: xous::MessageEnvelope,
) -> Result<(), EthAppError> {
    let stats = state.get_stats();

    // Return stats as scalar values
    xous::return_scalar2(
        msg.sender,
        stats.signs_completed as usize,
        stats.signs_rejected as usize,
    ).map_err(|_| EthAppError::InternalError)
}

#[cfg(not(target_os = "xous"))]
pub fn handle_get_stats(
    state: &mut ServiceState,
    _msg: (),
) -> Result<(u64, u64, u64), EthAppError> {
    let stats = state.get_stats();
    Ok((stats.signs_completed, stats.signs_rejected, stats.errors))
}
