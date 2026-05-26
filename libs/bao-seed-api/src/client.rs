//! bao-seed client.
//!
//! Coin apps (and the on-device test harness) instantiate `BaoSeedClient`
//! and call typed methods. Each method dispatches via Xous IPC to the
//! bao-seed service and decodes the response.

use alloc::string::ToString;

use bao_seed_common::{
    BaoSeedError, BaoSeedOp, CompressedPubkey, GenerateRequest, GenerateResponse, ImportRequest,
    ImportResponse, ImportSeedBytesRequest, LifecycleResult, MnemonicWords, OrchardActionInput,
    OrchardFvkBytes, OrchardFvkRequest, OrchardSignRequest, OrchardSignResponse,
    Secp256k1PubkeyRequest, Secp256k1SignRequest, Secp256k1Signature, StatusResponse,
    Zip32SeedFingerprintBytes,
};

use alloc::vec::Vec;

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use bao_seed_common::SERVER_NAME;

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use num_traits::ToPrimitive;

use crate::error::ApiError;

extern crate alloc;

/// Client handle for the bao-seed service.
///
/// NOT `Send`/`Sync`. Each thread should construct its own.
pub struct BaoSeedClient {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    conn: xous::CID,
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    _phantom: core::marker::PhantomData<()>,
}

impl BaoSeedClient {
    /// Connect to the bao-seed service via xous-names.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    pub fn new() -> Result<Self, ApiError> {
        let xns = xous_names::XousNames::new()
            .map_err(|_| ApiError::ConnectionFailed("xous-names unavailable".to_string()))?;
        let conn = xns
            .request_connection_blocking(SERVER_NAME)
            .map_err(|_| ApiError::ConnectionFailed("bao-seed service not found".to_string()))?;
        Ok(Self { conn })
    }

    /// Host-build stub (no real IPC).
    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    pub fn new() -> Result<Self, ApiError> {
        Ok(Self { _phantom: core::marker::PhantomData })
    }

    // -----------------------------------------------------------------
    // Lifecycle (PR 1)
    // -----------------------------------------------------------------

    /// Get service status: protocol version, seed presence, fingerprint.
    pub fn status(&self) -> Result<StatusResponse, ApiError> {
        self.send_receive_memory::<(), StatusResponse>(BaoSeedOp::Status, &())
    }

    /// Cheap presence check — true if a seed is loaded.
    pub fn has_seed(&self) -> Result<bool, ApiError> {
        let (err_code, payload) = self.send_blocking_scalar2(BaoSeedOp::HasSeed)?;
        check_err(err_code)?;
        Ok(payload != 0)
    }

    /// Generate a new seed from hardware TRNG. Returns mnemonic words +
    /// vault-internal fingerprint. Callers MUST show the mnemonic to the
    /// user and drop it after — bao-seed does not re-export it.
    pub fn generate(&self, word_count: u8) -> Result<GenerateResponse, ApiError> {
        let req = GenerateRequest { word_count };
        let result: LifecycleResult<GenerateResponse> =
            self.send_receive_memory(BaoSeedOp::Generate, &req)?;
        result_into(result)
    }

    /// Import an existing BIP-39 mnemonic. Returns the vault-internal
    /// fingerprint on success.
    pub fn import(&self, words: MnemonicWords) -> Result<ImportResponse, ApiError> {
        let req = ImportRequest { words };
        let result: LifecycleResult<ImportResponse> =
            self.send_receive_memory(BaoSeedOp::Import, &req)?;
        result_into(result)
    }

    /// Import a raw 64-byte master seed, bypassing BIP-39 derivation.
    /// Used by callers that already hold the derived seed (encrypted-
    /// import flow, dev-mode seed injection). Refuses if a seed is
    /// already loaded.
    pub fn import_seed_bytes(&self, seed: &[u8; 64]) -> Result<ImportResponse, ApiError> {
        let req = ImportSeedBytesRequest { seed: *seed };
        let result: LifecycleResult<ImportResponse> =
            self.send_receive_memory(BaoSeedOp::ImportSeedBytes, &req)?;
        result_into(result)
    }

    /// Wipe the seed from RAM and persistent storage. Idempotent.
    pub fn wipe(&self) -> Result<(), ApiError> {
        let err_code = self.send_blocking_scalar1(BaoSeedOp::Wipe)?;
        check_err(err_code)?;
        Ok(())
    }

    /// Compute the 32-byte ZIP-32 SeedFingerprint over the loaded seed.
    ///
    /// Coin apps that need to publish a stable seed identifier to a
    /// companion wallet should call this — bao-seed retains the seed.
    /// Returns `BaoSeedError::NoSeed` if no seed is loaded.
    pub fn zip32_seed_fingerprint(&self) -> Result<Zip32SeedFingerprintBytes, ApiError> {
        let result: LifecycleResult<Zip32SeedFingerprintBytes> =
            self.send_receive_memory(BaoSeedOp::Zip32SeedFingerprint, &())?;
        result_into(result)
    }

    // -----------------------------------------------------------------
    // secp256k1 (PR 2)
    // -----------------------------------------------------------------

    /// Derive the compressed secp256k1 pubkey at `path`. Requires a
    /// loaded seed; returns `BaoSeedError::NoSeed` otherwise.
    ///
    /// `path` components: bit 31 set marks hardened. Caller is
    /// responsible for policy (e.g. ethapp restricts to `m/44'/60'/…`).
    pub fn secp256k1_get_pubkey(&self, path: Vec<u32>) -> Result<CompressedPubkey, ApiError> {
        let req = Secp256k1PubkeyRequest { path };
        let result: LifecycleResult<CompressedPubkey> =
            self.send_receive_memory(BaoSeedOp::Secp256k1GetPubkey, &req)?;
        result_into(result)
    }

    /// Sign a 32-byte digest at `path`. Returns (r, s, recovery_id).
    pub fn secp256k1_sign(
        &self,
        path: Vec<u32>,
        hash: [u8; 32],
    ) -> Result<Secp256k1Signature, ApiError> {
        let req = Secp256k1SignRequest { path, hash };
        let result: LifecycleResult<Secp256k1Signature> =
            self.send_receive_memory(BaoSeedOp::Secp256k1Sign, &req)?;
        result_into(result)
    }

    // -----------------------------------------------------------------
    // Orchard / Pallas (PR 3)
    // -----------------------------------------------------------------

    /// Derive the 96-byte Orchard FullViewingKey for (coin_type, account).
    pub fn orchard_get_fvk(
        &self,
        coin_type: u32,
        account: u32,
    ) -> Result<OrchardFvkBytes, ApiError> {
        let req = OrchardFvkRequest { coin_type, account };
        let result: LifecycleResult<OrchardFvkBytes> =
            self.send_receive_memory(BaoSeedOp::OrchardGetFvk, &req)?;
        result_into(result)
    }

    /// Sign a batch of Orchard PCZT actions for (coin_type, account).
    /// Each input action must carry its alpha-scalar + expected rk;
    /// bao-seed signs only actions whose rk matches our wallet.
    pub fn orchard_sign(
        &self,
        coin_type: u32,
        account: u32,
        sighash: [u8; 32],
        actions: Vec<OrchardActionInput>,
    ) -> Result<OrchardSignResponse, ApiError> {
        let req = OrchardSignRequest { coin_type, account, sighash, actions };
        let result: LifecycleResult<OrchardSignResponse> =
            self.send_receive_memory(BaoSeedOp::OrchardSign, &req)?;
        result_into(result)
    }

    // -----------------------------------------------------------------
    // IPC helpers
    // -----------------------------------------------------------------

    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_receive_memory<Req, Resp>(
        &self,
        op: BaoSeedOp,
        req: &Req,
    ) -> Result<Resp, ApiError>
    where
        Req: Clone
            + for<'b, 'a> rkyv::Serialize<
                rkyv::rancor::Strategy<
                    rkyv::ser::Serializer<
                        rkyv::ser::writer::Buffer<'b>,
                        rkyv::ser::allocator::SubAllocator<'a>,
                        (),
                    >,
                    rkyv::rancor::Failure,
                >,
            >,
        Resp: rkyv::Archive,
        <Resp as rkyv::Archive>::Archived: rkyv::Portable
            + rkyv::Deserialize<
                Resp,
                rkyv::rancor::Strategy<rkyv::de::Pool, rkyv::rancor::Error>,
            >,
    {
        let opcode = op
            .to_u32()
            .ok_or_else(|| ApiError::SerializationFailed("opcode".to_string()))?;

        // Always allocate one page so even zero-sized requests like `()`
        // succeed, and the buffer has room for the response.
        let mut buf = xous_ipc::Buffer::new(4096);
        buf.replace(req.clone())
            .map_err(|_| ApiError::SerializationFailed("Buffer serialize".to_string()))?;

        buf.lend_mut(self.conn, opcode)
            .map_err(|e| ApiError::Ipc(alloc::format!("{:?}", e)))?;

        buf.to_original::<Resp, _>()
            .map_err(|_| ApiError::InvalidResponse("Buffer deserialize".to_string()))
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    fn send_receive_memory<Req, Resp>(
        &self,
        _op: BaoSeedOp,
        _req: &Req,
    ) -> Result<Resp, ApiError> {
        Err(ApiError::ConnectionFailed("no IPC on host build".to_string()))
    }

    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_blocking_scalar1(&self, op: BaoSeedOp) -> Result<usize, ApiError> {
        let opcode = op
            .to_u32()
            .ok_or_else(|| ApiError::SerializationFailed("opcode".to_string()))?
            as usize;
        let result = xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(opcode, 0, 0, 0, 0),
        )
        .map_err(|e| ApiError::Ipc(alloc::format!("send_message: {:?}", e)))?;
        if let xous::Result::Scalar1(v) = result {
            Ok(v)
        } else {
            Err(ApiError::InvalidResponse(
                "expected Scalar1 reply".to_string(),
            ))
        }
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    fn send_blocking_scalar1(&self, _op: BaoSeedOp) -> Result<usize, ApiError> {
        Err(ApiError::ConnectionFailed("no IPC on host build".to_string()))
    }

    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_blocking_scalar2(&self, op: BaoSeedOp) -> Result<(usize, usize), ApiError> {
        let opcode = op
            .to_u32()
            .ok_or_else(|| ApiError::SerializationFailed("opcode".to_string()))?
            as usize;
        let result = xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(opcode, 0, 0, 0, 0),
        )
        .map_err(|e| ApiError::Ipc(alloc::format!("send_message: {:?}", e)))?;
        if let xous::Result::Scalar2(a, b) = result {
            Ok((a, b))
        } else {
            Err(ApiError::InvalidResponse(
                "expected Scalar2 reply".to_string(),
            ))
        }
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    fn send_blocking_scalar2(&self, _op: BaoSeedOp) -> Result<(usize, usize), ApiError> {
        Err(ApiError::ConnectionFailed("no IPC on host build".to_string()))
    }
}

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
impl Drop for BaoSeedClient {
    fn drop(&mut self) {
        let _ = xous::send_message(
            self.conn,
            xous::Message::new_scalar(BaoSeedOp::Disconnect as usize, 0, 0, 0, 0),
        );
    }
}

// ---- Result helpers --------------------------------------------------------

fn check_err(err_code: usize) -> Result<(), ApiError> {
    use num_traits::FromPrimitive;
    let e = BaoSeedError::from_u32(err_code as u32).unwrap_or(BaoSeedError::Internal);
    if e == BaoSeedError::Ok {
        Ok(())
    } else {
        Err(ApiError::Service(e))
    }
}

fn result_into<T>(r: LifecycleResult<T>) -> Result<T, ApiError> {
    use num_traits::FromPrimitive;
    match r {
        LifecycleResult::Ok(v) => Ok(v),
        LifecycleResult::Err(code) => {
            let e = BaoSeedError::from_u32(code).unwrap_or(BaoSeedError::Internal);
            Err(ApiError::Service(e))
        }
    }
}
