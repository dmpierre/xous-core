//! ZcashApp IPC client for Xous.
//!
//! Provides a type-safe client for interacting with the zcashapp service
//! via Xous inter-process communication (scalar and memory messages).

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use num_traits::ToPrimitive;

use zcashapp_common::ZcashAppError;

#[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
use zcashapp_common::{ZcashAppOp, SERVER_NAME};

/// Map a wire status byte (as emitted by `services/zcashapp/src/serial.rs`'s
/// `error_to_status`) back into a `ZcashAppError`. Used to decode the
/// 2-byte error sentinel returned by `OP_SIGN_PCZT` over IPC.
fn map_status_to_error(status: u8) -> ZcashAppError {
    match status {
        0x00 => ZcashAppError::Success,
        0x01 => ZcashAppError::RejectedByUser,
        0x02 => ZcashAppError::InvalidOpcode,
        0x03 => ZcashAppError::InvalidParameter,
        0x04 => ZcashAppError::InvalidPczt, // STATUS_ERR_INVALID_DATA also funnels here
        0x05 => ZcashAppError::UnsupportedOperation,
        0x06 => ZcashAppError::InternalError,
        0x07 => ZcashAppError::CryptoError,
        0x08 => ZcashAppError::NoSeed,
        0x0D => ZcashAppError::SighashMismatch,
        _ => ZcashAppError::InternalError,
    }
}

/// Client for the zcashapp Xous service.
pub struct ZcashAppClient {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    conn: xous::CID,

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    _phantom: core::marker::PhantomData<()>,
}

impl ZcashAppClient {
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    pub fn new() -> Result<Self, ZcashAppError> {
        let xns = xous_names::XousNames::new()
            .map_err(|_| ZcashAppError::InternalError)?;
        let conn = xns
            .request_connection_blocking(SERVER_NAME)
            .map_err(|_| ZcashAppError::InternalError)?;
        Ok(Self { conn })
    }

    #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
    pub fn new() -> Result<Self, ZcashAppError> {
        Ok(Self {
            _phantom: core::marker::PhantomData,
        })
    }

    // =========================================================================
    // Scalar helpers
    // =========================================================================

    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_scalar(&self, op: ZcashAppOp) -> Result<usize, ZcashAppError> {
        let opcode = op.to_u32().ok_or(ZcashAppError::InternalError)? as usize;
        match xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(opcode, 0, 0, 0, 0),
        ) {
            Ok(xous::Result::Scalar1(val)) => Ok(val),
            Ok(xous::Result::Scalar2(val, _)) => Ok(val),
            Ok(_) => Ok(0),
            Err(_) => Err(ZcashAppError::InternalError),
        }
    }

    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_scalar2(&self, op: ZcashAppOp, arg1: usize, arg2: usize) -> Result<usize, ZcashAppError> {
        let opcode = op.to_u32().ok_or(ZcashAppError::InternalError)? as usize;
        match xous::send_message(
            self.conn,
            xous::Message::new_blocking_scalar(opcode, arg1, arg2, 0, 0),
        ) {
            Ok(xous::Result::Scalar1(val)) => Ok(val),
            Ok(xous::Result::Scalar2(val, _)) => Ok(val),
            Ok(_) => Ok(0),
            Err(_) => Err(ZcashAppError::InternalError),
        }
    }

    /// Send rkyv-serialized SerialFrameData via Buffer, get response back.
    #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
    fn send_buf(&self, op: ZcashAppOp, data: &[u8], buf_size: usize) -> Result<alloc::vec::Vec<u8>, ZcashAppError> {
        let opcode = op.to_u32().ok_or(ZcashAppError::InternalError)?;

        let request = zcashapp_common::SerialFrameData { data: data.to_vec() };
        let mut buf = xous_ipc::Buffer::new(buf_size.max(4096));
        buf.replace(request).map_err(|_| ZcashAppError::InternalError)?;
        buf.lend_mut(self.conn, opcode).map_err(|_| ZcashAppError::InternalError)?;

        match buf.to_original::<zcashapp_common::SerialFrameData, _>() {
            Ok(resp) => Ok(resp.data),
            Err(_) => Ok(alloc::vec::Vec::new()),
        }
    }

    // =========================================================================
    // Commands
    // =========================================================================

    /// Ping the service.
    pub fn ping(&self) -> Result<(), ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            self.send_scalar(ZcashAppOp::Ping)?;
            return Ok(());
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        Ok(())
    }

    /// Get configuration: returns (protocol_version, has_seed).
    pub fn get_config(&self) -> Result<(u32, bool), ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            let opcode = ZcashAppOp::GetConfig.to_u32().ok_or(ZcashAppError::InternalError)? as usize;
            match xous::send_message(
                self.conn,
                xous::Message::new_blocking_scalar(opcode, 0, 0, 0, 0),
            ) {
                Ok(xous::Result::Scalar2(version, has_seed)) => {
                    Ok((version as u32, has_seed != 0))
                }
                Ok(_) => Err(ZcashAppError::InternalError),
                Err(_) => Err(ZcashAppError::InternalError),
            }
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        Ok((1, false))
    }

    /// Generate a new mnemonic on the device.
    pub fn generate_mnemonic(&self) -> Result<(), ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            let result = self.send_scalar(ZcashAppOp::GenerateMnemonic)?;
            if result == 0 {
                return Ok(());
            }
            return Err(ZcashAppError::InternalError);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        Ok(())
    }

    /// Import a mnemonic phrase.
    pub fn import_mnemonic(&self, mnemonic: &str) -> Result<(), ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            let _buf = self.send_buf(
                ZcashAppOp::ImportMnemonic,
                mnemonic.as_bytes(),
                4096,
            )?;
            return Ok(());
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            let _ = mnemonic;
            Ok(())
        }
    }

    /// Clear the seed from memory.
    pub fn clear_seed(&self) -> Result<(), ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            let result = self.send_scalar(ZcashAppOp::ClearSeed)?;
            if result == 0 {
                return Ok(());
            }
            return Err(ZcashAppError::InternalError);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        Ok(())
    }

    /// Get Orchard address (43 bytes) for the given account.
    pub fn get_address(&self, account: u32) -> Result<[u8; 43], ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            let buf = self.send_buf(
                ZcashAppOp::GetOrchardAddress,
                &account.to_le_bytes(),
                256,
            )?;
            if buf.len() < 43 {
                return Err(ZcashAppError::InternalError);
            }
            let mut addr = [0u8; 43];
            addr.copy_from_slice(&buf[..43]);
            return Ok(addr);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            let _ = account;
            Err(ZcashAppError::UnsupportedOperation)
        }
    }

    /// Get Orchard Full Viewing Key (96 bytes) for the given account.
    pub fn get_fvk(&self, account: u32) -> Result<[u8; 96], ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            let buf = self.send_buf(
                ZcashAppOp::GetOrchardFVK,
                &account.to_le_bytes(),
                256,
            )?;
            if buf.len() < 96 {
                return Err(ZcashAppError::InternalError);
            }
            let mut fvk = [0u8; 96];
            fvk.copy_from_slice(&buf[..96]);
            return Ok(fvk);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            let _ = account;
            Err(ZcashAppError::UnsupportedOperation)
        }
    }

    /// Sign a PCZT. Returns the signed PCZT bytes on success.
    ///
    /// The device's IPC encoder uses a 2-byte sentinel `[0x00, status]` to
    /// signal errors (a valid signed PCZT always starts with the 4-byte
    /// "PCZT" magic, so the leading 0x00 is unambiguous). We decode that
    /// here back into a structured `ZcashAppError`.
    pub fn sign_pczt(&self, account: u32, sighash: &[u8; 32], pczt_bytes: &[u8]) -> Result<alloc::vec::Vec<u8>, ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            let mut payload = alloc::vec::Vec::with_capacity(4 + 32 + pczt_bytes.len());
            payload.extend_from_slice(&account.to_le_bytes());
            payload.extend_from_slice(sighash);
            payload.extend_from_slice(pczt_bytes);

            let buf = self.send_buf(
                ZcashAppOp::SignPczt,
                &payload,
                8192,
            )?;
            // Decode the error sentinel. We look for `[0x00, status]` where
            // `status` is one of the wire status codes the firmware emits.
            // 0x00 cannot be the first byte of a real PCZT (always starts
            // with "PCZT" = [0x50, ...]).
            if buf.len() == 2 && buf[0] == 0x00 {
                return Err(map_status_to_error(buf[1]));
            }
            return Ok(buf);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        {
            let _ = (account, sighash, pczt_bytes);
            Err(ZcashAppError::UnsupportedOperation)
        }
    }

    /// Check if device is ready (has seed).
    pub fn get_status(&self) -> Result<bool, ZcashAppError> {
        #[cfg(any(target_os = "xous", feature = "hosted-dabao"))]
        {
            let result = self.send_scalar(ZcashAppOp::GetPcztStatus)?;
            return Ok(result != 0);
        }
        #[cfg(not(any(target_os = "xous", feature = "hosted-dabao")))]
        Ok(false)
    }
}
