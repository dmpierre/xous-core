//! Serial transport layer for communicating with the zcashapp service
//! on a Baochip-1x device over USB CDC-ACM.
//!
//! Wire protocol (framed over serial):
//!   Request:  [0xE8] [length: u16 LE] [opcode: u8] [payload...]
//!   Response: [0xE8] [length: u16 LE] [status: u8] [payload...]
//!
//! Magic byte 0xE8 distinguishes zcashapp frames from ethapp (0xE7).

use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};

const MAGIC: u8 = 0xE8;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const BAUD_RATE: u32 = 115200;

/// USB Vendor/Product IDs for Baochip-1x (Precursor) device.
const VID: u16 = 0x1209;
const PID: u16 = 0x3613;

/// Status codes in responses.
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR_REJECTED: u8 = 0x01;
pub const STATUS_ERR_INVALID_OPCODE: u8 = 0x02;
pub const STATUS_ERR_NO_SEED: u8 = 0x08;

pub struct Transport {
    port: Box<dyn serialport::SerialPort>,
}

impl Transport {
    /// Open a connection to the device.
    ///
    /// If `path` is provided, use that serial port path directly.
    /// Otherwise, auto-detect the device by USB VID/PID.
    pub fn open(path: Option<&str>) -> Result<Self> {
        let port_name = match path {
            Some(p) => p.to_string(),
            None => auto_detect()?,
        };

        let port = serialport::new(&port_name, BAUD_RATE)
            .timeout(DEFAULT_TIMEOUT)
            .open()
            .with_context(|| format!("Failed to open serial port: {}", port_name))?;

        Ok(Self { port })
    }

    /// Send a command and receive a response.
    ///
    /// Returns (status, payload).
    pub fn command(&mut self, opcode: u8, payload: &[u8]) -> Result<(u8, Vec<u8>)> {
        self.send_frame(opcode, payload)?;
        self.receive_frame()
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let frame = encode_frame(opcode, payload)?;
        // Send in chunks to avoid overwhelming the device's USB CDC-ACM buffer.
        // The device receives data in USB packets (typically 64 bytes) and
        // processes them via IRQ. Large writes can cause data loss.
        const CHUNK_SIZE: usize = 64;
        for chunk in frame.chunks(CHUNK_SIZE) {
            self.port.write_all(chunk)?;
            self.port.flush()?;
            if frame.len() > CHUNK_SIZE {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        Ok(())
    }

    fn receive_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        decode_frame(&mut *self.port)
    }
}

/// Build a wire-format frame for a request: `[MAGIC][len LE u16][opcode][payload]`.
///
/// `len` covers `opcode + payload`. Returns an error if the frame would exceed
/// the 16-bit length limit.
pub fn encode_frame(opcode: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let length = 1 + payload.len();
    if length > 0xFFFF {
        bail!("Payload too large: {} bytes", payload.len());
    }
    let mut frame = Vec::with_capacity(3 + length);
    frame.push(MAGIC);
    frame.extend_from_slice(&(length as u16).to_le_bytes());
    frame.push(opcode);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Read a single response frame from `reader`, skipping bytes until MAGIC is
/// found. Returns `(status, payload)`. Errors if the framed length is zero
/// or the underlying read fails.
pub fn decode_frame<R: Read + ?Sized>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte)?;
        if byte[0] == MAGIC {
            break;
        }
    }

    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf)?;
    let length = u16::from_le_bytes(len_buf) as usize;

    if length == 0 {
        bail!("Received empty frame");
    }

    let mut data = vec![0u8; length];
    reader.read_exact(&mut data)?;

    let status = data[0];
    let payload = data[1..].to_vec();

    Ok((status, payload))
}

fn auto_detect() -> Result<String> {
    if let Ok(ports) = serialport::available_ports() {
        for port in &ports {
            if let serialport::SerialPortType::UsbPort(info) = &port.port_type {
                if info.vid == VID && info.pid == PID {
                    return Ok(port.port_name.clone());
                }
            }
        }
        for port in &ports {
            if port.port_name.contains("ttyACM") || port.port_name.contains("cu.usbmodem") {
                return Ok(port.port_name.clone());
            }
        }
    }

    for path in &["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM2"] {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    bail!(
        "No Baochip-1x device found. Connect the device or specify --port \
         (e.g. --port /dev/ttyACM0)."
    )
}

pub fn status_message(status: u8) -> &'static str {
    match status {
        STATUS_OK => "OK",
        STATUS_ERR_REJECTED => "Rejected by user",
        0x02 => "Invalid opcode",
        0x03 => "Invalid parameter",
        0x04 => "Invalid data",
        0x05 => "Unsupported",
        0x06 => "Internal error",
        0x07 => "Crypto error",
        STATUS_ERR_NO_SEED => "No seed loaded",
        _ => "Unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn encode_frame_layout() {
        let frame = encode_frame(0xFF, &[]).unwrap();
        // [MAGIC=0xE8][len=1 LE][opcode=0xFF]
        assert_eq!(frame, vec![0xE8, 0x01, 0x00, 0xFF]);

        let frame = encode_frame(0x94, &[0xAA, 0xBB, 0xCC]).unwrap();
        // [0xE8][len=4 LE][opcode][payload]
        assert_eq!(frame, vec![0xE8, 0x04, 0x00, 0x94, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn encode_frame_length_is_little_endian() {
        // 256-byte payload + 1-byte opcode = 257 (0x0101) → LE is [0x01, 0x01]
        let payload = vec![0u8; 256];
        let frame = encode_frame(0x90, &payload).unwrap();
        assert_eq!(&frame[0..3], &[0xE8, 0x01, 0x01]);
        assert_eq!(frame[3], 0x90);
        assert_eq!(frame.len(), 3 + 257);
    }

    #[test]
    fn encode_frame_max_size_accepted() {
        // 0xFFFE-byte payload + 1-byte opcode = 0xFFFF (max u16).
        let payload = vec![0u8; 0xFFFE];
        let frame = encode_frame(0x94, &payload).unwrap();
        // First three bytes = [magic][0xFF][0xFF]
        assert_eq!(&frame[0..3], &[0xE8, 0xFF, 0xFF]);
        assert_eq!(frame.len(), 3 + 0xFFFF);
    }

    #[test]
    fn encode_frame_overflow_rejected() {
        // 0xFFFF-byte payload + 1-byte opcode = 0x10000 — overflows u16.
        let payload = vec![0u8; 0xFFFF];
        assert!(encode_frame(0x94, &payload).is_err());
    }

    #[test]
    fn decode_frame_round_trip_empty_payload() {
        let frame = encode_frame(0x90, &[]).unwrap();
        // Simulate device response with status=OK and no payload.
        let resp = encode_frame(STATUS_OK, &[]).unwrap();
        let mut cursor = Cursor::new(resp);
        let (status, payload) = decode_frame(&mut cursor).unwrap();
        assert_eq!(status, STATUS_OK);
        assert!(payload.is_empty());
        // The original encoded request frame is unchanged.
        assert_eq!(frame[0], 0xE8);
    }

    #[test]
    fn decode_frame_round_trip_with_payload() {
        let resp = encode_frame(STATUS_OK, &[0x01, 0x02, 0x03, 0x04]).unwrap();
        let mut cursor = Cursor::new(resp);
        let (status, payload) = decode_frame(&mut cursor).unwrap();
        assert_eq!(status, STATUS_OK);
        assert_eq!(payload, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn decode_frame_skips_garbage_before_magic() {
        // Garbage bytes followed by a valid frame.
        let mut bytes: Vec<u8> = vec![0x00, 0xAB, 0xCD, 0xEF, 0x42];
        bytes.extend(encode_frame(STATUS_ERR_NO_SEED, &[]).unwrap());
        let mut cursor = Cursor::new(bytes);
        let (status, payload) = decode_frame(&mut cursor).unwrap();
        assert_eq!(status, STATUS_ERR_NO_SEED);
        assert!(payload.is_empty());
    }

    #[test]
    fn decode_frame_zero_length_rejected() {
        // Manually craft a zero-length frame.
        let bytes = vec![0xE8, 0x00, 0x00];
        let mut cursor = Cursor::new(bytes);
        let err = decode_frame(&mut cursor).unwrap_err();
        assert!(
            err.to_string().contains("empty frame"),
            "expected empty-frame error, got: {}",
            err,
        );
    }

    #[test]
    fn decode_frame_truncated_length_errs() {
        // Magic byte present, but only one length byte before EOF.
        let bytes = vec![0xE8, 0x05];
        let mut cursor = Cursor::new(bytes);
        // io::Error of kind UnexpectedEof — surfaced as "failed to fill
        // whole buffer" by `read_exact`.
        assert!(decode_frame(&mut cursor).is_err());
    }

    #[test]
    fn decode_frame_truncated_payload_errs() {
        // Magic + length=10 LE + only 3 payload bytes.
        let bytes = vec![0xE8, 0x0A, 0x00, 0x00, 0x01, 0x02];
        let mut cursor = Cursor::new(bytes);
        assert!(decode_frame(&mut cursor).is_err());
    }

    #[test]
    fn decode_frame_handles_chunk_boundary() {
        // Build a frame straddling two ChunkedReader reads.
        let resp_payload = vec![0x42; 200];
        let resp = encode_frame(STATUS_OK, &resp_payload).unwrap();
        let mut chunked = ChunkedReader::new(resp.clone(), 17);
        let (status, payload) = decode_frame(&mut chunked).unwrap();
        assert_eq!(status, STATUS_OK);
        assert_eq!(payload, resp_payload);
    }

    #[test]
    fn round_trip_request_response_pair() {
        // Encode a sign-pczt request, then decode its response side.
        let req_payload = vec![0u8; 36 + 100];
        let req = encode_frame(0x94, &req_payload).unwrap();
        // Reparse the request shape.
        assert_eq!(req[0], 0xE8);
        let len = u16::from_le_bytes([req[1], req[2]]);
        assert_eq!(len as usize, 1 + req_payload.len());
        assert_eq!(req[3], 0x94);
        assert_eq!(&req[4..], &req_payload[..]);

        // Build a response frame and decode it.
        let resp = encode_frame(STATUS_OK, &[0xDE, 0xAD]).unwrap();
        let mut cursor = Cursor::new(resp);
        let (status, payload) = decode_frame(&mut cursor).unwrap();
        assert_eq!(status, STATUS_OK);
        assert_eq!(payload, vec![0xDE, 0xAD]);
    }

    #[test]
    fn status_message_known_codes() {
        assert_eq!(status_message(STATUS_OK), "OK");
        assert_eq!(status_message(STATUS_ERR_REJECTED), "Rejected by user");
        assert_eq!(status_message(STATUS_ERR_NO_SEED), "No seed loaded");
        assert_eq!(status_message(0xFE), "Unknown error");
    }

    /// A reader that returns its buffer in fixed-size chunks (mimics how
    /// USB CDC-ACM hands data to the host one URB at a time). Used to make
    /// sure decode_frame correctly reassembles a frame across read boundaries.
    struct ChunkedReader {
        data: Vec<u8>,
        chunk: usize,
        pos: usize,
    }

    impl ChunkedReader {
        fn new(data: Vec<u8>, chunk: usize) -> Self {
            Self { data, chunk, pos: 0 }
        }
    }

    impl std::io::Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let want = buf.len().min(self.chunk).min(self.data.len() - self.pos);
            buf[..want].copy_from_slice(&self.data[self.pos..self.pos + want]);
            self.pos += want;
            Ok(want)
        }
    }
}
