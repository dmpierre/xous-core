//! RLP (Recursive Length Prefix) decoder.
//!
//! This module provides a minimal, secure RLP decoder for Ethereum data.
//! RLP is used to encode all Ethereum transactions and receipts.
//!
//! # Specification
//!
//! RLP encoding rules:
//! - Single byte [0x00, 0x7f]: itself
//! - String [0x80, 0xb7]: 0x80 + len, then data
//! - String [0xb8, 0xbf]: 0xb7 + len_of_len, then len, then data
//! - List [0xc0, 0xf7]: 0xc0 + len, then items
//! - List [0xf8, 0xff]: 0xf7 + len_of_len, then len, then items
//!
//! # Security
//!
//! - Validates all length fields before access
//! - Rejects non-canonical encodings
//! - Bounded recursion depth (max 16)
//! - No unbounded allocations

#[cfg(target_os = "xous")]
use alloc::vec;
#[cfg(target_os = "xous")]
use alloc::vec::Vec;

#[cfg(not(target_os = "xous"))]
use std::vec;
#[cfg(not(target_os = "xous"))]
use std::vec::Vec;

/// Maximum RLP nesting depth.
const MAX_DEPTH: usize = 16;

/// RLP decoding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlpError {
    /// Input is empty when data expected.
    EmptyInput,
    /// Input too short for declared length.
    UnexpectedEof,
    /// Non-canonical encoding (leading zeros in length).
    NonCanonical,
    /// Single byte should be encoded as itself.
    SingleByteMismatch,
    /// Length field is too large.
    LengthOverflow,
    /// Exceeded maximum nesting depth.
    TooDeep,
    /// Expected list but got string.
    ExpectedList,
    /// Expected string but got list.
    ExpectedString,
    /// Extra data after RLP item.
    TrailingData,
}

/// A decoded RLP item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpItem<'a> {
    /// A byte string (may be empty).
    String(&'a [u8]),
    /// A list of items.
    List(Vec<RlpItem<'a>>),
}

impl<'a> RlpItem<'a> {
    /// Returns true if this is a string item.
    #[inline]
    pub fn is_string(&self) -> bool {
        matches!(self, RlpItem::String(_))
    }

    /// Returns true if this is a list item.
    #[inline]
    pub fn is_list(&self) -> bool {
        matches!(self, RlpItem::List(_))
    }

    /// Returns the string data if this is a string item.
    pub fn as_string(&self) -> Option<&'a [u8]> {
        match self {
            RlpItem::String(data) => Some(data),
            _ => None,
        }
    }

    /// Returns the list items if this is a list item.
    pub fn as_list(&self) -> Option<&[RlpItem<'a>]> {
        match self {
            RlpItem::List(items) => Some(items),
            _ => None,
        }
    }

    /// Converts string data to a u64 value (big-endian).
    pub fn as_u64(&self) -> Option<u64> {
        let data = self.as_string()?;
        if data.is_empty() {
            return Some(0);
        }
        if data.len() > 8 {
            return None;
        }
        // Check for non-canonical (leading zeros)
        if data.len() > 1 && data[0] == 0 {
            return None;
        }
        let mut value = 0u64;
        for &byte in data {
            value = value << 8 | byte as u64;
        }
        Some(value)
    }

    /// Converts string data to a 20-byte address.
    pub fn as_address(&self) -> Option<[u8; 20]> {
        let data = self.as_string()?;
        if data.len() != 20 {
            return None;
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(data);
        Some(addr)
    }

    /// Converts string data to a 32-byte value (right-aligned).
    pub fn as_bytes32(&self) -> Option<[u8; 32]> {
        let data = self.as_string()?;
        if data.len() > 32 {
            return None;
        }
        let mut result = [0u8; 32];
        result[32 - data.len()..].copy_from_slice(data);
        Some(result)
    }
}

/// Decodes a complete RLP-encoded item from the input.
pub fn decode(input: &[u8]) -> Result<(RlpItem<'_>, &[u8]), RlpError> {
    decode_internal(input, 0)
}

/// Decodes a complete RLP item, rejecting trailing data.
pub fn decode_exact(input: &[u8]) -> Result<RlpItem<'_>, RlpError> {
    let (item, rest) = decode(input)?;
    if !rest.is_empty() {
        return Err(RlpError::TrailingData);
    }
    Ok(item)
}

/// Internal decode with depth tracking.
fn decode_internal(input: &[u8], depth: usize) -> Result<(RlpItem<'_>, &[u8]), RlpError> {
    if depth > MAX_DEPTH {
        return Err(RlpError::TooDeep);
    }

    if input.is_empty() {
        return Err(RlpError::EmptyInput);
    }

    let first = input[0];

    match first {
        // Single byte
        0x00..=0x7f => Ok((RlpItem::String(&input[..1]), &input[1..])),

        // Short string (0-55 bytes)
        0x80..=0xb7 => {
            let len = (first - 0x80) as usize;
            if input.len() < 1 + len {
                return Err(RlpError::UnexpectedEof);
            }
            let data = &input[1..1 + len];

            // Check for non-canonical single byte
            if len == 1 && data[0] < 0x80 {
                return Err(RlpError::SingleByteMismatch);
            }

            Ok((RlpItem::String(data), &input[1 + len..]))
        }

        // Long string (56+ bytes)
        0xb8..=0xbf => {
            let len_of_len = (first - 0xb7) as usize;
            if input.len() < 1 + len_of_len {
                return Err(RlpError::UnexpectedEof);
            }

            let len_bytes = &input[1..1 + len_of_len];

            // Check for non-canonical (leading zeros)
            if len_bytes[0] == 0 {
                return Err(RlpError::NonCanonical);
            }

            let len = decode_length(len_bytes)?;

            // Check that length >= 56
            if len < 56 {
                return Err(RlpError::NonCanonical);
            }

            let start = 1 + len_of_len;
            if input.len() < start + len {
                return Err(RlpError::UnexpectedEof);
            }

            let data = &input[start..start + len];
            Ok((RlpItem::String(data), &input[start + len..]))
        }

        // Short list (0-55 bytes total)
        0xc0..=0xf7 => {
            let len = (first - 0xc0) as usize;
            if input.len() < 1 + len {
                return Err(RlpError::UnexpectedEof);
            }

            let list_data = &input[1..1 + len];
            let items = decode_list_items(list_data, depth + 1)?;

            Ok((RlpItem::List(items), &input[1 + len..]))
        }

        // Long list (56+ bytes total)
        0xf8..=0xff => {
            let len_of_len = (first - 0xf7) as usize;
            if input.len() < 1 + len_of_len {
                return Err(RlpError::UnexpectedEof);
            }

            let len_bytes = &input[1..1 + len_of_len];

            // Check for non-canonical
            if len_bytes[0] == 0 {
                return Err(RlpError::NonCanonical);
            }

            let len = decode_length(len_bytes)?;

            if len < 56 {
                return Err(RlpError::NonCanonical);
            }

            let start = 1 + len_of_len;
            if input.len() < start + len {
                return Err(RlpError::UnexpectedEof);
            }

            let list_data = &input[start..start + len];
            let items = decode_list_items(list_data, depth + 1)?;

            Ok((RlpItem::List(items), &input[start + len..]))
        }
    }
}

/// Decodes a big-endian length value.
fn decode_length(bytes: &[u8]) -> Result<usize, RlpError> {
    if bytes.len() > 8 {
        return Err(RlpError::LengthOverflow);
    }

    let mut len = 0usize;
    for &byte in bytes {
        len = len.checked_shl(8).ok_or(RlpError::LengthOverflow)?;
        len = len.checked_add(byte as usize).ok_or(RlpError::LengthOverflow)?;
    }

    Ok(len)
}

/// Decodes all items in a list.
fn decode_list_items(mut data: &[u8], depth: usize) -> Result<Vec<RlpItem<'_>>, RlpError> {
    let mut items = Vec::new();

    while !data.is_empty() {
        let (item, rest) = decode_internal(data, depth)?;
        items.push(item);
        data = rest;
    }

    Ok(items)
}

// =============================================================================
// Encoding (for computing signing hashes)
// =============================================================================

/// Encodes a u64 as RLP bytes.
pub fn encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80]; // Empty string for zero
    }

    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let significant = &bytes[start..];

    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut result = vec![0x80 + significant.len() as u8];
        result.extend_from_slice(significant);
        result
    }
}

/// Encodes a byte slice as RLP.
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }

    if data.len() <= 55 {
        let mut result = vec![0x80 + data.len() as u8];
        result.extend_from_slice(data);
        result
    } else {
        let len_bytes = encode_length_bytes(data.len());
        let mut result = vec![0xb7 + len_bytes.len() as u8];
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(data);
        result
    }
}

/// Encodes a list of already-encoded items as RLP.
pub fn encode_list(items: &[u8]) -> Vec<u8> {
    if items.len() <= 55 {
        let mut result = vec![0xc0 + items.len() as u8];
        result.extend_from_slice(items);
        result
    } else {
        let len_bytes = encode_length_bytes(items.len());
        let mut result = vec![0xf7 + len_bytes.len() as u8];
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(items);
        result
    }
}

/// Encodes a length as big-endian bytes.
fn encode_length_bytes(len: usize) -> Vec<u8> {
    if len == 0 {
        return vec![];
    }
    let bytes = len.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_single_byte() {
        let (item, rest) = decode(&[0x42]).unwrap();
        assert_eq!(item.as_string(), Some(&[0x42][..]));
        assert!(rest.is_empty());
    }

    #[test]
    fn test_decode_empty_string() {
        let (item, rest) = decode(&[0x80]).unwrap();
        assert_eq!(item.as_string(), Some(&[][..]));
        assert!(rest.is_empty());
    }

    #[test]
    fn test_decode_short_string() {
        let data = [0x83, b'c', b'a', b't'];
        let (item, rest) = decode(&data).unwrap();
        assert_eq!(item.as_string(), Some(&b"cat"[..]));
        assert!(rest.is_empty());
    }

    #[test]
    fn test_decode_empty_list() {
        let (item, rest) = decode(&[0xc0]).unwrap();
        assert!(item.as_list().unwrap().is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn test_decode_nested_list() {
        // [[]] encoded as 0xc1 0xc0
        let data = [0xc1, 0xc0];
        let (item, _) = decode(&data).unwrap();
        let list = item.as_list().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].as_list().unwrap().is_empty());
    }

    #[test]
    fn test_as_u64() {
        let (item, _) = decode(&[0x82, 0x04, 0x00]).unwrap();
        assert_eq!(item.as_u64(), Some(1024));

        let (item, _) = decode(&[0x80]).unwrap();
        assert_eq!(item.as_u64(), Some(0));
    }

    #[test]
    fn test_non_canonical_single_byte() {
        // 0x81 0x42 should be just 0x42
        let result = decode(&[0x81, 0x42]);
        assert!(matches!(result, Err(RlpError::SingleByteMismatch)));
    }

    #[test]
    fn test_encode_u64() {
        assert_eq!(encode_u64(0), vec![0x80]);
        assert_eq!(encode_u64(127), vec![0x7f]);
        assert_eq!(encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(encode_u64(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_bytes() {
        assert_eq!(encode_bytes(b""), vec![0x80]);
        assert_eq!(encode_bytes(&[0x42]), vec![0x42]);
        assert_eq!(encode_bytes(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(encode_bytes(b"cat"), vec![0x83, b'c', b'a', b't']);
    }
}
