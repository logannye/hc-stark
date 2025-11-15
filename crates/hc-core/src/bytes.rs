//! Utilities for working with byte encodings.

use crate::error::{HcError, HcResult};

/// Serialises a `u64` to little-endian bytes.
#[inline]
pub fn u64_to_le_bytes(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// Deserialises a `u64` from a little-endian byte slice.
pub fn le_bytes_to_u64(bytes: &[u8]) -> HcResult<u64> {
    if bytes.len() != 8 {
        return Err(HcError::invalid_argument("expected 8 bytes for u64"));
    }
    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(array))
}

/// Writes bytes into the provided buffer, appending in-place.
pub fn append_bytes(dst: &mut Vec<u8>, data: &[u8]) {
    dst.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u64() {
        let value = 0xDEADBEEF_EEAABBCC;
        let bytes = u64_to_le_bytes(value);
        assert_eq!(le_bytes_to_u64(&bytes).unwrap(), value);
    }

    #[test]
    fn append_bytes_appends_in_order() {
        let mut buf = vec![1, 2, 3];
        append_bytes(&mut buf, &[4, 5]);
        assert_eq!(buf, vec![1, 2, 3, 4, 5]);
    }
}
