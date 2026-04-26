//! Proof compression utilities for on-chain submission.
//!
//! Two main optimizations:
//!
//! 1. **Merkle path deduplication**: When multiple queries hit the same subtree,
//!    their Merkle paths share sibling nodes near the root. This module
//!    deduplicates shared nodes and encodes a compact "path table" referenced
//!    by index.
//!
//! 2. **Index bit-packing**: Query indices are packed into variable-length
//!    encodings based on the domain size, saving ~50% over fixed u32.

use hc_commit::merkle::{MerklePath, PathNode};
use hc_hash::HashDigest;
use std::collections::HashMap;

/// A deduplicated set of Merkle sibling hashes with index-based references.
#[derive(Clone, Debug)]
pub struct CompressedPaths {
    /// Unique sibling hashes (the "dictionary").
    pub sibling_table: Vec<HashDigest>,
    /// For each original path: a sequence of (sibling_table_index, sibling_is_left) pairs.
    pub path_refs: Vec<Vec<(u32, bool)>>,
}

/// Compress a batch of Merkle paths by deduplicating shared sibling hashes.
///
/// Returns a `CompressedPaths` that can be serialized more compactly than
/// the raw paths. The sibling_table contains each unique digest exactly once.
pub fn compress_merkle_paths(paths: &[MerklePath]) -> CompressedPaths {
    let mut sibling_map: HashMap<[u8; 32], u32> = HashMap::new();
    let mut sibling_table: Vec<HashDigest> = Vec::new();
    let mut path_refs: Vec<Vec<(u32, bool)>> = Vec::with_capacity(paths.len());

    for path in paths {
        let mut refs = Vec::with_capacity(path.nodes().len());
        for node in path.nodes() {
            let key = *node.sibling.as_bytes();
            let idx = *sibling_map.entry(key).or_insert_with(|| {
                let idx = sibling_table.len() as u32;
                sibling_table.push(node.sibling);
                idx
            });
            refs.push((idx, node.sibling_is_left));
        }
        path_refs.push(refs);
    }

    CompressedPaths {
        sibling_table,
        path_refs,
    }
}

/// Decompress paths back to their original form.
pub fn decompress_merkle_paths(compressed: &CompressedPaths) -> Vec<MerklePath> {
    compressed
        .path_refs
        .iter()
        .map(|refs| {
            let nodes = refs
                .iter()
                .map(|&(idx, sibling_is_left)| PathNode {
                    sibling: compressed.sibling_table[idx as usize],
                    sibling_is_left,
                })
                .collect();
            MerklePath::new(nodes)
        })
        .collect()
}

/// Encode compressed paths into a compact binary format.
///
/// Format:
/// ```text
/// table_size: u32
/// sibling_table: [u8; 32 * table_size]
/// path_count: u32
/// for each path:
///   node_count: u16
///   direction_bits: packed bitfield (1 bit per node, ceil(node_count/8) bytes)
///   indices: [varint; node_count]  (LEB128-encoded table indices)
/// ```
pub fn encode_compressed(compressed: &CompressedPaths) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        4 + compressed.sibling_table.len() * 32 + 4 + compressed.path_refs.len() * 32,
    );

    // Sibling table.
    buf.extend_from_slice(&(compressed.sibling_table.len() as u32).to_be_bytes());
    for digest in &compressed.sibling_table {
        buf.extend_from_slice(digest.as_bytes());
    }

    // Paths.
    buf.extend_from_slice(&(compressed.path_refs.len() as u32).to_be_bytes());
    for refs in &compressed.path_refs {
        buf.extend_from_slice(&(refs.len() as u16).to_be_bytes());

        // Direction bits.
        let bit_bytes = (refs.len() + 7) / 8;
        let mut bits = vec![0u8; bit_bytes];
        for (i, &(_, is_left)) in refs.iter().enumerate() {
            if is_left {
                bits[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        buf.extend_from_slice(&bits);

        // LEB128-encoded indices.
        for &(idx, _) in refs {
            encode_leb128(idx, &mut buf);
        }
    }

    buf
}

/// Decode compressed paths from the binary format.
pub fn decode_compressed(data: &[u8]) -> Result<CompressedPaths, &'static str> {
    let mut cursor = 0usize;

    // Sibling table.
    let table_size = read_u32_be(data, &mut cursor)? as usize;
    let mut sibling_table = Vec::with_capacity(table_size);
    for _ in 0..table_size {
        if cursor + 32 > data.len() {
            return Err("truncated sibling table");
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[cursor..cursor + 32]);
        sibling_table.push(HashDigest::from(bytes));
        cursor += 32;
    }

    // Paths.
    let path_count = read_u32_be(data, &mut cursor)? as usize;
    let mut path_refs = Vec::with_capacity(path_count);

    for _ in 0..path_count {
        if cursor + 2 > data.len() {
            return Err("truncated path header");
        }
        let node_count = u16::from_be_bytes(data[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;

        // Direction bits.
        let bit_bytes = (node_count + 7) / 8;
        if cursor + bit_bytes > data.len() {
            return Err("truncated direction bits");
        }
        let bits = &data[cursor..cursor + bit_bytes];
        cursor += bit_bytes;

        let mut refs = Vec::with_capacity(node_count);
        for i in 0..node_count {
            let is_left = (bits[i / 8] >> (7 - (i % 8))) & 1 == 1;
            let idx = decode_leb128(data, &mut cursor)?;
            if idx as usize >= sibling_table.len() {
                return Err("sibling index out of range");
            }
            refs.push((idx, is_left));
        }
        path_refs.push(refs);
    }

    Ok(CompressedPaths {
        sibling_table,
        path_refs,
    })
}

/// Pack query indices using the minimum number of bits required by the domain size.
///
/// For a domain of size `2^k`, each index needs exactly `k` bits.
/// This packs `indices.len()` indices into a bitstream.
pub fn pack_indices(indices: &[usize], domain_size: usize) -> Vec<u8> {
    if indices.is_empty() || domain_size <= 1 {
        return Vec::new();
    }

    let bits_per_index = (usize::BITS - (domain_size - 1).leading_zeros()) as usize;
    let total_bits = indices.len() * bits_per_index;
    let mut output = vec![0u8; (total_bits + 7) / 8];

    let mut bit_offset = 0usize;
    for &idx in indices {
        for b in (0..bits_per_index).rev() {
            let bit = (idx >> b) & 1;
            if bit == 1 {
                output[bit_offset / 8] |= 1 << (7 - (bit_offset % 8));
            }
            bit_offset += 1;
        }
    }

    output
}

/// Unpack query indices from a packed bitstream.
pub fn unpack_indices(data: &[u8], count: usize, domain_size: usize) -> Vec<usize> {
    if count == 0 || domain_size <= 1 {
        return Vec::new();
    }

    let bits_per_index = (usize::BITS - (domain_size - 1).leading_zeros()) as usize;
    let mut indices = Vec::with_capacity(count);

    let mut bit_offset = 0usize;
    for _ in 0..count {
        let mut val = 0usize;
        for _ in 0..bits_per_index {
            val <<= 1;
            if bit_offset / 8 < data.len() {
                val |= ((data[bit_offset / 8] >> (7 - (bit_offset % 8))) & 1) as usize;
            }
            bit_offset += 1;
        }
        indices.push(val);
    }

    indices
}

/// Compute the compression ratio (compressed / original) for a set of paths.
pub fn compression_ratio(paths: &[MerklePath]) -> f64 {
    if paths.is_empty() {
        return 1.0;
    }

    let original_size: usize = paths
        .iter()
        .map(|p| p.nodes().len() * (32 + 1)) // 32 bytes hash + 1 byte direction
        .sum();

    let compressed = compress_merkle_paths(paths);
    let encoded = encode_compressed(&compressed);

    if original_size == 0 {
        return 1.0;
    }

    encoded.len() as f64 / original_size as f64
}

// ---- LEB128 helpers ----

fn encode_leb128(mut value: u32, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_leb128(data: &[u8], cursor: &mut usize) -> Result<u32, &'static str> {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        if *cursor >= data.len() {
            return Err("truncated LEB128");
        }
        let byte = data[*cursor];
        *cursor += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return Err("LEB128 overflow");
        }
    }
    Ok(result)
}

fn read_u32_be(data: &[u8], cursor: &mut usize) -> Result<u32, &'static str> {
    if *cursor + 4 > data.len() {
        return Err("truncated u32");
    }
    let val = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into().unwrap());
    *cursor += 4;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_path(siblings: &[[u8; 32]], directions: &[bool]) -> MerklePath {
        let nodes = siblings
            .iter()
            .zip(directions.iter())
            .map(|(s, &d)| PathNode {
                sibling: HashDigest::from(*s),
                sibling_is_left: d,
            })
            .collect();
        MerklePath::new(nodes)
    }

    #[test]
    fn compress_deduplicates_shared_siblings() {
        let shared = [0xAA; 32];
        let unique_a = [0xBB; 32];
        let unique_b = [0xCC; 32];

        let path_a = make_path(&[shared, unique_a], &[true, false]);
        let path_b = make_path(&[shared, unique_b], &[false, true]);

        let compressed = compress_merkle_paths(&[path_a, path_b]);

        // 3 unique siblings, not 4.
        assert_eq!(compressed.sibling_table.len(), 3);
        // Both paths reference the shared sibling at the same index.
        assert_eq!(compressed.path_refs[0][0].0, compressed.path_refs[1][0].0);
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let path_a = make_path(&[[1; 32], [2; 32], [3; 32]], &[true, false, true]);
        let path_b = make_path(&[[2; 32], [4; 32]], &[false, false]);
        let paths = vec![path_a, path_b];

        let compressed = compress_merkle_paths(&paths);
        let decompressed = decompress_merkle_paths(&compressed);

        assert_eq!(decompressed.len(), 2);
        assert_eq!(decompressed[0].nodes().len(), 3);
        assert_eq!(decompressed[1].nodes().len(), 2);

        // Check values preserved.
        assert_eq!(*decompressed[0].nodes()[0].sibling.as_bytes(), [1; 32]);
        assert!(decompressed[0].nodes()[0].sibling_is_left);
        assert_eq!(*decompressed[0].nodes()[1].sibling.as_bytes(), [2; 32]);
        assert!(!decompressed[0].nodes()[1].sibling_is_left);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let path_a = make_path(&[[10; 32], [20; 32]], &[true, false]);
        let path_b = make_path(&[[10; 32], [30; 32]], &[false, true]);
        let paths = vec![path_a, path_b];

        let compressed = compress_merkle_paths(&paths);
        let encoded = encode_compressed(&compressed);
        let decoded = decode_compressed(&encoded).unwrap();

        assert_eq!(decoded.sibling_table.len(), compressed.sibling_table.len());
        assert_eq!(decoded.path_refs.len(), compressed.path_refs.len());
        for (a, b) in decoded.path_refs.iter().zip(compressed.path_refs.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn pack_unpack_indices_roundtrip() {
        let indices = vec![0, 1, 7, 15, 42, 100, 255];
        let domain_size = 256; // 8 bits per index

        let packed = pack_indices(&indices, domain_size);
        let unpacked = unpack_indices(&packed, indices.len(), domain_size);

        assert_eq!(unpacked, indices);
    }

    #[test]
    fn pack_indices_power_of_two_domain() {
        let indices = vec![0, 1, 2, 3];
        let domain_size = 4; // 2 bits per index

        let packed = pack_indices(&indices, domain_size);
        // 4 indices * 2 bits = 8 bits = 1 byte
        assert_eq!(packed.len(), 1);
        // Binary: 00 01 10 11 = 0x1B
        assert_eq!(packed[0], 0b00_01_10_11);

        let unpacked = unpack_indices(&packed, 4, domain_size);
        assert_eq!(unpacked, indices);
    }

    #[test]
    fn pack_indices_large_domain() {
        let domain_size = 1 << 20; // 20 bits per index
        let indices = vec![0, 1, (1 << 20) - 1, 12345];

        let packed = pack_indices(&indices, domain_size);
        let unpacked = unpack_indices(&packed, indices.len(), domain_size);

        assert_eq!(unpacked, indices);
    }

    #[test]
    fn leb128_roundtrip() {
        let test_values = [0, 1, 127, 128, 255, 16384, u32::MAX];
        for &val in &test_values {
            let mut buf = Vec::new();
            encode_leb128(val, &mut buf);
            let mut cursor = 0;
            let decoded = decode_leb128(&buf, &mut cursor).unwrap();
            assert_eq!(decoded, val, "LEB128 roundtrip failed for {val}");
        }
    }

    #[test]
    fn compression_ratio_with_sharing() {
        // Two paths sharing all siblings should compress well.
        let shared = [0xFF; 32];
        let path = make_path(&[shared, shared, shared], &[true, false, true]);
        let paths = vec![path.clone(), path.clone(), path];

        let ratio = compression_ratio(&paths);
        // With 3 identical paths, the compressed version should be significantly smaller.
        assert!(ratio < 0.7, "Expected compression ratio < 0.7, got {ratio}");
    }

    #[test]
    fn empty_paths() {
        let compressed = compress_merkle_paths(&[]);
        assert!(compressed.sibling_table.is_empty());
        assert!(compressed.path_refs.is_empty());

        let encoded = encode_compressed(&compressed);
        let decoded = decode_compressed(&encoded).unwrap();
        assert!(decoded.sibling_table.is_empty());
    }
}
