#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz Merkle path verification with adversarial paths.
    // Must never panic; invalid paths must be rejected.
    if data.len() < 97 {
        // Need at least: 32 (root) + 32 (leaf) + 33 (one path node)
        return;
    }

    use hc_commit::merkle::{MerklePath, PathNode};
    use hc_hash::HashDigest;

    // Extract root from first 32 bytes.
    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&data[0..32]);
    let claimed_root = HashDigest::from(root_bytes);

    // Extract leaf hash from next 32 bytes.
    let mut leaf_bytes = [0u8; 32];
    leaf_bytes.copy_from_slice(&data[32..64]);
    let leaf_hash = HashDigest::from(leaf_bytes);

    // Build path nodes from remaining data (33 bytes each: 32 hash + 1 direction).
    let path_data = &data[64..];
    let mut nodes = Vec::new();
    for chunk in path_data.chunks_exact(33) {
        let mut sibling_bytes = [0u8; 32];
        sibling_bytes.copy_from_slice(&chunk[0..32]);
        nodes.push(PathNode {
            sibling: HashDigest::from(sibling_bytes),
            sibling_is_left: chunk[32] & 1 == 1,
        });
    }

    if nodes.is_empty() || nodes.len() > 64 {
        return;
    }

    let path = MerklePath::new(nodes);

    // Verify with Blake3: this should never panic.
    let _valid = path.verify::<hc_hash::blake3::Blake3>(claimed_root, leaf_hash);
});
