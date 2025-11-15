use crate::merkle::height_dfs::StreamingMerkle;

/// Height-compressed streaming Merkle builder; thin wrapper around the DFS
/// implementation that exists to keep the public API stable.
pub type HeightCompressedMerkle<H> = StreamingMerkle<H>;
