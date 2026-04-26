//! Proof-scoped arena allocator for field element temporaries.
//!
//! During proving, many short-lived `Vec<F>` allocations are created for
//! intermediate values (LDE blocks, constraint evaluations, folded layers).
//! This arena pre-allocates a large contiguous buffer and hands out slices,
//! avoiding repeated heap allocation/deallocation.
//!
//! The arena is scoped to a single proof: create it at the start, use it
//! throughout the pipeline, and drop it when the proof is complete.
//!
//! Since `hc-core` forbids unsafe code, this uses `Vec<F>` as the backing
//! store and tracks allocation via a bump pointer (index).

use crate::field::FieldElement;

/// A bump-allocating arena for field element slices.
///
/// All allocations are contiguous within a single `Vec<F>`. When the arena
/// is full, it allocates a new chunk. The arena is not thread-safe by design;
/// each thread should have its own arena or the caller should synchronize.
pub struct FieldArena<F: FieldElement> {
    /// Backing storage chunks. Each chunk is a contiguous `Vec<F>`.
    chunks: Vec<Vec<F>>,
    /// Current position within the active (last) chunk.
    cursor: usize,
    /// Size of each chunk.
    chunk_size: usize,
}

impl<F: FieldElement> FieldArena<F> {
    /// Create a new arena with the given chunk size.
    ///
    /// The chunk size should be large enough to hold several blocks worth of
    /// field elements. A good default is `64 * 1024` (64K elements = 512KB
    /// for 64-bit fields).
    pub fn new(chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "chunk_size must be positive");
        let mut initial = Vec::with_capacity(chunk_size);
        initial.resize(chunk_size, F::ZERO);
        Self {
            chunks: vec![initial],
            cursor: 0,
            chunk_size,
        }
    }

    /// Create an arena with the default chunk size (64K elements).
    pub fn default_size() -> Self {
        Self::new(64 * 1024)
    }

    /// Allocate a mutable slice of `len` field elements, initialized to zero.
    ///
    /// If the current chunk has enough space, returns a slice from it.
    /// Otherwise, allocates a new chunk (or a dedicated oversized chunk if
    /// `len > chunk_size`).
    pub fn alloc_slice(&mut self, len: usize) -> &mut [F] {
        if len == 0 {
            return &mut [];
        }

        // If the request fits in the current chunk, bump the cursor.
        if self.cursor + len <= self.chunk_size {
            let start = self.cursor;
            self.cursor += len;
            let chunk = self
                .chunks
                .last_mut()
                .expect("arena has at least one chunk");
            let slice = &mut chunk[start..start + len];
            // Zero-fill the allocated region.
            for elem in slice.iter_mut() {
                *elem = F::ZERO;
            }
            return slice;
        }

        // Request doesn't fit: start a new chunk.
        let new_size = if len > self.chunk_size {
            // Oversized allocation: create a chunk exactly the right size.
            len
        } else {
            self.chunk_size
        };
        let mut new_chunk = Vec::with_capacity(new_size);
        new_chunk.resize(new_size, F::ZERO);
        self.chunks.push(new_chunk);
        self.cursor = len;
        let chunk = self.chunks.last_mut().unwrap();
        &mut chunk[..len]
    }

    /// Allocate a slice and copy `src` into it. Returns a mutable reference
    /// to the arena-backed copy.
    pub fn alloc_copy(&mut self, src: &[F]) -> &mut [F] {
        let dest = self.alloc_slice(src.len());
        dest.copy_from_slice(src);
        dest
    }

    /// Reset the arena, making all previously allocated slices invalid.
    ///
    /// This does not free memory — it reuses the existing chunks. Call this
    /// between proof phases to reuse memory without reallocating.
    pub fn reset(&mut self) {
        // Keep only the first chunk (or the largest if there were oversized ones).
        if self.chunks.len() > 1 {
            // Find the largest chunk and keep it.
            let max_idx = self
                .chunks
                .iter()
                .enumerate()
                .max_by_key(|(_, c)| c.len())
                .map(|(i, _)| i)
                .unwrap_or(0);
            let largest = self.chunks.swap_remove(max_idx);
            self.chunks.clear();
            self.chunks.push(largest);
            self.chunk_size = self.chunks[0].len();
        }
        self.cursor = 0;
    }

    /// Total bytes currently reserved (across all chunks).
    pub fn reserved_bytes(&self) -> usize {
        self.chunks.iter().map(|c| c.len()).sum::<usize>() * std::mem::size_of::<F>()
    }

    /// Number of chunks allocated.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn basic_allocation() {
        let mut arena = FieldArena::<F>::new(1024);
        let slice = arena.alloc_slice(10);
        assert_eq!(slice.len(), 10);
        assert!(slice.iter().all(|&x| x == F::ZERO));
        // Write and read back.
        slice[0] = F::from_u64(42);
        assert_eq!(slice[0], F::from_u64(42));
    }

    #[test]
    fn multiple_allocations_same_chunk() {
        let mut arena = FieldArena::<F>::new(1024);
        let a = arena.alloc_slice(100);
        a[0] = F::from_u64(1);
        let b = arena.alloc_slice(200);
        b[0] = F::from_u64(2);
        assert_eq!(arena.chunk_count(), 1);
    }

    #[test]
    fn allocation_spills_to_new_chunk() {
        let mut arena = FieldArena::<F>::new(100);
        let _ = arena.alloc_slice(60);
        let _ = arena.alloc_slice(60); // doesn't fit, new chunk
        assert_eq!(arena.chunk_count(), 2);
    }

    #[test]
    fn oversized_allocation() {
        let mut arena = FieldArena::<F>::new(100);
        let big = arena.alloc_slice(500);
        assert_eq!(big.len(), 500);
        assert!(arena.chunk_count() >= 2);
    }

    #[test]
    fn alloc_copy_copies_data() {
        let mut arena = FieldArena::<F>::new(1024);
        let src: Vec<F> = (0..10).map(F::from_u64).collect();
        let copy = arena.alloc_copy(&src);
        assert_eq!(copy, src.as_slice());
        // Mutation doesn't affect source.
        copy[0] = F::from_u64(999);
        assert_eq!(src[0], F::from_u64(0));
    }

    #[test]
    fn reset_reuses_memory() {
        let mut arena = FieldArena::<F>::new(1024);
        let _ = arena.alloc_slice(500);
        let _ = arena.alloc_slice(500);
        let _ = arena.alloc_slice(500); // forces second chunk
        let bytes_before = arena.reserved_bytes();
        arena.reset();
        assert_eq!(arena.chunk_count(), 1);
        // After reset, we can allocate again.
        let slice = arena.alloc_slice(100);
        assert_eq!(slice.len(), 100);
        // Memory footprint should not have grown.
        assert!(arena.reserved_bytes() <= bytes_before);
    }

    #[test]
    fn empty_allocation() {
        let mut arena = FieldArena::<F>::new(1024);
        let empty = arena.alloc_slice(0);
        assert_eq!(empty.len(), 0);
    }
}
