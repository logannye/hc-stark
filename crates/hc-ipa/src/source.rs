//! On-demand vector source: lets the prover read entries of `a` and `b`
//! without materializing them.

use hc_core::HcResult;

/// A vector source that yields entries on demand.
///
/// Real implementations would derive entries from a witness commitment plus
/// an index, or read tiles from disk-backed storage. The IPA prover only
/// ever asks for tiles of contiguous indices.
pub trait IpaVectorSource {
    /// Length `n` of the vectors `a` and `b`. Must be a power of two.
    fn length(&self) -> usize;

    /// Read a contiguous tile of `a` into `out_a` and the corresponding tile
    /// of `b` into `out_b`. Both slices have length `tile_len`. The tile
    /// starts at index `start`.
    fn read_tile(&self, start: usize, out_a: &mut [u64], out_b: &mut [u64]) -> HcResult<()>;
}

/// Dummy source for tests: yields zero everywhere.
#[derive(Clone, Debug)]
pub struct DummyVectorSource {
    pub n: usize,
}

impl DummyVectorSource {
    pub fn new(n: usize) -> Self {
        debug_assert!(n.is_power_of_two(), "DummyVectorSource length must be POT");
        Self { n }
    }
}

impl IpaVectorSource for DummyVectorSource {
    fn length(&self) -> usize {
        self.n
    }

    fn read_tile(&self, _start: usize, out_a: &mut [u64], out_b: &mut [u64]) -> HcResult<()> {
        for slot in out_a.iter_mut().chain(out_b.iter_mut()) {
            *slot = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_source_zero_fill() {
        let s = DummyVectorSource::new(16);
        let mut a = vec![1u64; 4];
        let mut b = vec![2u64; 4];
        s.read_tile(0, &mut a, &mut b).unwrap();
        assert!(a.iter().all(|&x| x == 0));
        assert!(b.iter().all(|&x| x == 0));
    }
}
