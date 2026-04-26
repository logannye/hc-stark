//! Memory subsystem for the VM.
//!
//! Uses an offline memory checking model (a la Cairo): the VM maintains a
//! sorted access log. At verification time, the prover provides a permutation
//! argument proving that the access log is consistent with a valid memory.
//!
//! For now, this is a simple HashMap-based memory with an access log for
//! future constraint generation.

use std::collections::HashMap;

use hc_core::field::FieldElement;

/// A memory access record for the offline memory checking log.
#[derive(Clone, Copy, Debug)]
pub struct MemoryAccess<F: FieldElement> {
    /// Step number when the access occurred.
    pub step: usize,
    /// Memory address accessed.
    pub addr: F,
    /// Value read or written.
    pub value: F,
    /// Whether this was a write (true) or read (false).
    pub is_write: bool,
}

/// Simple addressable memory with access logging.
pub struct Memory<F: FieldElement> {
    /// The actual memory contents (address → value).
    store: HashMap<u64, F>,
    /// Ordered log of all memory accesses for offline checking.
    pub access_log: Vec<MemoryAccess<F>>,
}

impl<F: FieldElement> Memory<F> {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
            access_log: Vec::new(),
        }
    }

    /// Read a value from memory. Returns ZERO for uninitialized addresses.
    pub fn read(&mut self, addr: F, step: usize) -> F {
        let addr_u64 = addr.to_u64();
        let value = self.store.get(&addr_u64).copied().unwrap_or(F::ZERO);
        self.access_log.push(MemoryAccess {
            step,
            addr,
            value,
            is_write: false,
        });
        value
    }

    /// Write a value to memory.
    pub fn write(&mut self, addr: F, value: F, step: usize) {
        let addr_u64 = addr.to_u64();
        self.store.insert(addr_u64, value);
        self.access_log.push(MemoryAccess {
            step,
            addr,
            value,
            is_write: true,
        });
    }

    /// Number of distinct addresses written to.
    pub fn size(&self) -> usize {
        self.store.len()
    }
}

impl<F: FieldElement> Default for Memory<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn read_uninitialized_returns_zero() {
        let mut mem = Memory::<F>::new();
        assert_eq!(mem.read(F::from_u64(100), 0), F::ZERO);
    }

    #[test]
    fn write_then_read() {
        let mut mem = Memory::<F>::new();
        mem.write(F::from_u64(42), F::from_u64(999), 0);
        assert_eq!(mem.read(F::from_u64(42), 1), F::from_u64(999));
    }

    #[test]
    fn access_log_records_operations() {
        let mut mem = Memory::<F>::new();
        mem.write(F::from_u64(1), F::from_u64(10), 0);
        mem.read(F::from_u64(1), 1);
        assert_eq!(mem.access_log.len(), 2);
        assert!(mem.access_log[0].is_write);
        assert!(!mem.access_log[1].is_write);
    }
}
