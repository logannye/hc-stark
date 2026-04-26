//! Register file, memory, and program containers for the zkVM.

use crate::isa::RvInstr;
use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// 32 RV32I registers. `x0` is hardwired to zero on read; writes to `x0` are
/// silently dropped to match the RISC-V spec.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RegFile {
    pub x: [u32; 32],
    pub pc: u32,
}

impl RegFile {
    pub fn read(&self, idx: u8) -> u32 {
        if idx == 0 {
            0
        } else {
            self.x[idx as usize]
        }
    }

    pub fn write(&mut self, idx: u8, val: u32) {
        if idx != 0 {
            self.x[idx as usize] = val;
        }
    }
}

/// Page-addressed byte memory. Pages are allocated lazily so unbounded address
/// spaces don't blow up RAM during witness generation.
///
/// The AIR will commit to a Merkle tree of resident pages; only the pages
/// touched in a block are live during proving.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Memory {
    /// Page size in bytes. Must be a power of two; default is 4096.
    pub page_size: u32,
    /// Sparse map from page index to page bytes.
    pub pages: std::collections::BTreeMap<u32, Vec<u8>>,
}

impl Memory {
    pub fn new(page_size: u32) -> HcResult<Self> {
        if !page_size.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "memory page_size must be a power of two, got {page_size}"
            )));
        }
        Ok(Self {
            page_size,
            pages: Default::default(),
        })
    }
}

/// A loadable RISC-V program: a flat instruction stream plus an entry PC.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RiscvProgram {
    pub instructions: Vec<RvInstr>,
    pub entry_pc: u32,
    /// Optional human-readable label (not part of the commitment).
    pub label: Option<String>,
}

impl RiscvProgram {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> HcResult<()> {
        // The full validator will check immediate ranges, alignment, and
        // jump targets. For the API stub we only enforce the entry PC is in
        // bounds when there are instructions.
        if !self.instructions.is_empty() {
            let max = (self.instructions.len() as u32).saturating_mul(4);
            if self.entry_pc >= max {
                return Err(HcError::invalid_argument(format!(
                    "entry_pc {} is out of range for program of {} instructions",
                    self.entry_pc,
                    self.instructions.len()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x0_is_hardwired() {
        let mut rf = RegFile::default();
        rf.write(0, 42);
        assert_eq!(rf.read(0), 0);
    }

    #[test]
    fn write_then_read_nonzero_register() {
        let mut rf = RegFile::default();
        rf.write(7, 0xdeadbeef);
        assert_eq!(rf.read(7), 0xdeadbeef);
    }

    #[test]
    fn memory_rejects_non_power_of_two_page_size() {
        assert!(Memory::new(3000).is_err());
    }

    #[test]
    fn empty_program_validates() {
        RiscvProgram::empty().validate().unwrap();
    }
}
