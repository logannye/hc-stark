//! Built-in workloads shipped with the repo.

use anyhow::{anyhow, Result};
use hc_sdk::types::ProveRequest;
use hc_vm::{Instruction, Program};

use crate::{RegisteredWorkload, WorkloadCaps};

fn toy_add_1_2(_req: &ProveRequest) -> Result<Program> {
    Ok(Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]))
}

inventory::submit!(RegisteredWorkload {
    id: "toy_add_1_2",
    caps: WorkloadCaps {
        max_steps: 1 << 20,
        max_program_len: 2,
    },
    build_program: toy_add_1_2,
});

/// Helper used by binaries/tests that want to validate a workload exists.
pub fn require_builtin(id: &str) -> Result<()> {
    if super::workload_by_id(id).is_none() {
        return Err(anyhow!("missing builtin workload {id}"));
    }
    Ok(())
}
