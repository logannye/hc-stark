#![forbid(unsafe_code)]

//! Workload registry for `hc-server` and downstream integrators.
//!
//! Goals:
//! - Safe-by-default: server can restrict to a curated registry (`workload_id` only).
//! - Extensible without editing core crates: third-party crates can register workloads via
//!   `inventory` and linking.
//!
//! Non-goals:
//! - Arbitrary code execution / untrusted plugins. Workloads are Rust code compiled into the
//!   binary, and registration is compile-time.

use anyhow::{anyhow, Result};
use hc_sdk::types::ProveRequest;
use hc_vm::Program;

/// Hard caps for a workload. The server should enforce these before proving.
#[derive(Clone, Copy, Debug)]
pub struct WorkloadCaps {
    pub max_steps: usize,
    pub max_program_len: usize,
}

impl Default for WorkloadCaps {
    fn default() -> Self {
        Self {
            max_steps: 1 << 20,
            max_program_len: 1 << 20,
        }
    }
}

/// A registered workload definition.
#[derive(Clone, Copy)]
pub struct RegisteredWorkload {
    pub id: &'static str,
    pub caps: WorkloadCaps,
    pub build_program: fn(&ProveRequest) -> Result<Program>,
}

inventory::collect!(RegisteredWorkload);

/// Return a workload by id.
pub fn workload_by_id(id: &str) -> Option<&'static RegisteredWorkload> {
    inventory::iter::<RegisteredWorkload>
        .into_iter()
        .find(|w| w.id == id)
}

/// List registered workload IDs (stable order is not guaranteed).
pub fn list_workloads() -> Vec<&'static str> {
    inventory::iter::<RegisteredWorkload>
        .into_iter()
        .map(|w| w.id)
        .collect()
}

/// Build a `Program` for a known workload ID.
pub fn program_for_request(req: &ProveRequest) -> Result<Program> {
    let id = req
        .workload_id
        .as_deref()
        .ok_or_else(|| anyhow!("missing workload_id"))?;
    let w = workload_by_id(id).ok_or_else(|| anyhow!("unknown workload_id: {id}"))?;
    let program = (w.build_program)(req)?;
    if program.len() > w.caps.max_program_len {
        return Err(anyhow!(
            "workload {id} program length {} exceeds cap {}",
            program.len(),
            w.caps.max_program_len
        ));
    }
    if program.len() > w.caps.max_steps {
        return Err(anyhow!(
            "workload {id} steps {} exceeds cap {}",
            program.len(),
            w.caps.max_steps
        ));
    }
    Ok(program)
}

pub mod builtin;
pub mod spartan_templates;
pub mod templates;
pub mod unified;
pub mod zkml_templates;

pub use unified::{list_all_templates, UnifiedTemplateInfo};

#[cfg(test)]
mod tests {
    use super::*;
    use hc_vm::Instruction;

    #[test]
    fn builtin_registry_contains_toy_workload() {
        assert!(
            workload_by_id("toy_add_1_2").is_some(),
            "expected builtin toy_add_1_2 workload"
        );
    }

    #[test]
    fn builds_program_for_builtin_workload() {
        let req = ProveRequest {
            workload_id: Some("toy_add_1_2".to_string()),
            template_id: None,
            template_params: None,
            program: None,
            initial_acc: 5,
            final_acc: 8,
            block_size: 2,
            fri_final_poly_size: 2,
            query_count: 30,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        };
        let program = program_for_request(&req).unwrap();
        assert_eq!(program.instructions.len(), 2);
        match (program.instructions[0], program.instructions[1]) {
            (Instruction::AddImmediate(1), Instruction::AddImmediate(2)) => {}
            _ => panic!("unexpected program instructions"),
        }
    }
}
