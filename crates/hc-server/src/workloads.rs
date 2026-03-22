use anyhow::Result;
use hc_sdk::types::ProveRequest;
use hc_vm::Program;

/// Fixed workloads shipped with the repo.
///
/// This is the production-safe mode: clients reference a stable workload ID instead of
/// submitting arbitrary code.
pub fn program_for_request(req: &ProveRequest) -> Result<Program> {
    hc_workloads::program_for_request(req)
}

pub fn known_workload(id: &str) -> bool {
    hc_workloads::workload_by_id(id).is_some()
}

pub fn list_workloads() -> Vec<&'static str> {
    hc_workloads::list_workloads()
}

pub fn known_template(id: &str) -> bool {
    hc_workloads::templates::template_by_id(id).is_some()
}
