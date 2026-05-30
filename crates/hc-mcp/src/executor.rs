use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use anyhow::Result;
use hc_core::field::prime_field::GoldilocksField;
use hc_core::field::FieldElement;
use hc_prover::{config::ProverConfig, PublicInputs};
use hc_sdk::proof::encode_proof_v5;
use hc_vm::Program;

use crate::types::{JobEntry, JobStatus};

pub struct ProveExecutor {
    jobs: Arc<Mutex<HashMap<String, JobEntry>>>,
    max_inflight: usize,
}

impl ProveExecutor {
    pub fn new(max_inflight: usize) -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            max_inflight,
        }
    }

    pub async fn submit(
        &self,
        program: Program,
        initial_acc: u64,
        final_acc: u64,
        template_id: Option<String>,
        zk_mask_degree: Option<usize>,
    ) -> Result<String> {
        let job_id = uuid::Uuid::new_v4().to_string();

        // Check inflight count
        {
            let jobs = self.jobs.lock().await;
            let inflight = jobs
                .values()
                .filter(|j| matches!(j.status, JobStatus::Pending | JobStatus::Running))
                .count();
            if inflight >= self.max_inflight {
                anyhow::bail!(
                    "too many in-flight jobs ({inflight}/{max}). Wait for a job to complete or increase HC_MCP_MAX_INFLIGHT.",
                    max = self.max_inflight
                );
            }
        }

        // Insert pending entry
        {
            let mut jobs = self.jobs.lock().await;
            jobs.insert(
                job_id.clone(),
                JobEntry {
                    status: JobStatus::Running,
                    proof_bytes: None,
                    template_id,
                    initial_acc,
                    final_acc,
                },
            );
        }

        // Spawn blocking prove task
        let jobs = self.jobs.clone();
        let jid = job_id.clone();
        tokio::task::spawn_blocking(move || {
            let result = run_prove(program, initial_acc, final_acc, zk_mask_degree);
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let mut map = jobs.lock().await;
                if let Some(entry) = map.get_mut(&jid) {
                    match result {
                        Ok(proof_bytes) => {
                            entry.status = JobStatus::Succeeded;
                            entry.proof_bytes = Some(proof_bytes);
                        }
                        Err(e) => {
                            entry.status = JobStatus::Failed {
                                error: e.to_string(),
                            };
                        }
                    }
                }
            });
        });

        Ok(job_id)
    }

    pub async fn poll(&self, job_id: &str) -> Result<JobStatus> {
        let jobs = self.jobs.lock().await;
        jobs.get(job_id)
            .map(|e| e.status.clone())
            .ok_or_else(|| anyhow::anyhow!("unknown job_id: {job_id}"))
    }

    pub async fn get_entry(&self, job_id: &str) -> Result<JobEntry> {
        let jobs = self.jobs.lock().await;
        jobs.get(job_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown job_id: {job_id}"))
    }
}

fn run_prove(
    program: Program,
    initial_acc: u64,
    final_acc: u64,
    zk_mask_degree: Option<usize>,
) -> Result<hc_sdk::types::ProofBytes> {
    // Phase 1A cutover: the MCP prove path now produces SOUND v5 proofs.
    // `production_v5` pins blowup ≥ 8, query_count ≥ 40, grinding_bits = 20 and
    // protocol version 5 (or 6 for ZK) so the proof re-verifies under the
    // default v5 floor used by `verify_proof_impl`.
    let config = ProverConfig::production_v5(2, 2, 80, 8, zk_mask_degree)?;
    let public_inputs = PublicInputs {
        initial_acc: GoldilocksField::from_u64(initial_acc),
        final_acc: GoldilocksField::from_u64(final_acc),
    };
    let proof_v5 = hc_prover::prove_v5(config, program, public_inputs)?;
    encode_proof_v5(&proof_v5)
}
