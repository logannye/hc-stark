use crate::protocol::{emit_progress, ProtocolFailure};
use anyhow::{bail, Context, Result};
use hc_plonky3::contracts::{
    air_package_schema, air_proof_bundle_schema, benchmark_report_schema, proof_bundle_schema,
    public_inputs_schema, trace_manifest_schema, workload_manifest_schema, AirPackageV1,
    AirProofBundleV1, InputGeneratorV1, ProofBundleV1, PublicInputsV1, TraceChunkV1,
    TraceManifestV1, WorkloadId, WorkloadManifestV1, MAX_AIR_BUNDLE_JSON_BYTES, MAX_AIR_JSON_BYTES,
    MAX_BUNDLE_JSON_BYTES, MAX_CUSTOM_TRACE_ROWS, MAX_MANIFEST_JSON_BYTES,
    MAX_TRACE_CHUNK_UNCOMPRESSED_BYTES, MAX_TRACE_MANIFEST_JSON_BYTES,
    MAX_TRACE_UNCOMPRESSED_BYTES, MIN_CUSTOM_TRACE_ROWS,
};
use hc_plonky3::{
    plan_declarative_statement,
    prove_resource_with_policy_observed_with_cancellation_at_checkpoint_dir,
    resume_resource_bounded_with_cancellation_observed, InternalProofBundle,
    ResourceBoundedUniStarkProver, UploadedTraceWorkload, WorkloadKind, COMPATIBILITY_PROFILE,
    PLONKY3_VERSION,
};
use hc_stream::{CheckpointManifestV2, ExecutionMode, ResourceMode, ResourcePolicyV1};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tinyzkp_contracts::{
    parse_strict_json, EngineEstimateResultV1, EngineOperationReportV1, EngineProgressEventV1,
    EngineVerifyResultV1, ReasonCodeV1, ReasonV1, ResourceEstimateV1, ResourceEstimatesV1,
    ResourcePreflightV1, ResourceUsageV1, SelectedModeV1,
};

pub fn validate_air(air_path: &Path) -> Result<()> {
    let air: AirPackageV1 = read_json_limited(air_path, MAX_AIR_JSON_BYTES)?;
    air.validate()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "valid": true,
            "air_digest_hex": hex_lower(&air.digest().map_err(anyhow::Error::msg)?),
            "trace_width": air.trace_width,
            "public_value_count": air.public_inputs.len(),
            "constraint_count": air.constraints.len(),
            "profile": air.profile,
            "expected_verifier": air.expected_verifier,
        }))?
    );
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument maps directly to one explicit CLI file contract"
)]
pub fn prove_air(
    air_path: &Path,
    trace_manifest_path: &Path,
    chunks_dir: &Path,
    public_inputs_path: &Path,
    policy_path: &Path,
    checkpoint_dir: &Path,
    output: &Path,
    reference: bool,
) -> Result<()> {
    let air: AirPackageV1 = read_json_limited(air_path, MAX_AIR_JSON_BYTES)?;
    let trace_manifest: TraceManifestV1 =
        read_json_limited(trace_manifest_path, MAX_TRACE_MANIFEST_JSON_BYTES)?;
    let public_inputs: PublicInputsV1 =
        read_json_limited(public_inputs_path, MAX_MANIFEST_JSON_BYTES)?;
    let policy: ResourcePolicyV1 = read_json_limited(policy_path, MAX_MANIFEST_JSON_BYTES)?;
    air.validate()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    trace_manifest
        .validate_for_air(&air)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    public_inputs
        .validate_for_air(&air)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    let workload = UploadedTraceWorkload::new(
        air.clone(),
        trace_manifest.clone(),
        public_inputs.values.clone(),
        chunks_dir,
    )
    .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    let mut execution_policy = policy;
    if reference {
        execution_policy.mode = ResourceMode::Memory;
    }
    let cancellation = hc_plonky3::CancellationToken::new();
    let handler_token = cancellation.clone();
    ctrlc::set_handler(move || handler_token.cancel())
        .context("failed to install the prover cancellation handler")?;
    let started = Instant::now();
    let mut scratch_high_water_bytes = 0;
    let checkpoint_path = checkpoint_dir.join("checkpoint.json");
    let planned = prove_resource_with_policy_observed_with_cancellation_at_checkpoint_dir(
        &workload,
        &execution_policy,
        checkpoint_dir,
        cancellation,
        |event| observe_air_operation(event, &mut scratch_high_water_bytes),
    )
    .map_err(|error| map_prover_error(error, checkpoint_path.is_file()))?;
    let selected_mode = planned.selected_mode;
    let bundle = AirProofBundleV1::from_proof(
        air,
        trace_manifest,
        public_inputs,
        planned.proof_bytes,
        hc_plonky3::release_identity(),
    )
    .map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    write_json_atomic(output, &bundle)?;
    emit_air_operation_report(selected_mode, scratch_high_water_bytes, started.elapsed())?;
    Ok(())
}

pub fn verify_air(bundle_path: &Path) -> Result<()> {
    let bundle: AirProofBundleV1 = read_json_limited(bundle_path, MAX_AIR_BUNDLE_JSON_BYTES)?;
    bundle
        .verify()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::VerificationRejected))?;
    write_stdout_result(&EngineVerifyResultV1 {
        schema_version: 1,
        engine_release_identity: hc_plonky3::release_identity(),
        accepted: true,
    })?;
    Ok(())
}

pub fn estimate_air(
    air_path: &Path,
    trace_manifest_path: &Path,
    public_inputs_path: &Path,
    policy_path: &Path,
) -> Result<()> {
    let air: AirPackageV1 = read_json_limited(air_path, MAX_AIR_JSON_BYTES)?;
    let trace_manifest: TraceManifestV1 =
        read_json_limited(trace_manifest_path, MAX_TRACE_MANIFEST_JSON_BYTES)?;
    let public_inputs: PublicInputsV1 =
        read_json_limited(public_inputs_path, MAX_MANIFEST_JSON_BYTES)?;
    let policy: ResourcePolicyV1 = read_json_limited(policy_path, MAX_MANIFEST_JSON_BYTES)?;
    air.validate()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    trace_manifest
        .validate_for_air(&air)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    public_inputs
        .validate_for_air(&air)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    let plan = plan_declarative_statement(
        air,
        trace_manifest.logical_rows,
        &public_inputs.values,
        &policy,
    )
    .map_err(|error| map_prover_error(error, false))?;
    let selected_mode = map_selected_mode(plan.selected_mode);
    write_stdout_result(&EngineEstimateResultV1 {
        schema_version: 1,
        engine_release_identity: hc_plonky3::release_identity(),
        selected_mode,
        estimates: ResourceEstimatesV1 {
            conventional: resource_estimate(plan.conventional_estimate),
            bounded: resource_estimate(plan.bounded_estimate),
        },
        preflight: ResourcePreflightV1 {
            ram_budget_bytes: policy.max_resident_bytes,
            scratch_budget_bytes: policy.max_scratch_bytes,
            available_scratch_bytes: Some(plan.preflight.available_scratch_bytes),
            memory_selection_threshold_bytes: plan.preflight.memory_selection_threshold_bytes,
            scratch_required_with_headroom_bytes: plan
                .preflight
                .scratch_required_with_headroom_bytes,
        },
    })?;
    Ok(())
}

pub fn resume_air(
    air_path: &Path,
    trace_manifest_path: &Path,
    chunks_dir: &Path,
    public_inputs_path: &Path,
    checkpoint_path: &Path,
    output: &Path,
) -> Result<()> {
    let air: AirPackageV1 = read_json_limited(air_path, MAX_AIR_JSON_BYTES)?;
    let trace_manifest: TraceManifestV1 =
        read_json_limited(trace_manifest_path, MAX_TRACE_MANIFEST_JSON_BYTES)?;
    let public_inputs: PublicInputsV1 =
        read_json_limited(public_inputs_path, MAX_MANIFEST_JSON_BYTES)?;
    air.validate()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    trace_manifest
        .validate_for_air(&air)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    public_inputs
        .validate_for_air(&air)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    let workload = UploadedTraceWorkload::new(
        air.clone(),
        trace_manifest.clone(),
        public_inputs.values.clone(),
        chunks_dir,
    )
    .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    let checkpoint = CheckpointManifestV2::read(checkpoint_path)
        .map_err(|error| map_stream_error(error, true))?;
    if checkpoint.release_hash
        != *blake3::hash(hc_plonky3::release_identity().as_bytes()).as_bytes()
    {
        return Err(ProtocolFailure::new(ReasonCodeV1::CheckpointReleaseMismatch).into());
    }
    let cancellation = hc_plonky3::CancellationToken::new();
    let handler_token = cancellation.clone();
    ctrlc::set_handler(move || handler_token.cancel())
        .context("failed to install the declarative AIR resume cancellation handler")?;
    let started = Instant::now();
    let mut scratch_high_water_bytes = 0;
    let proof_bytes = resume_resource_bounded_with_cancellation_observed(
        checkpoint_path,
        &workload,
        cancellation,
        |event| observe_air_operation(event, &mut scratch_high_water_bytes),
    )
    .map_err(|error| map_prover_error(error, checkpoint_path.is_file()))?;
    let bundle = AirProofBundleV1::from_proof(
        air,
        trace_manifest,
        public_inputs,
        proof_bytes,
        hc_plonky3::release_identity(),
    )
    .map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    write_json_atomic(output, &bundle)?;
    emit_air_operation_report(
        ExecutionMode::Scratch,
        scratch_high_water_bytes,
        started.elapsed(),
    )?;
    Ok(())
}

pub fn pack_trace(
    air_path: &Path,
    trace_path: &Path,
    logical_rows: u64,
    output_dir: &Path,
    chunk_uncompressed_bytes: u64,
) -> Result<()> {
    let air: AirPackageV1 = read_json_limited(air_path, MAX_AIR_JSON_BYTES)?;
    air.validate().map_err(anyhow::Error::msg)?;
    if !(MIN_CUSTOM_TRACE_ROWS..=MAX_CUSTOM_TRACE_ROWS).contains(&logical_rows)
        || !logical_rows.is_power_of_two()
    {
        bail!("trace rows must be a power of two from 2^10 through 2^24");
    }
    if chunk_uncompressed_bytes == 0
        || chunk_uncompressed_bytes > MAX_TRACE_CHUNK_UNCOMPRESSED_BYTES
        || !chunk_uncompressed_bytes.is_multiple_of(8)
    {
        bail!("chunk bytes must be a nonzero multiple of 8 and at most 256 MiB");
    }
    let expected_bytes = logical_rows
        .checked_mul(u64::from(air.trace_width))
        .and_then(|value| value.checked_mul(8))
        .context("trace size overflow")?;
    let row_bytes = u64::from(air.trace_width) * 8;
    let chunk_uncompressed_bytes = chunk_uncompressed_bytes - chunk_uncompressed_bytes % row_bytes;
    if chunk_uncompressed_bytes == 0 {
        bail!("chunk bytes must hold at least one complete trace row");
    }
    if expected_bytes > MAX_TRACE_UNCOMPRESSED_BYTES {
        bail!("expanded trace exceeds the 32 GiB beta limit");
    }
    let metadata = fs::symlink_metadata(trace_path)
        .with_context(|| format!("stat {}", trace_path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() != expected_bytes {
        bail!(
            "trace must be a regular file containing exactly {expected_bytes} bytes of row-major Goldilocks u64 little-endian values"
        );
    }

    fs::create_dir_all(output_dir)?;
    let mut input = fs::File::open(trace_path)?;
    let mut trace_hasher = blake3::Hasher::new();
    let mut chunks = Vec::new();
    let mut remaining = expected_bytes;
    let mut index = 0u32;
    while remaining > 0 {
        let this_chunk = remaining.min(chunk_uncompressed_bytes);
        let mut raw = vec![0u8; usize::try_from(this_chunk)?];
        input.read_exact(&mut raw)?;
        for encoded in raw.chunks_exact(8) {
            let value = u64::from_le_bytes(encoded.try_into().expect("eight-byte chunk"));
            if value >= hc_plonky3::GOLDILOCKS_MODULUS_U64 {
                return Err(ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid).into());
            }
        }
        trace_hasher.update(&raw);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3)?;
        let chunk_name = format!("chunk-{index:06}.zst");
        write_bytes_atomic(&output_dir.join(&chunk_name), &compressed)?;
        chunks.push(TraceChunkV1 {
            index,
            compressed_bytes: compressed.len() as u64,
            uncompressed_bytes: this_chunk,
            blake3_hex: hex_lower(blake3::hash(&compressed).as_bytes()),
        });
        remaining -= this_chunk;
        index = index.checked_add(1).context("too many trace chunks")?;
    }
    let manifest = TraceManifestV1 {
        schema_version: 1,
        air_digest_hex: hex_lower(&air.digest().map_err(anyhow::Error::msg)?),
        trace_digest_hex: hex_lower(trace_hasher.finalize().as_bytes()),
        logical_rows,
        trace_width: air.trace_width,
        field_encoding: "goldilocks_u64_le".into(),
        compression: "zstd".into(),
        chunk_uncompressed_bytes,
        chunks,
    };
    manifest
        .validate_for_air(&air)
        .map_err(anyhow::Error::msg)?;
    let manifest_path = output_dir.join("trace-manifest-v1.json");
    write_json_atomic(&manifest_path, &manifest)?;
    println!("{}", manifest_path.display());
    Ok(())
}

pub fn prove(manifest_path: &Path, output: &Path) -> Result<()> {
    let manifest: WorkloadManifestV1 = read_json_limited(manifest_path, MAX_MANIFEST_JSON_BYTES)?;
    manifest.validate().map_err(anyhow::Error::msg)?;
    emit_event(
        "prove_started",
        serde_json::json!({
            "phase": "trace",
            "workload_id": manifest.workload_id,
            "logical_rows": manifest.logical_rows,
            "profile": manifest.profile,
        }),
    );
    let prover = ResourceBoundedUniStarkProver::new(manifest.resource_policy.clone())
        .map_err(anyhow::Error::msg)?;
    let cancellation = hc_plonky3::CancellationToken::new();
    let handler_token = cancellation.clone();
    ctrlc::set_handler(move || handler_token.cancel())
        .context("failed to install the prover cancellation handler")?;
    let internal = match prover.prove_with_events_and_cancellation(
        manifest.workload().map_err(anyhow::Error::msg)?,
        manifest.logical_rows,
        cancellation,
        emit_backend_event,
    ) {
        Ok(internal) => internal,
        Err(hc_plonky3::BackendError::Bounded(hc_plonky3::BoundedProverError::Cancelled)) => {
            emit_event(
                "prove_cancelled",
                serde_json::json!({
                    "phase": "checkpoint_boundary",
                }),
            );
            bail!("proving was cancelled")
        }
        Err(error) => {
            emit_event(
                "prove_failed",
                serde_json::json!({
                    "phase": "unknown",
                    "error": error.to_string(),
                }),
            );
            return Err(anyhow::Error::msg(error));
        }
    };
    let release = hc_plonky3::release_identity();
    let bundle =
        ProofBundleV1::from_internal(manifest, internal, release).map_err(anyhow::Error::msg)?;
    bundle.verify().map_err(anyhow::Error::msg)?;
    write_json_atomic(output, &bundle)?;
    emit_event(
        "prove_completed",
        serde_json::json!({
            "phase": "proof_assembly",
            "progress": 1.0,
            "output": output,
            "manifest_digest": bundle.manifest_digest_hex,
        }),
    );
    Ok(())
}

pub fn verify(bundle_path: &Path) -> Result<()> {
    let bundle: ProofBundleV1 = read_json_limited(bundle_path, MAX_BUNDLE_JSON_BYTES)?;
    bundle
        .verify()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::VerificationRejected))?;
    write_stdout_result(&EngineVerifyResultV1 {
        schema_version: 1,
        engine_release_identity: hc_plonky3::release_identity(),
        accepted: true,
    })
}

pub fn resume(checkpoint_path: &Path, output: &Path) -> Result<()> {
    let checkpoint = CheckpointManifestV2::read(checkpoint_path).map_err(anyhow::Error::msg)?;
    emit_event(
        "resume_started",
        serde_json::json!({
            "phase": checkpoint.completed_phase.to_string(),
            "checkpoint": checkpoint_path,
        }),
    );
    let cancellation = hc_plonky3::CancellationToken::new();
    let handler_token = cancellation.clone();
    ctrlc::set_handler(move || handler_token.cancel())
        .context("failed to install the resume cancellation handler")?;
    let resumed = match hc_plonky3::resume_resource_bounded_cancelable_observed(
        checkpoint_path,
        cancellation,
        emit_backend_event,
    ) {
        Ok(resumed) => resumed,
        Err(hc_plonky3::BoundedProverError::Cancelled) => {
            emit_event(
                "resume_cancelled",
                serde_json::json!({
                    "phase": "checkpoint_boundary",
                    "checkpoint": checkpoint_path,
                }),
            );
            bail!("proof resume was cancelled")
        }
        Err(error) => {
            emit_event(
                "resume_failed",
                serde_json::json!({
                    "phase": checkpoint.completed_phase.to_string(),
                    "checkpoint": checkpoint_path,
                    "error": error.to_string(),
                }),
            );
            return Err(anyhow::Error::msg(error));
        }
    };
    let (workload_id, input_generator, workload) = match resumed.workload_id.as_str() {
        "fibonacci" if resumed.public_values.len() == 3 => (
            WorkloadId::Fibonacci,
            InputGeneratorV1::Fibonacci {
                initial_a: resumed.public_values[0],
                initial_b: resumed.public_values[1],
            },
            WorkloadKind::Fibonacci {
                initial_a: resumed.public_values[0],
                initial_b: resumed.public_values[1],
            },
        ),
        "poseidon2_goldilocks" if resumed.public_values.is_empty() => (
            WorkloadId::Poseidon2Goldilocks,
            InputGeneratorV1::Poseidon2 { seed: 0 },
            WorkloadKind::Poseidon2,
        ),
        _ => bail!("checkpoint workload cannot be packaged by the built-in CLI"),
    };
    let manifest = WorkloadManifestV1 {
        schema_version: 1,
        workload_id,
        backend: "plonky3".into(),
        profile: COMPATIBILITY_PROFILE.into(),
        input_generator,
        logical_rows: resumed.logical_rows,
        deterministic_seed: 0,
        resource_policy: resumed.resource_policy,
        expected_verifier: "p3_uni_stark_0.6.1".into(),
    };
    let internal = InternalProofBundle {
        schema_version: 1,
        compatibility_profile: COMPATIBILITY_PROFILE.into(),
        plonky3_version: PLONKY3_VERSION.into(),
        workload,
        logical_rows: resumed.logical_rows,
        public_values: resumed.public_values,
        proof_digest: *blake3::hash(&resumed.proof_bytes).as_bytes(),
        proof_bytes: resumed.proof_bytes,
    };
    let release = hc_plonky3::release_identity();
    let bundle =
        ProofBundleV1::from_internal(manifest, internal, release).map_err(anyhow::Error::msg)?;
    bundle.verify().map_err(anyhow::Error::msg)?;
    write_json_atomic(output, &bundle)?;
    emit_event(
        "resume_completed",
        serde_json::json!({
            "phase": "proof_assembly",
            "output": output,
            "proof_bytes": bundle.proof_base64url.len(),
        }),
    );
    Ok(())
}

pub fn export_schemas(output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;
    write_json_atomic(
        &output_dir.join("workload-manifest-v1.schema.json"),
        &workload_manifest_schema(),
    )?;
    write_json_atomic(
        &output_dir.join("proof-bundle-v1.schema.json"),
        &proof_bundle_schema(),
    )?;
    write_json_atomic(
        &output_dir.join("benchmark-report-v1.schema.json"),
        &benchmark_report_schema(),
    )?;
    write_json_atomic(
        &output_dir.join("air-package-v1.schema.json"),
        &air_package_schema(),
    )?;
    write_json_atomic(
        &output_dir.join("trace-manifest-v1.schema.json"),
        &trace_manifest_schema(),
    )?;
    write_json_atomic(
        &output_dir.join("public-inputs-v1.schema.json"),
        &public_inputs_schema(),
    )?;
    write_json_atomic(
        &output_dir.join("air-proof-bundle-v1.schema.json"),
        &air_proof_bundle_schema(),
    )?;
    for name in tinyzkp_contracts::PUBLISHED_SCHEMA_NAMES {
        let schema = tinyzkp_contracts::schema_by_name(name)
            .ok_or_else(|| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
        write_json_atomic(&output_dir.join(name), &schema)?;
    }
    println!("generated schemas in {}", output_dir.display());
    Ok(())
}

pub fn benchmark_guidance(manifest: &Path, mode: &str, report: &Path) -> Result<()> {
    let _: WorkloadManifestV1 = read_json_limited(manifest, MAX_MANIFEST_JSON_BYTES)?;
    let harness = std::env::var_os("TINYZKP_BENCHMARK_HARNESS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("scripts/benchmark/run_plonky3_cgroup.py"));
    if !harness.is_file() {
        bail!(
            "Linux cgroup benchmark harness not found at {}; set TINYZKP_BENCHMARK_HARNESS",
            harness.display()
        );
    }
    let cli = std::env::current_exe()?;
    let status = std::process::Command::new("python3")
        .arg(harness)
        .arg("--manifest")
        .arg(manifest)
        .arg("--mode")
        .arg(mode)
        .arg("--report")
        .arg(report)
        .arg("--hc-cli")
        .arg(cli)
        .status()?;
    if !status.success() {
        bail!("Linux cgroup benchmark harness failed with {status}");
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchmarkWorkerResult {
    pub schema_version: u32,
    pub mode: String,
    pub manifest_digest_hex: String,
    pub proof_size_bytes: u64,
    pub prover_scratch_high_water_bytes: u64,
    pub peak_rss_bytes: u64,
    pub verification_time_ms: u64,
    pub verification_succeeded: bool,
}

pub fn benchmark_worker(manifest_path: &Path, mode: &str, output: &Path) -> Result<()> {
    let manifest: WorkloadManifestV1 = read_json_limited(manifest_path, MAX_MANIFEST_JSON_BYTES)?;
    manifest.validate().map_err(anyhow::Error::msg)?;
    let workload = manifest.workload().map_err(anyhow::Error::msg)?;
    let mut prover_scratch_high_water_bytes = 0;
    let internal = match mode {
        "conventional" => {
            ResourceBoundedUniStarkProver::prove_reference(workload, manifest.logical_rows)
        }
        "bounded" => ResourceBoundedUniStarkProver::new(manifest.resource_policy.clone()).and_then(
            |prover| {
                prover.prove_with_events(workload, manifest.logical_rows, |event| {
                    if let hc_plonky3::ProverEventV1::Phase { resource_usage, .. } = event {
                        prover_scratch_high_water_bytes =
                            prover_scratch_high_water_bytes.max(resource_usage.scratch_bytes);
                    }
                })
            },
        ),
        _ => bail!("benchmark worker mode must be conventional or bounded"),
    }
    .map_err(anyhow::Error::msg)?;
    let proof_size_bytes = internal.proof_bytes.len() as u64;
    let verify_start = std::time::Instant::now();
    ResourceBoundedUniStarkProver::verify(&internal).map_err(anyhow::Error::msg)?;
    let verification_time_ms = verify_start.elapsed().as_millis() as u64;
    let peak_rss_bytes = process_peak_rss_bytes();
    let manifest_digest = manifest.digest().map_err(anyhow::Error::msg)?;
    let result = BenchmarkWorkerResult {
        schema_version: 1,
        mode: mode.into(),
        manifest_digest_hex: manifest_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        proof_size_bytes,
        prover_scratch_high_water_bytes,
        peak_rss_bytes,
        verification_time_ms,
        verification_succeeded: true,
    };
    write_json_atomic(output, &result)
}

#[cfg(target_os = "linux")]
fn process_peak_rss_bytes() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_proc_peak_rss_bytes(&status))
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
const fn process_peak_rss_bytes() -> u64 {
    0
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_peak_rss_bytes(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

fn read_json_limited<T: DeserializeOwned>(path: &Path, max_bytes: usize) -> Result<T> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
    }
    if metadata.len() > max_bytes as u64 {
        return Err(ProtocolFailure::new(ReasonCodeV1::InputLimitExceeded).into());
    }
    let bytes = fs::read(path).map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    parse_strict_json(&bytes)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid).into())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = temp_path(path);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = temp_path(path);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
}

fn emit_event(kind: &str, fields: serde_json::Value) {
    let mut event = serde_json::Map::new();
    event.insert("schema_version".into(), serde_json::Value::from(1));
    event.insert("event".into(), serde_json::Value::String(kind.into()));
    if let Some(fields) = fields.as_object() {
        for (key, value) in fields {
            if key != "schema_version" && key != "event" {
                event.insert(key.clone(), value.clone());
            }
        }
    }
    eprintln!("{}", serde_json::Value::Object(event));
}

fn emit_backend_event(event: &hc_plonky3::ProverEventV1) {
    let release = hc_plonky3::release_identity();
    let typed = match event {
        hc_plonky3::ProverEventV1::ResourceEstimate { .. } => {
            EngineProgressEventV1::simple(&release, "resource_estimate", "resource_estimate")
        }
        hc_plonky3::ProverEventV1::Phase {
            phase,
            completed_phases,
            total_phases,
            checkpoint_path,
            resource_usage,
        } => EngineProgressEventV1 {
            schema_version: 1,
            engine_release_identity: release.clone(),
            event: "phase".into(),
            stage: "proving".into(),
            phase: Some(phase.to_string()),
            completed_phases: Some(*completed_phases),
            total_phases: Some(*total_phases),
            progress: (*total_phases > 0)
                .then_some(f64::from(*completed_phases) / f64::from(*total_phases)),
            resource_usage: Some(ResourceUsageV1 {
                resident_bytes: resource_usage.resident_bytes,
                scratch_bytes: resource_usage.scratch_bytes,
            }),
            checkpoint_durable: Some(checkpoint_path.is_some()),
        },
    };
    debug_assert!(typed.validate(&release));
    emit_progress(&typed);
}

fn observe_air_operation(event: &hc_plonky3::ProverEventV1, scratch_high_water_bytes: &mut u64) {
    if let hc_plonky3::ProverEventV1::Phase { resource_usage, .. } = event {
        *scratch_high_water_bytes = (*scratch_high_water_bytes).max(resource_usage.scratch_bytes);
    }
    emit_backend_event(event);
}

fn emit_air_operation_report(
    selected_mode: ExecutionMode,
    scratch_high_water_bytes: u64,
    elapsed: std::time::Duration,
) -> Result<()> {
    let report = EngineOperationReportV1 {
        schema_version: 1,
        engine_release_identity: hc_plonky3::release_identity(),
        selected_mode: map_selected_mode(selected_mode),
        peak_resident_bytes: process_peak_rss_bytes(),
        scratch_high_water_bytes,
        wall_time_millis: u64::try_from(elapsed.as_millis())
            .unwrap_or(u64::MAX)
            .max(1),
    };
    write_stdout_result(&report)
}

fn map_selected_mode(mode: ExecutionMode) -> SelectedModeV1 {
    match mode {
        ExecutionMode::Memory => SelectedModeV1::Conventional,
        ExecutionMode::Scratch => SelectedModeV1::Bounded,
    }
}

fn resource_estimate(estimate: hc_stream::ResourceEstimate) -> ResourceEstimateV1 {
    ResourceEstimateV1 {
        peak_resident_bytes: estimate.peak_resident_bytes,
        scratch_high_water_bytes: estimate.scratch_high_water_bytes,
        total_read_bytes: estimate.total_read_bytes,
        total_write_bytes: estimate.total_write_bytes,
    }
}

fn write_stdout_result<T: Serialize>(value: &T) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    stdout
        .write_all(b"\n")
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    stdout
        .flush()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    Ok(())
}

fn map_prover_error(
    error: hc_plonky3::BoundedProverError,
    checkpoint_present: bool,
) -> ProtocolFailure {
    use hc_plonky3::BoundedProverError;
    match error {
        BoundedProverError::UnsupportedProfile => {
            ProtocolFailure::new(ReasonCodeV1::UnsupportedProfile)
        }
        BoundedProverError::Verification(_) => {
            ProtocolFailure::new(ReasonCodeV1::VerificationRejected)
        }
        BoundedProverError::InvalidCheckpoint | BoundedProverError::CheckpointPayload(_) => {
            ProtocolFailure::new(ReasonCodeV1::CheckpointCorrupt)
        }
        BoundedProverError::CheckpointStateExists => {
            ProtocolFailure::new(ReasonCodeV1::JobStateExists)
        }
        BoundedProverError::Cancelled if checkpoint_present => ProtocolFailure::interrupted(true),
        BoundedProverError::Cancelled => ProtocolFailure::new(ReasonCodeV1::InternalError),
        BoundedProverError::Stream(error) => map_stream_error(error, checkpoint_present),
        BoundedProverError::Workload(_) => {
            ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid)
        }
        BoundedProverError::Io(error) if error.kind() == std::io::ErrorKind::StorageFull => {
            ProtocolFailure::new(ReasonCodeV1::ScratchSpaceInsufficient)
        }
        _ => ProtocolFailure::new(ReasonCodeV1::InternalError),
    }
}

fn map_stream_error(error: hc_stream::StreamError, checkpoint_context: bool) -> ProtocolFailure {
    match error {
        hc_stream::StreamError::InvalidPolicy(_) => {
            ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid)
        }
        hc_stream::StreamError::ResourceLimit {
            resource: "resident memory",
            required,
            cap,
        } => ProtocolFailure {
            reason: ReasonV1::new(ReasonCodeV1::RamBudgetInsufficient).resource(
                required,
                None,
                Some(cap),
            ),
            resumable: false,
            checkpoint_present: false,
        },
        hc_stream::StreamError::ResourceLimit {
            resource,
            required,
            cap,
        } if resource.starts_with("available scratch") => ProtocolFailure {
            reason: ReasonV1::new(ReasonCodeV1::ScratchSpaceInsufficient).resource(
                required,
                Some(cap),
                None,
            ),
            resumable: false,
            checkpoint_present: false,
        },
        hc_stream::StreamError::ResourceLimit { required, cap, .. } => ProtocolFailure {
            reason: ReasonV1::new(ReasonCodeV1::ScratchBudgetInsufficient).resource(
                required,
                None,
                Some(cap),
            ),
            resumable: false,
            checkpoint_present: false,
        },
        hc_stream::StreamError::Corrupt(_) | hc_stream::StreamError::CheckpointMismatch => {
            ProtocolFailure::new(ReasonCodeV1::CheckpointCorrupt)
        }
        hc_stream::StreamError::UnsafePath => ProtocolFailure::new(ReasonCodeV1::UnsafePath),
        hc_stream::StreamError::Io(error) if error.kind() == std::io::ErrorKind::StorageFull => {
            ProtocolFailure::new(ReasonCodeV1::ScratchSpaceInsufficient)
        }
        hc_stream::StreamError::Io(error)
            if checkpoint_context && error.kind() == std::io::ErrorKind::NotFound =>
        {
            ProtocolFailure::new(ReasonCodeV1::CheckpointMissing)
        }
        hc_stream::StreamError::Json(_) if checkpoint_context => {
            ProtocolFailure::new(ReasonCodeV1::CheckpointCorrupt)
        }
        _ => ProtocolFailure::new(ReasonCodeV1::InternalError),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::parse_proc_peak_rss_bytes;

    #[test]
    fn parses_linux_process_high_water_mark_in_kibibytes() {
        assert_eq!(
            parse_proc_peak_rss_bytes("Name:\ttest\nVmHWM:\t2048 kB\n"),
            Some(2 * 1024 * 1024)
        );
        assert_eq!(parse_proc_peak_rss_bytes("VmRSS:\t2048 kB\n"), None);
        assert_eq!(parse_proc_peak_rss_bytes("VmHWM:\tnot-a-number kB\n"), None);
    }
}
