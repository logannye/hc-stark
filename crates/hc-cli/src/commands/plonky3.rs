use anyhow::{bail, Context, Result};
use hc_plonky3::contracts::{
    benchmark_report_schema, proof_bundle_schema, workload_manifest_schema, ProofBundleV1,
    WorkloadManifestV1, MAX_BUNDLE_JSON_BYTES, MAX_MANIFEST_JSON_BYTES,
};
use hc_plonky3::ResourceBoundedUniStarkProver;
use hc_stream::{CheckpointManifestV2, ResourceEstimate, ResourcePolicyV1};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn prove(manifest_path: &Path, output: &Path) -> Result<()> {
    let manifest: WorkloadManifestV1 = read_json_limited(manifest_path, MAX_MANIFEST_JSON_BYTES)?;
    manifest.validate().map_err(anyhow::Error::msg)?;
    let prover = ResourceBoundedUniStarkProver::new(manifest.resource_policy.clone())
        .map_err(anyhow::Error::msg)?;
    let internal = prover
        .prove(
            manifest.workload().map_err(anyhow::Error::msg)?,
            manifest.logical_rows,
        )
        .map_err(anyhow::Error::msg)?;
    let release =
        std::env::var("HC_RELEASE_SHA").unwrap_or_else(|_| "development-unreleased".into());
    let bundle =
        ProofBundleV1::from_internal(manifest, internal, release).map_err(anyhow::Error::msg)?;
    bundle.verify().map_err(anyhow::Error::msg)?;
    write_json_atomic(output, &bundle)?;
    println!(
        "verified official Plonky3 proof bundle written to {}",
        output.display()
    );
    Ok(())
}

pub fn verify(bundle_path: &Path) -> Result<()> {
    let bundle: ProofBundleV1 = read_json_limited(bundle_path, MAX_BUNDLE_JSON_BYTES)?;
    bundle.verify().map_err(anyhow::Error::msg)?;
    println!("proof accepted by the official p3-uni-stark verifier");
    Ok(())
}

pub fn doctor(policy_path: &Path) -> Result<()> {
    let policy: ResourcePolicyV1 = read_json_limited(policy_path, MAX_MANIFEST_JSON_BYTES)?;
    let estimate = ResourceEstimate {
        peak_resident_bytes: 16 * 1024 * 1024,
        scratch_high_water_bytes: 1,
        total_read_bytes: 0,
        total_write_bytes: 0,
        phases: vec![],
    };
    let report = policy.preflight(estimate).map_err(anyhow::Error::msg)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

pub fn resume(checkpoint_path: &Path, _output: &Path) -> Result<()> {
    let checkpoint = CheckpointManifestV2::read(checkpoint_path).map_err(anyhow::Error::msg)?;
    bail!(
        "checkpoint '{}' (phase '{}') is structurally valid, but Plonky3 challenger-state continuation is not release-enabled; refusing a non-deterministic restart",
        checkpoint_path.display(),
        checkpoint.completed_phase
    )
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
    println!("generated schemas in {}", output_dir.display());
    Ok(())
}

pub fn benchmark_guidance(
    manifest: &Path,
    baseline: &str,
    candidate: &str,
    report: &Path,
) -> Result<()> {
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
        .arg("--baseline")
        .arg(baseline)
        .arg("--candidate")
        .arg(candidate)
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
    pub verification_time_ms: u64,
    pub verification_succeeded: bool,
}

pub fn benchmark_worker(manifest_path: &Path, mode: &str, output: &Path) -> Result<()> {
    let manifest: WorkloadManifestV1 = read_json_limited(manifest_path, MAX_MANIFEST_JSON_BYTES)?;
    manifest.validate().map_err(anyhow::Error::msg)?;
    let workload = manifest.workload().map_err(anyhow::Error::msg)?;
    let internal = match mode {
        "conventional" => {
            ResourceBoundedUniStarkProver::prove_reference(workload, manifest.logical_rows)
        }
        "bounded" => ResourceBoundedUniStarkProver::new(manifest.resource_policy.clone())
            .and_then(|prover| prover.prove(workload, manifest.logical_rows)),
        _ => bail!("benchmark worker mode must be conventional or bounded"),
    }
    .map_err(anyhow::Error::msg)?;
    let proof_size_bytes = internal.proof_bytes.len() as u64;
    let verify_start = std::time::Instant::now();
    ResourceBoundedUniStarkProver::verify(&internal).map_err(anyhow::Error::msg)?;
    let verification_time_ms = verify_start.elapsed().as_millis() as u64;
    let manifest_digest = manifest.digest().map_err(anyhow::Error::msg)?;
    let result = BenchmarkWorkerResult {
        schema_version: 1,
        mode: mode.into(),
        manifest_digest_hex: manifest_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        proof_size_bytes,
        verification_time_ms,
        verification_succeeded: true,
    };
    write_json_atomic(output, &result)
}

fn read_json_limited<T: DeserializeOwned>(path: &Path, max_bytes: usize) -> Result<T> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if metadata.len() > max_bytes as u64 {
        bail!(
            "{} exceeds the {} byte contract limit",
            path.display(),
            max_bytes
        );
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
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

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
}
