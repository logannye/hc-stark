//! Local artifact SDK for TinyZKP's resource-bounded Plonky3 backend.
//!
//! This package deliberately contains no hosted proving, polling, template,
//! receipt, or remote-verification client. It constructs and validates the
//! versioned local artifacts and can invoke a pinned `hc-cli` binary.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

pub use hc_plonky3::contracts::{
    canonical_json_bytes_v1, BenchmarkMode, BenchmarkReportV1, InputGeneratorV1, ProofBundleV1,
    ReleaseProvenanceV1, WorkloadId, WorkloadManifestV1, MAX_BUNDLE_JSON_BYTES,
    MAX_MANIFEST_JSON_BYTES, MAX_PROOF_BYTES, MAX_REPORT_JSON_BYTES,
};
pub use hc_plonky3::{
    ResourceBoundedUniStarkProver, ResourceBoundedWorkload, WorkloadKind, COMPATIBILITY_PROFILE,
    PLONKY3_VERSION,
};
pub use hc_stream::{CheckpointPolicy, ResourceMode, ResourcePolicyV1};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("artifact exceeds its {limit} byte limit: {actual} bytes")]
    SizeLimit { limit: usize, actual: u64 },
    #[error("artifact JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("artifact validation failed: {0}")]
    Validation(String),
    #[error("CLI invocation failed with status {0}")]
    Cli(ExitStatus),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct ManifestBuilder {
    workload_id: WorkloadId,
    input_generator: InputGeneratorV1,
    logical_rows: u64,
    resource_policy: ResourcePolicyV1,
}

impl ManifestBuilder {
    pub fn fibonacci(
        initial_a: u64,
        initial_b: u64,
        logical_rows: u64,
        resource_policy: ResourcePolicyV1,
    ) -> Self {
        Self {
            workload_id: WorkloadId::Fibonacci,
            input_generator: InputGeneratorV1::Fibonacci {
                initial_a,
                initial_b,
            },
            logical_rows,
            resource_policy,
        }
    }

    pub fn poseidon2(logical_rows: u64, resource_policy: ResourcePolicyV1) -> Self {
        Self {
            workload_id: WorkloadId::Poseidon2Goldilocks,
            input_generator: InputGeneratorV1::Poseidon2 { seed: 0 },
            logical_rows,
            resource_policy,
        }
    }

    pub fn build(self) -> Result<WorkloadManifestV1> {
        let manifest = WorkloadManifestV1 {
            schema_version: 1,
            workload_id: self.workload_id,
            backend: "plonky3".into(),
            profile: COMPATIBILITY_PROFILE.into(),
            input_generator: self.input_generator,
            logical_rows: self.logical_rows,
            deterministic_seed: 0,
            resource_policy: self.resource_policy,
            expected_verifier: "p3_uni_stark_0.6.1".into(),
        };
        manifest
            .validate()
            .map_err(|error| Error::Validation(error.to_string()))?;
        Ok(manifest)
    }
}

pub fn manifest_digest(manifest: &WorkloadManifestV1) -> Result<[u8; 32]> {
    manifest
        .digest()
        .map_err(|error| Error::Validation(error.to_string()))
}

pub fn verify_bundle(bundle: &ProofBundleV1) -> Result<()> {
    bundle
        .verify()
        .map_err(|error| Error::Validation(error.to_string()))
}

pub fn load_manifest(path: impl AsRef<Path>) -> Result<WorkloadManifestV1> {
    let manifest: WorkloadManifestV1 = read_json_limited(path, MAX_MANIFEST_JSON_BYTES)?;
    manifest
        .validate()
        .map_err(|error| Error::Validation(error.to_string()))?;
    Ok(manifest)
}

pub fn load_bundle(path: impl AsRef<Path>) -> Result<ProofBundleV1> {
    let bundle: ProofBundleV1 = read_json_limited(path, MAX_BUNDLE_JSON_BYTES)?;
    bundle
        .verify()
        .map_err(|error| Error::Validation(error.to_string()))?;
    Ok(bundle)
}

pub fn load_report(path: impl AsRef<Path>) -> Result<BenchmarkReportV1> {
    let report: BenchmarkReportV1 = read_json_limited(path, MAX_REPORT_JSON_BYTES)?;
    report
        .validate()
        .map_err(|error| Error::Validation(error.to_string()))?;
    Ok(report)
}

pub fn write_manifest(path: impl AsRef<Path>, manifest: &WorkloadManifestV1) -> Result<()> {
    manifest
        .validate()
        .map_err(|error| Error::Validation(error.to_string()))?;
    write_json(path, manifest)
}

#[derive(Clone, Debug)]
pub struct Cli {
    binary: PathBuf,
}

impl Cli {
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    pub fn prove(&self, manifest: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
        self.run([
            "plonky3",
            "prove",
            "--manifest",
            path_arg(manifest.as_ref())?,
            "--output",
            path_arg(output.as_ref())?,
        ])
    }

    pub fn resume(&self, checkpoint: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
        self.run([
            "plonky3",
            "resume",
            "--checkpoint",
            path_arg(checkpoint.as_ref())?,
            "--output",
            path_arg(output.as_ref())?,
        ])
    }

    pub fn verify(&self, bundle: impl AsRef<Path>) -> Result<()> {
        self.run(["plonky3", "verify", "--bundle", path_arg(bundle.as_ref())?])
    }

    fn run<const N: usize>(&self, arguments: [&str; N]) -> Result<()> {
        let status = Command::new(&self.binary).args(arguments).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Cli(status))
        }
    }
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::Validation("CLI paths must be valid UTF-8".into()))
}

fn read_json_limited<T: DeserializeOwned>(path: impl AsRef<Path>, limit: usize) -> Result<T> {
    let path = path.as_ref();
    let metadata = fs::metadata(path)?;
    if metadata.len() > limit as u64 {
        return Err(Error::SizeLimit {
            limit,
            actual: metadata.len(),
        });
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(root: &Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 128 * 1024 * 1024,
            max_scratch_bytes: 2 * 1024 * 1024 * 1024,
            scratch_dir: root.into(),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::RetainOnFailure,
        }
    }

    #[test]
    fn builder_produces_valid_canonical_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = ManifestBuilder::fibonacci(0, 1, 1024, policy(dir.path()))
            .build()
            .unwrap();
        assert_eq!(
            manifest_digest(&manifest).unwrap(),
            manifest.digest().unwrap()
        );
        assert!(!canonical_json_bytes_v1(&manifest).unwrap().is_empty());
    }

    #[test]
    fn shared_manifest_vector_matches_core_digest() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/plonky3/fibonacci-16.manifest.json");
        let manifest = load_manifest(path).unwrap();
        assert_eq!(
            manifest_digest(&manifest).unwrap(),
            [
                0x9d, 0x13, 0x16, 0x02, 0xe2, 0x74, 0x28, 0xca, 0x29, 0x0c, 0x5c, 0xa8,
                0x7d, 0x54, 0x3d, 0x08, 0x58, 0x73, 0x84, 0x0e, 0x4d, 0xba, 0x22, 0xdd,
                0x3d, 0x80, 0x74, 0x94, 0x5e, 0x57, 0xef, 0xcd,
            ]
        );
    }

    #[test]
    fn maximum_goldilocks_manifest_matches_cross_language_digest() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/plonky3/fibonacci-max-field.manifest.json");
        let manifest = load_manifest(path).unwrap();
        assert_eq!(
            manifest_digest(&manifest).unwrap(),
            [
                0xd6, 0x6d, 0x86, 0x84, 0x41, 0x13, 0x7e, 0x6d, 0xb9, 0x64, 0xad, 0xd9,
                0xd7, 0xe4, 0xa2, 0x16, 0x4c, 0xa3, 0xa7, 0x22, 0xc6, 0x6e, 0x73, 0xcb,
                0xf0, 0x6c, 0x2a, 0x57, 0x6e, 0xfe, 0xe6, 0x53,
            ]
        );
    }

    #[test]
    fn shared_bundle_fixture_rejects_truncation_and_dependency_skew() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/plonky3/fibonacci-16.bundle.json");
        let bundle = load_bundle(&path).unwrap();
        verify_bundle(&bundle).unwrap();

        let source = fs::read(&path).unwrap();
        let mut truncated: serde_json::Value = serde_json::from_slice(&source).unwrap();
        let proof = truncated["proof_base64url"].as_str().unwrap();
        truncated["proof_base64url"] = proof[..proof.len() - 1].into();
        let dir = tempfile::tempdir().unwrap();
        let truncated_path = dir.path().join("truncated.json");
        fs::write(&truncated_path, serde_json::to_vec(&truncated).unwrap()).unwrap();
        assert!(load_bundle(truncated_path).is_err());

        let mut skewed: serde_json::Value = serde_json::from_slice(&source).unwrap();
        skewed["provenance"]["dependency_profile"] = "unreviewed-profile".into();
        let skewed_path = dir.path().join("skewed.json");
        fs::write(&skewed_path, serde_json::to_vec(&skewed).unwrap()).unwrap();
        assert!(load_bundle(skewed_path).is_err());
    }

    #[test]
    fn shared_report_fixture_rejects_unknown_fields() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/plonky3/benchmark-report-v1.json");
        let report = load_report(&path).unwrap();
        assert_eq!(report.mode, BenchmarkMode::Bounded);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        value["unbound_metric"] = 1.into();
        let dir = tempfile::tempdir().unwrap();
        let mutated = dir.path().join("report.json");
        fs::write(&mutated, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_report(mutated).is_err());
    }
}
