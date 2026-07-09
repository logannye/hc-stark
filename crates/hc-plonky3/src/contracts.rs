use crate::{
    InternalProofBundle, ResourceBoundedUniStarkProver, WorkloadKind, COMPATIBILITY_PROFILE,
    PLONKY3_VERSION,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hc_stream::ResourcePolicyV1;
use schemars::{schema_for, JsonSchema, Schema};
use serde::{Deserialize, Serialize};

pub const MAX_MANIFEST_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_BUNDLE_JSON_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_REPORT_JSON_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("unknown or inconsistent schema/profile/dependency version")]
    ProfileMismatch,
    #[error("invalid workload contract")]
    InvalidWorkload,
    #[error("artifact exceeds its size limit")]
    SizeLimit,
    #[error("manifest digest mismatch")]
    ManifestDigestMismatch,
    #[error("proof encoding or digest mismatch")]
    ProofEncoding,
    #[error("JSON serialization failed: {0}")]
    Json(String),
    #[error("proof verification failed: {0}")]
    Verification(String),
}

pub type Result<T> = std::result::Result<T, ContractError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadId {
    Fibonacci,
    Poseidon2Goldilocks,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputGeneratorV1 {
    Fibonacci { initial_a: u64, initial_b: u64 },
    Poseidon2 { seed: u64 },
    Digest { blake3_hex: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadManifestV1 {
    pub schema_version: u32,
    pub workload_id: WorkloadId,
    pub backend: String,
    pub profile: String,
    pub input_generator: InputGeneratorV1,
    pub logical_rows: u64,
    pub deterministic_seed: u64,
    pub resource_policy: ResourcePolicyV1,
    pub expected_verifier: String,
}

impl WorkloadManifestV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.backend != "plonky3"
            || self.profile != COMPATIBILITY_PROFILE
            || self.expected_verifier != "p3_uni_stark_0.6.1"
            || self.logical_rows == 0
            || !self.logical_rows.is_power_of_two()
            || self.logical_rows > (1u64 << 30)
            || self.resource_policy.validate().is_err()
        {
            return Err(ContractError::ProfileMismatch);
        }
        match (&self.workload_id, &self.input_generator) {
            (WorkloadId::Fibonacci, InputGeneratorV1::Fibonacci { .. }) => Ok(()),
            (WorkloadId::Poseidon2Goldilocks, InputGeneratorV1::Poseidon2 { seed })
                if *seed == self.deterministic_seed =>
            {
                Ok(())
            }
            // Content-addressed external inputs are reserved in the schema but
            // not accepted by the two reference workload generators yet.
            _ => Err(ContractError::InvalidWorkload),
        }
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|error| ContractError::Json(error.to_string()))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    pub fn workload(&self) -> Result<WorkloadKind> {
        self.validate()?;
        match self.input_generator {
            InputGeneratorV1::Fibonacci {
                initial_a,
                initial_b,
            } => Ok(WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            }),
            InputGeneratorV1::Poseidon2 { .. } => Ok(WorkloadKind::Poseidon2),
            InputGeneratorV1::Digest { .. } => Err(ContractError::InvalidWorkload),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProvenanceV1 {
    pub prover_version: String,
    pub verifier_version: String,
    pub release_sha: String,
    pub dependency_profile: String,
    pub proof_serializer: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofBundleV1 {
    pub schema_version: u32,
    pub manifest: WorkloadManifestV1,
    pub manifest_digest_hex: String,
    pub proof_base64url: String,
    pub proof_digest_hex: String,
    pub public_values: Vec<u64>,
    pub provenance: ReleaseProvenanceV1,
}

impl ProofBundleV1 {
    pub fn from_internal(
        manifest: WorkloadManifestV1,
        internal: InternalProofBundle,
        release_sha: impl Into<String>,
    ) -> Result<Self> {
        manifest.validate()?;
        internal
            .validate_envelope()
            .map_err(|error| ContractError::Verification(error.to_string()))?;
        if manifest.logical_rows != internal.logical_rows
            || manifest.workload()? != internal.workload
        {
            return Err(ContractError::InvalidWorkload);
        }
        let manifest_digest = manifest.digest()?;
        Ok(Self {
            schema_version: 1,
            manifest,
            manifest_digest_hex: hex_lower(&manifest_digest),
            proof_base64url: URL_SAFE_NO_PAD.encode(&internal.proof_bytes),
            proof_digest_hex: hex_lower(&internal.proof_digest),
            public_values: internal.public_values,
            provenance: ReleaseProvenanceV1 {
                prover_version: PLONKY3_VERSION.into(),
                verifier_version: PLONKY3_VERSION.into(),
                release_sha: release_sha.into(),
                dependency_profile: COMPATIBILITY_PROFILE.into(),
                proof_serializer: "postcard-1".into(),
            },
        })
    }

    pub fn verify(&self) -> Result<()> {
        if self.schema_version != 1
            || self.provenance.prover_version != PLONKY3_VERSION
            || self.provenance.verifier_version != PLONKY3_VERSION
            || self.provenance.dependency_profile != COMPATIBILITY_PROFILE
            || self.provenance.proof_serializer != "postcard-1"
        {
            return Err(ContractError::ProfileMismatch);
        }
        let manifest_digest = self.manifest.digest()?;
        if self.manifest_digest_hex != hex_lower(&manifest_digest) {
            return Err(ContractError::ManifestDigestMismatch);
        }
        let proof_bytes = URL_SAFE_NO_PAD
            .decode(&self.proof_base64url)
            .map_err(|_| ContractError::ProofEncoding)?;
        let proof_digest = *blake3::hash(&proof_bytes).as_bytes();
        if self.proof_digest_hex != hex_lower(&proof_digest) {
            return Err(ContractError::ProofEncoding);
        }
        let internal = InternalProofBundle {
            schema_version: 1,
            compatibility_profile: COMPATIBILITY_PROFILE.into(),
            plonky3_version: PLONKY3_VERSION.into(),
            workload: self.manifest.workload()?,
            logical_rows: self.manifest.logical_rows,
            public_values: self.public_values.clone(),
            proof_bytes,
            proof_digest,
        };
        ResourceBoundedUniStarkProver::verify(&internal)
            .map_err(|error| ContractError::Verification(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkMode {
    Baseline,
    Bounded,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkReportV1 {
    pub schema_version: u32,
    pub scope: String,
    pub mode: BenchmarkMode,
    pub hardware: String,
    pub operating_system: String,
    pub storage: String,
    pub release_sha: String,
    pub dependency_profile: String,
    pub exact_command: Vec<String>,
    pub workload_manifest_digest_hex: String,
    pub cpu_seconds: f64,
    pub wall_time_ms: u64,
    pub peak_rss_bytes: u64,
    pub scratch_high_water_bytes: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub proof_size_bytes: u64,
    pub verification_time_ms: u64,
    pub verification_succeeded: bool,
    pub exit_status: i32,
}

impl BenchmarkReportV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.scope != "full_pipeline"
            || self.dependency_profile != COMPATIBILITY_PROFILE
            || self.exact_command.is_empty()
            || !self.verification_succeeded
            || self.exit_status != 0
            || self.workload_manifest_digest_hex.len() != 64
            || self.cpu_seconds.is_sign_negative()
            || !self.cpu_seconds.is_finite()
        {
            return Err(ContractError::ProfileMismatch);
        }
        Ok(())
    }
}

pub fn workload_manifest_schema() -> Schema {
    schema_for!(WorkloadManifestV1)
}

pub fn proof_bundle_schema() -> Schema {
    schema_for!(ProofBundleV1)
}

pub fn benchmark_report_schema() -> Schema {
    schema_for!(BenchmarkReportV1)
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
    use super::*;
    use hc_stream::{CheckpointPolicy, ResourceMode};

    fn manifest(root: &std::path::Path) -> WorkloadManifestV1 {
        WorkloadManifestV1 {
            schema_version: 1,
            workload_id: WorkloadId::Fibonacci,
            backend: "plonky3".into(),
            profile: COMPATIBILITY_PROFILE.into(),
            input_generator: InputGeneratorV1::Fibonacci {
                initial_a: 0,
                initial_b: 1,
            },
            logical_rows: 8,
            deterministic_seed: 1,
            resource_policy: ResourcePolicyV1 {
                mode: ResourceMode::Scratch,
                max_resident_bytes: 128 * 1024 * 1024,
                max_scratch_bytes: 1024 * 1024 * 1024,
                scratch_dir: root.to_path_buf(),
                max_threads: 1,
                checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
            },
            expected_verifier: "p3_uni_stark_0.6.1".into(),
        }
    }

    #[test]
    fn bundle_round_trip_verifies_and_binds_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = manifest(dir.path());
        let prover = ResourceBoundedUniStarkProver::new(manifest.resource_policy.clone()).unwrap();
        let internal = prover
            .prove(manifest.workload().unwrap(), manifest.logical_rows)
            .unwrap();
        let bundle = ProofBundleV1::from_internal(manifest, internal, "test-release").unwrap();
        bundle.verify().unwrap();

        let mut mutation = bundle;
        mutation.manifest.deterministic_seed ^= 1;
        assert!(matches!(
            mutation.verify(),
            Err(ContractError::ManifestDigestMismatch)
        ));
    }

    #[test]
    fn schemas_are_generated_from_rust_types() {
        for schema in [
            workload_manifest_schema(),
            proof_bundle_schema(),
            benchmark_report_schema(),
        ] {
            let json = serde_json::to_value(schema).unwrap();
            assert_eq!(
                json["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
        }
    }
}
