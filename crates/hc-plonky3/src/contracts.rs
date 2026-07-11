use crate::{
    InternalProofBundle, ResourceBoundedUniStarkProver, WorkloadKind, COMPATIBILITY_PROFILE,
    GOLDILOCKS_MODULUS_U64, PLONKY3_VERSION,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hc_stream::{ResourceEstimate, ResourcePolicyV1};
use schemars::{schema_for, JsonSchema, Schema};
use serde::{Deserialize, Serialize};

pub const MAX_MANIFEST_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_BUNDLE_JSON_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_REPORT_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
const MAX_PUBLIC_VALUES: usize = 1024;

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
    Fibonacci {
        #[schemars(range(max = 18446744069414584320u64))]
        initial_a: u64,
        #[schemars(range(max = 18446744069414584320u64))]
        initial_b: u64,
    },
    Poseidon2 {
        seed: u64,
    },
    Digest {
        blake3_hex: String,
    },
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
            (
                WorkloadId::Fibonacci,
                InputGeneratorV1::Fibonacci {
                    initial_a,
                    initial_b,
                },
            ) if self.deterministic_seed == 0
                && *initial_a < GOLDILOCKS_MODULUS_U64
                && *initial_b < GOLDILOCKS_MODULUS_U64 =>
            {
                Ok(())
            }
            (WorkloadId::Poseidon2Goldilocks, InputGeneratorV1::Poseidon2 { seed })
                if *seed == 0 && self.deterministic_seed == 0 =>
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
        let bytes = canonical_json_bytes_v1(self)?;
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
        if internal.proof_bytes.len() > MAX_PROOF_BYTES
            || internal.public_values.len() > MAX_PUBLIC_VALUES
        {
            return Err(ContractError::SizeLimit);
        }
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
                proof_serializer: "postcard-1.1.3".into(),
            },
        })
    }

    pub fn verify(&self) -> Result<()> {
        validate_bundle_sizes(self.proof_base64url.len(), self.public_values.len())?;
        if self.schema_version != 1
            || self.provenance.prover_version != PLONKY3_VERSION
            || self.provenance.verifier_version != PLONKY3_VERSION
            || self.provenance.dependency_profile != COMPATIBILITY_PROFILE
            || self.provenance.proof_serializer != "postcard-1.1.3"
            || self.provenance.release_sha.is_empty()
            || self.provenance.release_sha.len() > 128
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
        if proof_bytes.len() > MAX_PROOF_BYTES
            || URL_SAFE_NO_PAD.encode(&proof_bytes) != self.proof_base64url
        {
            return Err(ContractError::ProofEncoding);
        }
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
    #[schemars(length(equal = 32), regex(pattern = "^[0-9a-f]{32}$"))]
    pub benchmark_session_id: String,
    #[schemars(length(min = 1))]
    pub hardware: String,
    #[schemars(range(min = 1))]
    pub logical_cpu_count: u32,
    #[schemars(range(min = 1))]
    pub total_memory_bytes: u64,
    #[schemars(length(min = 1))]
    pub operating_system: String,
    #[schemars(length(min = 1))]
    pub storage: String,
    #[schemars(length(min = 1))]
    pub storage_device: String,
    pub storage_is_rotational: bool,
    pub storage_is_nvme: bool,
    #[schemars(range(min = 1))]
    pub storage_total_bytes: u64,
    #[schemars(range(min = 1))]
    pub storage_available_bytes: u64,
    #[schemars(range(min = 448, max = 448))]
    pub scratch_directory_mode: u32,
    pub scratch_owned_by_runner: bool,
    pub release_sha: String,
    pub dependency_profile: String,
    pub exact_command: Vec<String>,
    pub normalized_manifest_path: String,
    pub workload_manifest_digest_hex: String,
    pub normalized_manifest_digest_hex: String,
    pub preflight_estimate: ResourceEstimate,
    pub cpu_seconds: f64,
    #[schemars(range(min = 1))]
    pub wall_time_ms: u64,
    #[schemars(range(min = 1))]
    pub peak_rss_bytes: u64,
    #[schemars(range(min = 1))]
    pub cgroup_peak_bytes: u64,
    pub scratch_high_water_bytes: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    #[schemars(range(min = 1))]
    pub proof_size_bytes: u64,
    pub verification_time_ms: u64,
    pub verification_succeeded: bool,
    pub exit_status: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 4000))]
    pub failure_diagnostic: Option<String>,
}

impl BenchmarkReportV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.scope != "full_pipeline"
            || self.dependency_profile != COMPATIBILITY_PROFILE
            || !is_lower_hex_identifier(&self.benchmark_session_id, 32)
            || self.hardware.is_empty()
            || self.logical_cpu_count == 0
            || self.total_memory_bytes == 0
            || self.operating_system.is_empty()
            || self.storage.is_empty()
            || self.storage_device.is_empty()
            || self.storage_total_bytes == 0
            || self.storage_available_bytes == 0
            || self.storage_available_bytes > self.storage_total_bytes
            || self.scratch_directory_mode != 0o700
            || !self.scratch_owned_by_runner
            || self.release_sha.is_empty()
            || self.release_sha.len() > 128
            || self.exact_command.is_empty()
            || self.exact_command.iter().any(String::is_empty)
            || self.normalized_manifest_path.is_empty()
            || !self.verification_succeeded
            || self.exit_status != 0
            || !is_lower_hex_digest(&self.workload_manifest_digest_hex)
            || !is_lower_hex_digest(&self.normalized_manifest_digest_hex)
            || self.preflight_estimate.peak_resident_bytes == 0
            || self.preflight_estimate.scratch_high_water_bytes == 0
            || self.cpu_seconds.is_sign_negative()
            || !self.cpu_seconds.is_finite()
            || self.wall_time_ms == 0
            || self.peak_rss_bytes == 0
            || self.cgroup_peak_bytes < self.peak_rss_bytes
            || self.proof_size_bytes == 0
            || self
                .failure_diagnostic
                .as_ref()
                .is_some_and(|value| value.len() > 4000)
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

/// TinyZKP canonical JSON v1. Object keys are sorted lexicographically, no
/// insignificant whitespace is emitted, and only integer JSON numbers are
/// accepted. Artifact manifests intentionally contain no floating-point
/// values, making this representation straightforward to reproduce in Rust,
/// Python, TypeScript, and WASM.
pub fn canonical_json_bytes_v1<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value =
        serde_json::to_value(value).map_err(|error| ContractError::Json(error.to_string()))?;
    let mut output = Vec::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<()> {
    use std::io::Write;
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => output.extend_from_slice(if *value {
            b"true".as_slice()
        } else {
            b"false".as_slice()
        }),
        serde_json::Value::Number(value) => {
            if !value.is_i64() && !value.is_u64() {
                return Err(ContractError::Json(
                    "canonical artifact JSON forbids floating-point numbers".into(),
                ));
            }
            write!(output, "{value}").map_err(|error| ContractError::Json(error.to_string()))?;
        }
        serde_json::Value::String(value) => {
            serde_json::to_writer(output, value)
                .map_err(|error| ContractError::Json(error.to_string()))?;
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|error| ContractError::Json(error.to_string()))?;
                output.push(b':');
                write_canonical_json(
                    values.get(key).expect("canonical object key exists"),
                    output,
                )?;
            }
            output.push(b'}');
        }
    }
    Ok(())
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

const fn max_base64url_len(bytes: usize) -> usize {
    bytes.saturating_mul(4).saturating_add(2) / 3
}

fn is_lower_hex_digest(value: &str) -> bool {
    is_lower_hex_identifier(value, 64)
}

fn is_lower_hex_identifier(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_bundle_sizes(encoded_proof_bytes: usize, public_values: usize) -> Result<()> {
    if public_values > MAX_PUBLIC_VALUES || encoded_proof_bytes > max_base64url_len(MAX_PROOF_BYTES)
    {
        Err(ContractError::SizeLimit)
    } else {
        Ok(())
    }
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
            deterministic_seed: 0,
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
        mutation.manifest.input_generator = InputGeneratorV1::Fibonacci {
            initial_a: 1,
            initial_b: 1,
        };
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

    #[test]
    fn canonical_json_v1_sorts_keys_and_rejects_floats() {
        let canonical = canonical_json_bytes_v1(&serde_json::json!({
            "z": [3, {"b": true, "a": "value"}],
            "a": 1,
        }))
        .unwrap();
        assert_eq!(canonical, br#"{"a":1,"z":[3,{"a":"value","b":true}]}"#);
        assert_eq!(
            hex_lower(blake3::hash(&canonical).as_bytes()),
            "75cb2762f02e1cf0c67805150ce6179cf7f05e6eb28e5353d5923dcccbf7598c"
        );
        assert!(canonical_json_bytes_v1(&serde_json::json!({"value": 1.5})).is_err());
    }

    #[test]
    fn shared_manifest_golden_vector_has_stable_digest() {
        let manifest: WorkloadManifestV1 = serde_json::from_str(include_str!(
            "../../../test-vectors/plonky3/fibonacci-16.manifest.json"
        ))
        .unwrap();
        assert_eq!(
            hex_lower(&manifest.digest().unwrap()),
            "9d131602e27428ca290c5ca87d543d085873840e4dba22dd3d8074945e57efcd"
        );
    }

    #[test]
    fn maximum_goldilocks_manifest_has_cross_language_digest() {
        let manifest: WorkloadManifestV1 = serde_json::from_str(include_str!(
            "../../../test-vectors/plonky3/fibonacci-max-field.manifest.json"
        ))
        .unwrap();
        assert_eq!(
            manifest.input_generator,
            InputGeneratorV1::Fibonacci {
                initial_a: 18_446_744_069_414_584_320,
                initial_b: 0,
            }
        );
        assert_eq!(
            hex_lower(&manifest.digest().unwrap()),
            "d66d868441137e6db964add9d7e4a2164ca3a722c66e73cbf06c2a576efee653"
        );
    }

    #[test]
    fn fibonacci_manifest_rejects_noncanonical_field_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let mut value = manifest(dir.path());
        value.input_generator = InputGeneratorV1::Fibonacci {
            initial_a: GOLDILOCKS_MODULUS_U64,
            initial_b: 0,
        };
        assert!(matches!(
            value.validate(),
            Err(ContractError::InvalidWorkload)
        ));

        value.input_generator = InputGeneratorV1::Fibonacci {
            initial_a: GOLDILOCKS_MODULUS_U64 - 1,
            initial_b: 0,
        };
        value.validate().unwrap();
    }

    #[test]
    fn reference_generators_reject_unbound_seed_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let mut fibonacci = manifest(dir.path());
        fibonacci.deterministic_seed = 1;
        assert!(matches!(
            fibonacci.validate(),
            Err(ContractError::InvalidWorkload)
        ));

        fibonacci.workload_id = WorkloadId::Poseidon2Goldilocks;
        fibonacci.input_generator = InputGeneratorV1::Poseidon2 { seed: 9 };
        fibonacci.deterministic_seed = 9;
        assert!(matches!(
            fibonacci.validate(),
            Err(ContractError::InvalidWorkload)
        ));
    }

    #[test]
    fn artifact_boundaries_reject_oversize_and_noncanonical_encodings() {
        let mut bundle: ProofBundleV1 = serde_json::from_str(include_str!(
            "../../../test-vectors/plonky3/fibonacci-16.bundle.json"
        ))
        .unwrap();
        bundle.proof_base64url.push('=');
        assert!(matches!(bundle.verify(), Err(ContractError::ProofEncoding)));

        assert!(matches!(
            validate_bundle_sizes(max_base64url_len(MAX_PROOF_BYTES) + 1, 0),
            Err(ContractError::SizeLimit)
        ));

        let mut report: BenchmarkReportV1 = serde_json::from_str(include_str!(
            "../../../test-vectors/plonky3/benchmark-report-v1.json"
        ))
        .unwrap();
        report.validate().unwrap();
        report.workload_manifest_digest_hex.make_ascii_uppercase();
        assert!(matches!(
            report.validate(),
            Err(ContractError::ProfileMismatch)
        ));

        let mut report: BenchmarkReportV1 = serde_json::from_str(include_str!(
            "../../../test-vectors/plonky3/benchmark-report-v1.json"
        ))
        .unwrap();
        report.benchmark_session_id = "not-a-session".into();
        assert!(matches!(
            report.validate(),
            Err(ContractError::ProfileMismatch)
        ));

        let mut report: BenchmarkReportV1 = serde_json::from_str(include_str!(
            "../../../test-vectors/plonky3/benchmark-report-v1.json"
        ))
        .unwrap();
        report.storage_available_bytes = report.storage_total_bytes + 1;
        assert!(matches!(
            report.validate(),
            Err(ContractError::ProfileMismatch)
        ));

        let mut report: BenchmarkReportV1 = serde_json::from_str(include_str!(
            "../../../test-vectors/plonky3/benchmark-report-v1.json"
        ))
        .unwrap();
        report.scratch_directory_mode = 0o755;
        report.scratch_owned_by_runner = false;
        assert!(matches!(
            report.validate(),
            Err(ContractError::ProfileMismatch)
        ));
    }

    #[test]
    fn bundle_rejects_every_version_and_dependency_skew() {
        let fixture = || {
            serde_json::from_str::<ProofBundleV1>(include_str!(
                "../../../test-vectors/plonky3/fibonacci-16.bundle.json"
            ))
            .unwrap()
        };
        let mutations: [fn(&mut ProofBundleV1); 6] = [
            |bundle| bundle.schema_version += 1,
            |bundle| bundle.manifest.schema_version += 1,
            |bundle| bundle.manifest.profile = "unreviewed-profile".into(),
            |bundle| bundle.provenance.prover_version = "0.6.2".into(),
            |bundle| bundle.provenance.verifier_version = "0.6.2".into(),
            |bundle| bundle.provenance.dependency_profile = "unreviewed-profile".into(),
        ];
        for mutate in mutations {
            let mut bundle = fixture();
            mutate(&mut bundle);
            assert!(bundle.verify().is_err());
        }
    }
}
