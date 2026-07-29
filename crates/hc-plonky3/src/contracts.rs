use crate::profile::{declared_field_profile, DurableFieldProfile, GoldilocksProfile};
use crate::{
    verify_declarative_proof, InternalProofBundle, ResourceBoundedUniStarkProver, WorkloadKind,
    COMPATIBILITY_PROFILE, GOLDILOCKS_MODULUS_U64, PLONKY3_VERSION,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hc_stream::{ResourceEstimate, ResourcePolicyV1};
use schemars::{schema_for, JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_MANIFEST_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_BUNDLE_JSON_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_REPORT_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_AIR_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TRACE_MANIFEST_JSON_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_AIR_BUNDLE_JSON_BYTES: usize = 104 * 1024 * 1024;
pub const MAX_AIR_NODES: usize = 8192;
pub const MAX_AIR_CONSTRAINTS: usize = 1024;
pub const MAX_TRACE_WIDTH: u32 = 256;
pub const MAX_TRACE_COMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_TRACE_UNCOMPRESSED_BYTES: u64 = 32 * 1024 * 1024 * 1024;
pub const MAX_TRACE_CHUNK_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
pub const MIN_CUSTOM_TRACE_ROWS: u64 = 1 << 10;
pub const MAX_CUSTOM_TRACE_ROWS: u64 = 1 << 24;
const MAX_PUBLIC_VALUES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("unknown or inconsistent schema/profile/dependency version")]
    ProfileMismatch,
    #[error("invalid workload contract")]
    InvalidWorkload,
    #[error("invalid declarative AIR contract")]
    InvalidAir,
    #[error("invalid trace contract")]
    InvalidTrace,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AirExpressionV1 {
    Constant {
        #[schemars(range(max = 18446744069414584320u64))]
        value: u64,
    },
    Current {
        column: u32,
    },
    Next {
        column: u32,
    },
    Public {
        index: u32,
    },
    Add {
        left: u32,
        right: u32,
    },
    Sub {
        left: u32,
        right: u32,
    },
    Mul {
        left: u32,
        right: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AirConstraintKindV1 {
    Transition,
    FirstRow,
    LastRow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AirConstraintV1 {
    pub kind: AirConstraintKindV1,
    pub expression: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicInputSlotV1 {
    #[schemars(
        length(min = 1, max = 64),
        regex(pattern = "^[A-Za-z][A-Za-z0-9_]{0,63}$")
    )]
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AirPackageV1 {
    pub schema_version: u32,
    pub backend: String,
    pub profile: String,
    pub field: String,
    pub expected_verifier: String,
    pub trace_width: u32,
    pub public_inputs: Vec<PublicInputSlotV1>,
    pub expressions: Vec<AirExpressionV1>,
    pub constraints: Vec<AirConstraintV1>,
}

impl AirPackageV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !(1..=MAX_TRACE_WIDTH).contains(&self.trace_width)
            || self.public_inputs.len() > MAX_PUBLIC_VALUES
            || self.expressions.is_empty()
            || self.expressions.len() > MAX_AIR_NODES
            || self.constraints.is_empty()
            || self.constraints.len() > MAX_AIR_CONSTRAINTS
        {
            return Err(ContractError::InvalidAir);
        }
        let mut public_names = HashSet::with_capacity(self.public_inputs.len());
        if self.public_inputs.iter().any(|slot| {
            !valid_public_input_name(&slot.name) || !public_names.insert(slot.name.as_str())
        }) {
            return Err(ContractError::InvalidAir);
        }

        // Constants are field elements, so their bound is the DECLARED field's
        // modulus, not Goldilocks'. An unrecognised field name falls back to
        // Goldilocks — the widest modulus this crate knows — purely to keep the
        // pre-existing ordering ("malformed structure is reported before profile
        // skew", pinned by `declarative_air_distinguishes_profile_skew_from_
        // malformed_structure`); the profile gate at the end of this function
        // rejects such a package unconditionally, so the fallback can never
        // admit anything.
        let field_modulus = declared_field_profile(&self.field)
            .map_or(GOLDILOCKS_MODULUS_U64, |field| field.modulus_u64);
        let mut degrees = Vec::with_capacity(self.expressions.len());
        for (position, expression) in self.expressions.iter().enumerate() {
            let position = u32::try_from(position).map_err(|_| ContractError::InvalidAir)?;
            let degree = match expression {
                AirExpressionV1::Constant { value } if *value < field_modulus => 0,
                AirExpressionV1::Current { column } | AirExpressionV1::Next { column }
                    if *column < self.trace_width =>
                {
                    1
                }
                AirExpressionV1::Public { index }
                    if (*index as usize) < self.public_inputs.len() =>
                {
                    0
                }
                AirExpressionV1::Add { left, right } | AirExpressionV1::Sub { left, right } => {
                    let (left_degree, right_degree) =
                        prior_degrees(&degrees, position, *left, *right)?;
                    left_degree.max(right_degree)
                }
                AirExpressionV1::Mul { left, right } => {
                    let (left_degree, right_degree) =
                        prior_degrees(&degrees, position, *left, *right)?;
                    left_degree + right_degree
                }
                _ => return Err(ContractError::InvalidAir),
            };
            if degree > 3 {
                return Err(ContractError::InvalidAir);
            }
            degrees.push(degree);
        }
        if self
            .constraints
            .iter()
            .any(|constraint| constraint.expression as usize >= self.expressions.len())
        {
            return Err(ContractError::InvalidAir);
        }
        for constraint in &self.constraints {
            if constraint.kind != AirConstraintKindV1::Transition
                && expression_uses_next(&self.expressions, constraint.expression as usize)
            {
                return Err(ContractError::InvalidAir);
            }
        }
        if canonical_json_bytes_v1(self)?.len() > MAX_AIR_JSON_BYTES {
            return Err(ContractError::SizeLimit);
        }
        // `profile` names the frozen DEPENDENCY profile (Plonky3 0.6.1 +
        // `p3_uni_stark` + postcard); `field` names the field within it. That
        // split is the convention `bounded_prover.rs::checkpoint_identity`
        // already established, which hashes
        // `{COMPATIBILITY_PROFILE}:{PLONKY3_VERSION}:{P::FIELD_NAME}:{PW}:{DE}`
        // precisely because the profile constant is shared across fields.
        //
        // Admitting a field here does NOT assert the engine can prove it.
        // `declarative.rs`'s workloads are `ResourceBoundedWorkload<8, 4,
        // GoldilocksProfile>` at the type level and refuse anything else, and
        // `AirProofBundleV1` refuses to stamp provenance on a non-Goldilocks
        // AIR. What admission buys is that the canonicality bounds above and in
        // `PublicInputsV1`/`TraceManifestV1` are evaluated against the field the
        // package actually declares, instead of silently reducing mod p later.
        if self.backend != "plonky3"
            || self.profile != COMPATIBILITY_PROFILE
            || declared_field_profile(&self.field).is_none()
            || self.expected_verifier != "p3_uni_stark_0.6.1"
        {
            return Err(ContractError::ProfileMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(*blake3::hash(&canonical_json_bytes_v1(self)?).as_bytes())
    }
}

fn valid_public_input_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn expression_uses_next(expressions: &[AirExpressionV1], root: usize) -> bool {
    let mut stack = vec![root];
    let mut visited = vec![false; expressions.len()];
    while let Some(index) = stack.pop() {
        if visited[index] {
            continue;
        }
        visited[index] = true;
        match expressions[index] {
            AirExpressionV1::Next { .. } => return true,
            AirExpressionV1::Add { left, right }
            | AirExpressionV1::Sub { left, right }
            | AirExpressionV1::Mul { left, right } => {
                stack.push(left as usize);
                stack.push(right as usize);
            }
            _ => {}
        }
    }
    false
}

/// Refuse to build or accept a proof bundle whose AIR declares a field this
/// release cannot honestly stamp provenance for.
///
/// `ReleaseProvenanceV1::dependency_profile` is written unconditionally as
/// `COMPATIBILITY_PROFILE`, and `release/plonky3-compatibility-v1.json` — the
/// signed record that string refers to — documents exactly one qualified
/// instantiation (`configuration.field: p3_goldilocks::Goldilocks`). Stamping
/// it onto a BabyBear AIR would label non-Goldilocks work as Goldilocks-profile
/// work, so the bundle is refused instead of relabelled. Nothing here is
/// reachable today (the declarative prover and verifier are Goldilocks-typed
/// and refuse first), which is precisely why the guard is stated explicitly
/// rather than left to depend on that ordering.
fn provenance_representable_field(air: &AirPackageV1) -> Result<()> {
    if air.field != <GoldilocksProfile as DurableFieldProfile<8, 4>>::FIELD_NAME {
        return Err(ContractError::ProfileMismatch);
    }
    Ok(())
}

fn prior_degrees(degrees: &[u32], position: u32, left: u32, right: u32) -> Result<(u32, u32)> {
    if left >= position || right >= position {
        return Err(ContractError::InvalidAir);
    }
    Ok((degrees[left as usize], degrees[right as usize]))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceChunkV1 {
    pub index: u32,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub blake3_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceManifestV1 {
    pub schema_version: u32,
    pub air_digest_hex: String,
    pub trace_digest_hex: String,
    pub logical_rows: u64,
    pub trace_width: u32,
    pub field_encoding: String,
    pub compression: String,
    pub chunk_uncompressed_bytes: u64,
    pub chunks: Vec<TraceChunkV1>,
}

impl TraceManifestV1 {
    pub fn validate_for_air(&self, air: &AirPackageV1) -> Result<()> {
        air.validate()?;
        // `air.validate()` already refused every field this crate has no
        // canonicality rule for, so the lookup cannot fail; `ok_or` rather than
        // an `expect` keeps that a refusal instead of a panic if the two ever
        // drift. Both the accepted encoding string and the bytes-per-element
        // arithmetic below follow the AIR's declared field: a BabyBear trace is
        // 4 bytes per element, so reusing Goldilocks' 8 would compute the wrong
        // chunk count and the wrong total size for it.
        let field = declared_field_profile(&air.field).ok_or(ContractError::ProfileMismatch)?;
        if self.schema_version != 1
            || self.air_digest_hex != hex_lower(&air.digest()?)
            || !is_lower_hex_digest(&self.trace_digest_hex)
            || self.trace_width != air.trace_width
            || self.logical_rows < MIN_CUSTOM_TRACE_ROWS
            || self.logical_rows > MAX_CUSTOM_TRACE_ROWS
            || !self.logical_rows.is_power_of_two()
            || self.field_encoding != field.trace_encoding
            || self.compression != "zstd"
            || self.chunk_uncompressed_bytes == 0
            || self.chunk_uncompressed_bytes > MAX_TRACE_CHUNK_UNCOMPRESSED_BYTES
            || !self
                .chunk_uncompressed_bytes
                .is_multiple_of(field.element_bytes)
            || self.chunks.is_empty()
            || canonical_json_bytes_v1(self)?.len() > MAX_TRACE_MANIFEST_JSON_BYTES
        {
            return Err(ContractError::InvalidTrace);
        }
        let expected_uncompressed = self
            .logical_rows
            .checked_mul(u64::from(self.trace_width))
            .and_then(|value| value.checked_mul(field.element_bytes))
            .ok_or(ContractError::InvalidTrace)?;
        let mut compressed_total = 0u64;
        let mut uncompressed_total = 0u64;
        let expected_chunk_count = expected_uncompressed.div_ceil(self.chunk_uncompressed_bytes);
        if self.chunks.len() as u64 != expected_chunk_count {
            return Err(ContractError::InvalidTrace);
        }
        for (index, chunk) in self.chunks.iter().enumerate() {
            let expected_chunk_bytes = if index + 1 == self.chunks.len() {
                expected_uncompressed
                    - self.chunk_uncompressed_bytes * (self.chunks.len() as u64 - 1)
            } else {
                self.chunk_uncompressed_bytes
            };
            if chunk.index as usize != index
                || chunk.compressed_bytes == 0
                || chunk.uncompressed_bytes == 0
                || chunk.uncompressed_bytes != expected_chunk_bytes
                || !is_lower_hex_digest(&chunk.blake3_hex)
            {
                return Err(ContractError::InvalidTrace);
            }
            compressed_total = compressed_total
                .checked_add(chunk.compressed_bytes)
                .ok_or(ContractError::InvalidTrace)?;
            uncompressed_total = uncompressed_total
                .checked_add(chunk.uncompressed_bytes)
                .ok_or(ContractError::InvalidTrace)?;
        }
        if compressed_total > MAX_TRACE_COMPRESSED_BYTES
            || uncompressed_total > MAX_TRACE_UNCOMPRESSED_BYTES
            || uncompressed_total != expected_uncompressed
        {
            return Err(ContractError::SizeLimit);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&canonical_json_bytes_v1(self)?).as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicInputsV1 {
    pub schema_version: u32,
    pub air_digest_hex: String,
    pub values: Vec<u64>,
}

impl PublicInputsV1 {
    pub fn validate_for_air(&self, air: &AirPackageV1) -> Result<()> {
        air.validate()?;
        // The bound is the DECLARED field's modulus. Comparing against
        // Goldilocks' here would admit every value below 2^64 for a BabyBear
        // AIR, and the field constructor would then reduce it mod 2^31-2^27+1 —
        // making distinct public-input sets collapse onto the same field
        // element and the same proof.
        let field = declared_field_profile(&air.field).ok_or(ContractError::ProfileMismatch)?;
        if self.schema_version != 1
            || self.air_digest_hex != hex_lower(&air.digest()?)
            || self.values.len() != air.public_inputs.len()
            || self.values.iter().any(|value| *value >= field.modulus_u64)
        {
            return Err(ContractError::InvalidAir);
        }
        Ok(())
    }

    pub fn digest(&self, air: &AirPackageV1) -> Result<[u8; 32]> {
        self.validate_for_air(air)?;
        Ok(*blake3::hash(&canonical_json_bytes_v1(self)?).as_bytes())
    }
}

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
        // DELIBERATELY Goldilocks-only, not an oversight. `WorkloadManifestV1`
        // carries no `field` at all, and the only executor it feeds —
        // `ResourceBoundedUniStarkProver` — is pinned to
        // `<8, 4, GoldilocksProfile>`. Threading a profile through here would
        // require adding a `field` property to a schema that is byte-compared
        // against the published, signed `site/schemas/workload-manifest-v1
        // .schema.json`, so it is out of scope until that schema is versioned.
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AirProofBundleV1 {
    pub schema_version: u32,
    pub air: AirPackageV1,
    pub air_digest_hex: String,
    pub trace_manifest: TraceManifestV1,
    pub trace_manifest_digest_hex: String,
    pub public_inputs: PublicInputsV1,
    pub public_inputs_digest_hex: String,
    pub proof_base64url: String,
    pub proof_digest_hex: String,
    pub provenance: ReleaseProvenanceV1,
}

impl AirProofBundleV1 {
    pub fn from_proof(
        air: AirPackageV1,
        trace_manifest: TraceManifestV1,
        public_inputs: PublicInputsV1,
        proof_bytes: Vec<u8>,
        release_sha: impl Into<String>,
    ) -> Result<Self> {
        provenance_representable_field(&air)?;
        trace_manifest.validate_for_air(&air)?;
        public_inputs.validate_for_air(&air)?;
        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(ContractError::SizeLimit);
        }
        let air_digest = air.digest()?;
        let trace_manifest_digest = trace_manifest.digest()?;
        let public_inputs_digest = public_inputs.digest(&air)?;
        let proof_digest = *blake3::hash(&proof_bytes).as_bytes();
        let bundle = Self {
            schema_version: 1,
            air,
            air_digest_hex: hex_lower(&air_digest),
            trace_manifest,
            trace_manifest_digest_hex: hex_lower(&trace_manifest_digest),
            public_inputs,
            public_inputs_digest_hex: hex_lower(&public_inputs_digest),
            proof_base64url: URL_SAFE_NO_PAD.encode(&proof_bytes),
            proof_digest_hex: hex_lower(&proof_digest),
            provenance: ReleaseProvenanceV1 {
                prover_version: PLONKY3_VERSION.into(),
                verifier_version: PLONKY3_VERSION.into(),
                release_sha: release_sha.into(),
                dependency_profile: COMPATIBILITY_PROFILE.into(),
                proof_serializer: "postcard-1.1.3".into(),
            },
        };
        bundle.verify()?;
        Ok(bundle)
    }

    pub fn verify(&self) -> Result<()> {
        provenance_representable_field(&self.air)?;
        if canonical_json_bytes_v1(self)?.len() > MAX_AIR_BUNDLE_JSON_BYTES
            || self.schema_version != 1
            || self.provenance.prover_version != PLONKY3_VERSION
            || self.provenance.verifier_version != PLONKY3_VERSION
            || self.provenance.dependency_profile != COMPATIBILITY_PROFILE
            || self.provenance.proof_serializer != "postcard-1.1.3"
            || self.provenance.release_sha.is_empty()
            || self.provenance.release_sha.len() > 128
        {
            return Err(ContractError::ProfileMismatch);
        }
        self.trace_manifest.validate_for_air(&self.air)?;
        self.public_inputs.validate_for_air(&self.air)?;
        if self.air_digest_hex != hex_lower(&self.air.digest()?)
            || self.trace_manifest_digest_hex != hex_lower(&self.trace_manifest.digest()?)
            || self.public_inputs_digest_hex != hex_lower(&self.public_inputs.digest(&self.air)?)
        {
            return Err(ContractError::ManifestDigestMismatch);
        }
        let proof_bytes = URL_SAFE_NO_PAD
            .decode(&self.proof_base64url)
            .map_err(|_| ContractError::ProofEncoding)?;
        if proof_bytes.len() > MAX_PROOF_BYTES
            || URL_SAFE_NO_PAD.encode(&proof_bytes) != self.proof_base64url
            || self.proof_digest_hex != hex_lower(blake3::hash(&proof_bytes).as_bytes())
        {
            return Err(ContractError::ProofEncoding);
        }
        verify_declarative_proof(
            self.air.clone(),
            self.trace_manifest.logical_rows,
            &self.public_inputs.values,
            &proof_bytes,
        )
        .map_err(|error| ContractError::Verification(error.to_string()))
    }

    pub fn verify_local_registration_proof(&self) -> Result<()> {
        if self.trace_manifest.logical_rows != MIN_CUSTOM_TRACE_ROWS {
            return Err(ContractError::InvalidTrace);
        }
        self.verify()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostedResourceReportV1 {
    pub peak_resident_bytes: u64,
    pub scratch_high_water_bytes: u64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub wall_time_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostedProofBundleV1 {
    pub schema_version: u32,
    pub proof: AirProofBundleV1,
    pub resource_report: HostedResourceReportV1,
    pub charge_millicredits: u64,
    pub official_verification: bool,
}

impl HostedProofBundleV1 {
    pub fn verify(&self) -> Result<()> {
        if self.schema_version != 1
            || !self.official_verification
            || self.resource_report.peak_resident_bytes == 0
            || self.resource_report.wall_time_ms == 0
            || self.charge_millicredits != hosted_charge_millicredits(&self.resource_report)
        {
            return Err(ContractError::ProfileMismatch);
        }
        self.proof.verify()
    }
}

pub fn hosted_charge_millicredits(report: &HostedResourceReportV1) -> u64 {
    hosted_measured_cost_millicredits(report)
        .saturating_mul(120)
        .div_ceil(100)
        .saturating_mul(100)
        .div_ceil(30)
        .max(10)
}

/// Direct metered compute and I/O cost before the operations reserve and
/// public-beta gross-margin floor are applied.
pub fn hosted_measured_cost_millicredits(report: &HostedResourceReportV1) -> u64 {
    let compute = report.wall_time_ms.saturating_mul(250).div_ceil(3_600_000);
    let io = report
        .total_read_bytes
        .saturating_add(report.total_write_bytes)
        .div_ceil(1024 * 1024 * 1024);
    compute.saturating_add(io).max(3)
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
    pub physical_logical_cpu_count: u32,
    #[schemars(range(min = 1))]
    pub physical_memory_bytes: u64,
    #[schemars(range(min = 1))]
    pub effective_cpu_count: u32,
    pub effective_cpu_affinity: Vec<u32>,
    #[schemars(range(min = 1))]
    pub effective_memory_max_bytes: u64,
    pub effective_swap_max_bytes: u64,
    #[schemars(length(min = 1))]
    pub cgroup_v2_path: String,
    #[schemars(length(min = 1))]
    pub operating_system: String,
    #[schemars(length(min = 1))]
    pub storage: String,
    #[schemars(length(min = 1))]
    pub storage_device: String,
    #[schemars(length(min = 1))]
    pub effective_storage_device: String,
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
        if self.schema_version != 2
            || self.scope != "full_pipeline"
            || self.dependency_profile != COMPATIBILITY_PROFILE
            || !is_lower_hex_identifier(&self.benchmark_session_id, 32)
            || self.hardware.is_empty()
            || self.physical_logical_cpu_count == 0
            || self.physical_memory_bytes == 0
            || self.effective_cpu_count == 0
            || self.effective_cpu_affinity.len() != self.effective_cpu_count as usize
            || self
                .effective_cpu_affinity
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.effective_cpu_affinity.len()
            || self.effective_memory_max_bytes == 0
            || !self.cgroup_v2_path.starts_with('/')
            || self.operating_system.is_empty()
            || self.storage.is_empty()
            || self.storage_device.is_empty()
            || self.effective_storage_device != self.storage_device
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

pub fn air_package_schema() -> Schema {
    schema_for!(AirPackageV1)
}

pub fn trace_manifest_schema() -> Schema {
    schema_for!(TraceManifestV1)
}

pub fn public_inputs_schema() -> Schema {
    schema_for!(PublicInputsV1)
}

pub fn air_proof_bundle_schema() -> Schema {
    schema_for!(AirProofBundleV1)
}

pub fn hosted_proof_bundle_schema() -> Schema {
    schema_for!(HostedProofBundleV1)
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
    use crate::profile::BABYBEAR_MODULUS_U64;
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
            air_package_schema(),
            trace_manifest_schema(),
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

    fn customer_air() -> AirPackageV1 {
        AirPackageV1 {
            schema_version: 1,
            backend: "plonky3".into(),
            profile: COMPATIBILITY_PROFILE.into(),
            field: "goldilocks".into(),
            expected_verifier: "p3_uni_stark_0.6.1".into(),
            trace_width: 1,
            public_inputs: vec![],
            expressions: vec![
                AirExpressionV1::Current { column: 0 },
                AirExpressionV1::Next { column: 0 },
                AirExpressionV1::Sub { left: 1, right: 0 },
            ],
            constraints: vec![AirConstraintV1 {
                kind: AirConstraintKindV1::Transition,
                expression: 2,
            }],
        }
    }

    #[test]
    fn declarative_air_is_hash_bound_and_rejects_unsafe_graphs() {
        let air = customer_air();
        air.validate().unwrap();
        assert_ne!(air.digest().unwrap(), [0; 32]);

        let mut forward_reference = air.clone();
        forward_reference.expressions[2] = AirExpressionV1::Add { left: 2, right: 0 };
        assert!(matches!(
            forward_reference.validate(),
            Err(ContractError::InvalidAir)
        ));

        let mut degree_four = air;
        degree_four.expressions = vec![
            AirExpressionV1::Current { column: 0 },
            AirExpressionV1::Mul { left: 0, right: 0 },
            AirExpressionV1::Mul { left: 1, right: 0 },
            AirExpressionV1::Mul { left: 2, right: 0 },
        ];
        degree_four.constraints[0].expression = 3;
        assert!(matches!(
            degree_four.validate(),
            Err(ContractError::InvalidAir)
        ));
    }

    #[test]
    fn declarative_air_distinguishes_profile_skew_from_malformed_structure() {
        let original = customer_air();
        for incompatible in [
            {
                let mut air = original.clone();
                air.backend = "other".into();
                air
            },
            {
                let mut air = original.clone();
                air.profile = "other".into();
                air
            },
            {
                let mut air = original.clone();
                air.field = "other".into();
                air
            },
            {
                let mut air = original.clone();
                air.expected_verifier = "other".into();
                air
            },
        ] {
            assert!(matches!(
                incompatible.validate(),
                Err(ContractError::ProfileMismatch)
            ));
        }

        let mut malformed = original;
        malformed.profile = "other".into();
        malformed.constraints.clear();
        assert!(matches!(
            malformed.validate(),
            Err(ContractError::InvalidAir)
        ));
    }

    #[test]
    fn maximum_width_and_goldilocks_value_are_valid_customer_air_inputs() {
        let air = AirPackageV1 {
            schema_version: 1,
            backend: "plonky3".into(),
            profile: COMPATIBILITY_PROFILE.into(),
            field: "goldilocks".into(),
            expected_verifier: "p3_uni_stark_0.6.1".into(),
            trace_width: MAX_TRACE_WIDTH,
            public_inputs: vec![PublicInputSlotV1 {
                name: "expected".into(),
            }],
            expressions: vec![
                AirExpressionV1::Current {
                    column: MAX_TRACE_WIDTH - 1,
                },
                AirExpressionV1::Constant {
                    value: GOLDILOCKS_MODULUS_U64 - 1,
                },
                AirExpressionV1::Sub { left: 0, right: 1 },
            ],
            constraints: vec![AirConstraintV1 {
                kind: AirConstraintKindV1::FirstRow,
                expression: 2,
            }],
        };
        air.validate().unwrap();
        assert_eq!(
            hex_lower(&air.digest().unwrap()),
            "6886efd9315d23e967964ab8ca67e635558cf89c245c7fa787ae35ef05543fbc"
        );

        let mut duplicate = air.clone();
        duplicate.public_inputs.push(PublicInputSlotV1 {
            name: "expected".into(),
        });
        assert!(matches!(
            duplicate.validate(),
            Err(ContractError::InvalidAir)
        ));

        let mut unsafe_boundary = air;
        unsafe_boundary
            .expressions
            .push(AirExpressionV1::Next { column: 0 });
        unsafe_boundary.constraints[0].expression = (unsafe_boundary.expressions.len() - 1) as u32;
        assert!(matches!(
            unsafe_boundary.validate(),
            Err(ContractError::InvalidAir)
        ));
    }

    #[test]
    fn trace_manifest_binds_air_shape_chunks_and_expanded_size() {
        let air = customer_air();
        let mut trace = TraceManifestV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&air.digest().unwrap()),
            trace_digest_hex: "11".repeat(32),
            logical_rows: MIN_CUSTOM_TRACE_ROWS,
            trace_width: 1,
            field_encoding: "goldilocks_u64_le".into(),
            compression: "zstd".into(),
            chunk_uncompressed_bytes: MIN_CUSTOM_TRACE_ROWS * 8,
            chunks: vec![TraceChunkV1 {
                index: 0,
                compressed_bytes: 256,
                uncompressed_bytes: MIN_CUSTOM_TRACE_ROWS * 8,
                blake3_hex: "22".repeat(32),
            }],
        };
        trace.validate_for_air(&air).unwrap();

        trace.chunks[0].index = 1;
        assert!(matches!(
            trace.validate_for_air(&air),
            Err(ContractError::InvalidTrace)
        ));
        trace.chunks[0].index = 0;
        trace.chunks[0].uncompressed_bytes = MAX_TRACE_UNCOMPRESSED_BYTES + 1;
        assert!(trace.validate_for_air(&air).is_err());
    }

    /// The same customer AIR, declared over BabyBear instead of Goldilocks.
    fn babybear_air() -> AirPackageV1 {
        AirPackageV1 {
            field: crate::profile::BabyBearProfile::FIELD_NAME.into(),
            ..customer_air()
        }
    }

    /// Values in `[BABYBEAR_MODULUS, GOLDILOCKS_MODULUS)` are the whole hazard:
    /// every validator in this file used to admit them for any field, and the
    /// field constructor would then reduce them mod 2^31-2^27+1, so `x` and
    /// `x + p` became the same public input and the same proof.
    #[test]
    fn babybear_public_inputs_above_its_modulus_are_rejected() {
        let mut air = babybear_air();
        air.public_inputs = vec![PublicInputSlotV1 {
            name: "expected".into(),
        }];
        air.expressions.push(AirExpressionV1::Public { index: 0 });
        air.validate().expect("a BabyBear AIR must be declarable");

        let inputs = |value: u64| PublicInputsV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&air.digest().unwrap()),
            values: vec![value],
        };

        for value in [
            BABYBEAR_MODULUS_U64,
            BABYBEAR_MODULUS_U64 + 1,
            GOLDILOCKS_MODULUS_U64 - 1,
        ] {
            assert!(
                matches!(
                    inputs(value).validate_for_air(&air),
                    Err(ContractError::InvalidAir)
                ),
                "BabyBear admitted the non-canonical public input {value}"
            );
        }

        // ...and the largest canonical BabyBear value still passes, so the
        // bound is not off by one.
        inputs(BABYBEAR_MODULUS_U64 - 1)
            .validate_for_air(&air)
            .expect("the largest canonical BabyBear public input must validate");

        // The identical value is legitimate for the Goldilocks AIR, which is
        // what makes this a field-relative bound rather than a tightening.
        let goldilocks = AirPackageV1 {
            public_inputs: air.public_inputs.clone(),
            expressions: air.expressions.clone(),
            ..customer_air()
        };
        PublicInputsV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&goldilocks.digest().unwrap()),
            values: vec![BABYBEAR_MODULUS_U64],
        }
        .validate_for_air(&goldilocks)
        .expect("Goldilocks must still accept a value above BabyBear's modulus");
    }

    #[test]
    fn babybear_air_constants_are_bounded_by_babybears_modulus() {
        let mut air = babybear_air();
        air.expressions.push(AirExpressionV1::Constant {
            value: BABYBEAR_MODULUS_U64,
        });
        assert!(matches!(air.validate(), Err(ContractError::InvalidAir)));

        air.expressions.pop();
        air.expressions.push(AirExpressionV1::Constant {
            value: BABYBEAR_MODULUS_U64 - 1,
        });
        air.validate()
            .expect("the largest canonical BabyBear constant must validate");
    }

    /// A BabyBear trace is four bytes per element, so a manifest that declares
    /// Goldilocks' eight-byte encoding — or sizes its chunks by it — describes
    /// a different trace than the AIR does.
    #[test]
    fn babybear_trace_manifests_must_use_babybears_encoding_and_width() {
        let air = babybear_air();
        let rows = MIN_CUSTOM_TRACE_ROWS;
        let babybear_bytes = rows * 4;
        let mut trace = TraceManifestV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&air.digest().unwrap()),
            trace_digest_hex: "11".repeat(32),
            logical_rows: rows,
            trace_width: 1,
            field_encoding: "babybear_u32_le".into(),
            compression: "zstd".into(),
            chunk_uncompressed_bytes: babybear_bytes,
            chunks: vec![TraceChunkV1 {
                index: 0,
                compressed_bytes: 256,
                uncompressed_bytes: babybear_bytes,
                blake3_hex: "22".repeat(32),
            }],
        };
        trace.validate_for_air(&air).unwrap();

        trace.field_encoding = "goldilocks_u64_le".into();
        assert!(matches!(
            trace.validate_for_air(&air),
            Err(ContractError::InvalidTrace)
        ));

        // Goldilocks' eight-byte sizing is now a size mismatch, not a pass.
        trace.field_encoding = "babybear_u32_le".into();
        trace.chunk_uncompressed_bytes = rows * 8;
        trace.chunks[0].uncompressed_bytes = rows * 8;
        assert!(matches!(
            trace.validate_for_air(&air),
            Err(ContractError::InvalidTrace)
        ));
    }

    /// `AirProofBundleV1` stamps `dependency_profile: COMPATIBILITY_PROFILE`
    /// unconditionally, and the signed record behind that string documents one
    /// qualified field. Refusing beats relabelling.
    #[test]
    fn air_proof_bundles_refuse_a_non_goldilocks_air_rather_than_relabelling_it() {
        let air = babybear_air();
        let rows = MIN_CUSTOM_TRACE_ROWS;
        let trace = TraceManifestV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&air.digest().unwrap()),
            trace_digest_hex: "11".repeat(32),
            logical_rows: rows,
            trace_width: 1,
            field_encoding: "babybear_u32_le".into(),
            compression: "zstd".into(),
            chunk_uncompressed_bytes: rows * 4,
            chunks: vec![TraceChunkV1 {
                index: 0,
                compressed_bytes: 256,
                uncompressed_bytes: rows * 4,
                blake3_hex: "22".repeat(32),
            }],
        };
        let public_inputs = PublicInputsV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&air.digest().unwrap()),
            values: vec![],
        };
        assert!(matches!(
            AirProofBundleV1::from_proof(air, trace, public_inputs, vec![1, 2, 3], "release"),
            Err(ContractError::ProfileMismatch)
        ));
    }

    /// The whole point of the table is that a name it does not know resolves to
    /// nothing, rather than inheriting Goldilocks' bounds by default.
    #[test]
    fn air_packages_still_reject_fields_with_no_canonicality_rule() {
        for name in ["", "other", "koalabear", "GOLDILOCKS"] {
            let air = AirPackageV1 {
                field: name.into(),
                ..customer_air()
            };
            assert!(
                matches!(air.validate(), Err(ContractError::ProfileMismatch)),
                "{name} was admitted as a field"
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
