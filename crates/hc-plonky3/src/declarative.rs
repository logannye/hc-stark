use crate::contracts::{AirConstraintKindV1, AirExpressionV1, AirPackageV1, TraceManifestV1};
use crate::profile::{DurableFieldProfile, GoldilocksProfile};
use crate::{
    estimate_resource_bounded_workload, plan_resource_workload, verify_resource_bounded_proof,
    GeneratedTraceV1, GoldilocksWord, ResourceBoundedWorkload, ResourceExecutionPlanV1,
    WorkloadError, WorkloadIdentityV1, GOLDILOCKS_MODULUS_U64,
};
use hc_stream::{ArtifactDigest, MatrixStore, ResourceEstimate, ResourcePolicyV1};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Dup, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const DECLARATIVE_WORKLOAD_ID: &str = "declarative_air_v1";

#[derive(Clone, Debug)]
pub struct DeclarativeAir {
    package: AirPackageV1,
    next_columns: Vec<usize>,
    max_degree: usize,
}

/// Every `ResourceBoundedWorkload` in this module is implemented at the trait's
/// default parameters — `<8, 4, GoldilocksProfile>` — so its public values are
/// `Vec<Goldilocks>` and its trace store is `MatrixStore<GoldilocksWord>`. It
/// therefore cannot represent an AIR that declares another field, and the four
/// `GOLDILOCKS_MODULUS_U64` bounds and `* 8` row arithmetic below are exact only
/// because of this refusal.
///
/// `AirPackageV1::validate` admits any field this crate has canonicality rules
/// for, which is a strictly wider set. Refusing here rather than reducing mod p
/// is what keeps a BabyBear-declared statement from being proved — or
/// **verified** — as a Goldilocks one. The verify path matters as much as the
/// prove path: `verify_declarative_proof` builds a `DeclarativeStatement`, so
/// without this guard a BabyBear AIR would be checked against a Goldilocks
/// transcript.
fn require_goldilocks_air(package: &AirPackageV1) -> Result<(), WorkloadError> {
    if package.field != <GoldilocksProfile as DurableFieldProfile<8, 4>>::FIELD_NAME {
        return Err(WorkloadError::InvalidShape);
    }
    Ok(())
}

impl DeclarativeAir {
    pub fn new(package: AirPackageV1) -> Result<Self, WorkloadError> {
        package
            .validate()
            .map_err(|_| WorkloadError::InvalidShape)?;
        require_goldilocks_air(&package)?;
        let mut next_columns = Vec::new();
        let mut degrees: Vec<usize> = Vec::with_capacity(package.expressions.len());
        for expression in &package.expressions {
            let degree = match *expression {
                AirExpressionV1::Constant { .. } | AirExpressionV1::Public { .. } => 0,
                AirExpressionV1::Current { .. } => 1,
                AirExpressionV1::Next { column } => {
                    next_columns.push(column as usize);
                    1
                }
                AirExpressionV1::Add { left, right } | AirExpressionV1::Sub { left, right } => {
                    degrees[left as usize].max(degrees[right as usize])
                }
                AirExpressionV1::Mul { left, right } => {
                    degrees[left as usize] + degrees[right as usize]
                }
            };
            degrees.push(degree);
        }
        next_columns.sort_unstable();
        next_columns.dedup();
        let max_degree = package
            .constraints
            .iter()
            .map(|constraint| degrees[constraint.expression as usize])
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        Ok(Self {
            package,
            next_columns,
            max_degree,
        })
    }

    pub fn package(&self) -> &AirPackageV1 {
        &self.package
    }
}

impl<F> BaseAir<F> for DeclarativeAir {
    fn width(&self) -> usize {
        self.package.trace_width as usize
    }

    fn num_public_values(&self) -> usize {
        self.package.public_inputs.len()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(self.max_degree)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        self.next_columns.clone()
    }
}

impl<AB: AirBuilder> Air<AB> for DeclarativeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.current_slice();
        let next = main.next_slice();
        let public = builder.public_values();
        let mut values: Vec<AB::Expr> = Vec::with_capacity(self.package.expressions.len());
        for expression in &self.package.expressions {
            let value = match *expression {
                AirExpressionV1::Constant { value } => AB::Expr::from(AB::F::from_u64(value)),
                AirExpressionV1::Current { column } => current[column as usize].into(),
                AirExpressionV1::Next { column } => next[column as usize].into(),
                AirExpressionV1::Public { index } => public[index as usize].into(),
                AirExpressionV1::Add { left, right } => {
                    values[left as usize].dup() + values[right as usize].dup()
                }
                AirExpressionV1::Sub { left, right } => {
                    values[left as usize].dup() - values[right as usize].dup()
                }
                AirExpressionV1::Mul { left, right } => {
                    values[left as usize].dup() * values[right as usize].dup()
                }
            };
            values.push(value);
        }
        for constraint in &self.package.constraints {
            let value = values[constraint.expression as usize].dup();
            match constraint.kind {
                AirConstraintKindV1::Transition => builder.when_transition().assert_zero(value),
                AirConstraintKindV1::FirstRow => builder.when_first_row().assert_zero(value),
                AirConstraintKindV1::LastRow => builder.when_last_row().assert_zero(value),
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct UploadedTraceWorkload {
    air: DeclarativeAir,
    manifest: TraceManifestV1,
    public_values: Vec<u64>,
    chunks_dir: PathBuf,
    input_digest: [u8; 32],
}

/// zstd is scoped to non-wasm targets in Cargo.toml: its build script
/// compiles an x86-64 assembly file even when targeting wasm32, which made
/// `hc-wasm` -- and therefore the vendored WASM estimator -- unbuildable for
/// that target. The uploaded-trace path below reads chunk FILES, so it is
/// already unreachable on wasm32; this shim keeps the call sites identical
/// on both targets rather than cfg-gating public methods, so the crate's API
/// does not change shape by target.
#[cfg(not(target_arch = "wasm32"))]
mod compression {
    use super::WorkloadError;
    use std::io::Read;

    pub(super) fn decoder<R: Read>(reader: R) -> Result<impl Read, WorkloadError> {
        zstd::stream::read::Decoder::new(reader).map_err(|_| WorkloadError::InvalidShape)
    }
}

#[cfg(target_arch = "wasm32")]
mod compression {
    use super::WorkloadError;
    use std::io::Read;

    /// Unreachable on wasm32: reaching it requires an opened chunk file, and
    /// this target has no filesystem. Fails closed rather than silently
    /// returning empty data, so a future caller that does reach it gets an
    /// error instead of a zero-row trace.
    pub(super) fn decoder<R: Read>(_reader: R) -> Result<std::io::Empty, WorkloadError> {
        Err(WorkloadError::InvalidShape)
    }
}

impl UploadedTraceWorkload {
    pub fn new(
        air: AirPackageV1,
        manifest: TraceManifestV1,
        public_values: Vec<u64>,
        chunks_dir: impl Into<PathBuf>,
    ) -> Result<Self, WorkloadError> {
        let air = DeclarativeAir::new(air)?;
        manifest
            .validate_for_air(air.package())
            .map_err(|_| WorkloadError::InvalidShape)?;
        if public_values.len() != air.package.public_inputs.len()
            || public_values
                .iter()
                .any(|value| *value >= GOLDILOCKS_MODULUS_U64)
        {
            return Err(WorkloadError::InvalidShape);
        }
        let row_bytes = u64::from(manifest.trace_width) * 8;
        if !manifest.chunk_uncompressed_bytes.is_multiple_of(row_bytes) {
            return Err(WorkloadError::InvalidShape);
        }
        let chunks_dir = chunks_dir.into();
        let details = fs::symlink_metadata(&chunks_dir).map_err(|_| WorkloadError::InvalidShape)?;
        if !details.file_type().is_dir() {
            return Err(WorkloadError::InvalidShape);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(
            air.package
                .digest()
                .map_err(|_| WorkloadError::InvalidShape)?
                .as_slice(),
        );
        hasher.update(
            manifest
                .digest()
                .map_err(|_| WorkloadError::InvalidShape)?
                .as_slice(),
        );
        for value in &public_values {
            hasher.update(&value.to_le_bytes());
        }
        Ok(Self {
            air,
            manifest,
            public_values,
            chunks_dir,
            input_digest: *hasher.finalize().as_bytes(),
        })
    }

    fn chunk_path(&self, index: u32) -> PathBuf {
        self.chunks_dir.join(format!("chunk-{index:06}.zst"))
    }

    /// Fully validate every supplied trace chunk without creating scratch
    /// state or materializing the trace.
    ///
    /// Construction validates the AIR/manifest/public-input identity. This
    /// additional pass binds that identity to the actual compressed and
    /// uncompressed chunk bytes before a checkpoint is accepted for resume.
    pub fn validate_trace_chunks(&self) -> Result<(), WorkloadError> {
        let width =
            usize::try_from(self.manifest.trace_width).map_err(|_| WorkloadError::InvalidShape)?;
        let row_bytes = width.checked_mul(8).ok_or(WorkloadError::InvalidShape)?;
        let expected_total = self
            .manifest
            .logical_rows
            .checked_mul(row_bytes as u64)
            .ok_or(WorkloadError::InvalidShape)?;
        let mut total_uncompressed = 0u64;
        let mut raw_hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024];

        for chunk in &self.manifest.chunks {
            let path = self.chunk_path(chunk.index);
            let file = open_validated_chunk(&path, chunk.compressed_bytes, &chunk.blake3_hex)?;
            let mut decoder = compression::decoder(file)?;
            let mut remaining = chunk.uncompressed_bytes;
            while remaining > 0 {
                let read_len = usize::try_from(remaining.min(buffer.len() as u64))
                    .map_err(|_| WorkloadError::InvalidShape)?;
                decoder
                    .read_exact(&mut buffer[..read_len])
                    .map_err(|_| WorkloadError::InvalidShape)?;
                if !buffer[..read_len].chunks_exact(8).remainder().is_empty()
                    || buffer[..read_len].chunks_exact(8).any(|encoded| {
                        u64::from_le_bytes(
                            encoded
                                .try_into()
                                .expect("chunks_exact(8) always yields eight bytes"),
                        ) >= GOLDILOCKS_MODULUS_U64
                    })
                {
                    return Err(WorkloadError::InvalidShape);
                }
                raw_hasher.update(&buffer[..read_len]);
                remaining -= read_len as u64;
                total_uncompressed = total_uncompressed
                    .checked_add(read_len as u64)
                    .ok_or(WorkloadError::InvalidShape)?;
            }
            let mut extra = [0u8; 1];
            if decoder
                .read(&mut extra)
                .map_err(|_| WorkloadError::InvalidShape)?
                != 0
            {
                return Err(WorkloadError::InvalidShape);
            }
        }

        if total_uncompressed != expected_total
            || hex_lower(raw_hasher.finalize().as_bytes()) != self.manifest.trace_digest_hex
        {
            return Err(WorkloadError::InvalidShape);
        }
        Ok(())
    }
}

impl ResourceBoundedWorkload for UploadedTraceWorkload {
    type Air = DeclarativeAir;

    fn identity(&self) -> WorkloadIdentityV1 {
        WorkloadIdentityV1 {
            id: DECLARATIVE_WORKLOAD_ID,
            version: 1,
        }
    }

    fn rows(&self) -> u64 {
        self.manifest.logical_rows
    }

    fn air(&self) -> Self::Air {
        self.air.clone()
    }

    fn public_values(&self) -> Vec<Goldilocks> {
        self.public_values
            .iter()
            .copied()
            .map(Goldilocks::from_u64)
            .collect()
    }

    fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }

    fn write_trace<S: MatrixStore<GoldilocksWord>>(
        &self,
        store: &mut S,
        block_rows: usize,
    ) -> Result<GeneratedTraceV1, WorkloadError> {
        if block_rows == 0
            || store.rows() != self.rows()
            || store.columns() != self.air.package.trace_width as usize
        {
            return Err(WorkloadError::InvalidShape);
        }
        let width = self.air.package.trace_width as usize;
        let row_bytes = width.checked_mul(8).ok_or(WorkloadError::InvalidShape)?;
        let mut global_row = 0u64;
        for chunk in &self.manifest.chunks {
            let path = self.chunk_path(chunk.index);
            let file = open_validated_chunk(&path, chunk.compressed_bytes, &chunk.blake3_hex)?;
            let mut decoder = compression::decoder(file)?;
            let chunk_rows = usize::try_from(chunk.uncompressed_bytes / row_bytes as u64)
                .map_err(|_| WorkloadError::InvalidShape)?;
            let mut remaining_rows = chunk_rows;
            while remaining_rows > 0 {
                let rows = remaining_rows.min(block_rows);
                let mut bytes = vec![0u8; rows * row_bytes];
                decoder
                    .read_exact(&mut bytes)
                    .map_err(|_| WorkloadError::InvalidShape)?;
                let mut words = Vec::with_capacity(rows * width);
                for encoded in bytes.chunks_exact(8) {
                    let value = u64::from_le_bytes(
                        encoded
                            .try_into()
                            .map_err(|_| WorkloadError::InvalidShape)?,
                    );
                    if value >= GOLDILOCKS_MODULUS_U64 {
                        return Err(WorkloadError::InvalidShape);
                    }
                    words.push(GoldilocksWord(Goldilocks::from_u64(value)));
                }
                store.write_rows(global_row, rows, &words)?;
                global_row += rows as u64;
                remaining_rows -= rows;
            }
            let mut extra = [0u8; 1];
            if decoder
                .read(&mut extra)
                .map_err(|_| WorkloadError::InvalidShape)?
                != 0
            {
                return Err(WorkloadError::InvalidShape);
            }
        }
        if global_row != self.rows() {
            return Err(WorkloadError::InvalidShape);
        }
        let trace_digest = store.finalize()?;
        if hex_lower(&trace_digest.blake3) != self.manifest.trace_digest_hex {
            return Err(WorkloadError::InvalidShape);
        }
        Ok(GeneratedTraceV1 {
            identity: self.identity(),
            rows: self.rows(),
            columns: width,
            public_values: self.public_values(),
            input_digest: self.input_digest,
            trace_digest: ArtifactDigest {
                rows: trace_digest.rows,
                columns: trace_digest.columns,
                element_width: trace_digest.element_width,
                blake3: trace_digest.blake3,
            },
        })
    }
}

#[derive(Clone, Debug)]
struct DeclarativeStatement {
    air: DeclarativeAir,
    rows: u64,
    public_values: Vec<u64>,
    input_digest: [u8; 32],
}

impl DeclarativeStatement {
    fn new(air: AirPackageV1, rows: u64, public_values: &[u64]) -> Result<Self, WorkloadError> {
        let air = DeclarativeAir::new(air)?;
        if rows == 0
            || !rows.is_power_of_two()
            || public_values.len() != air.package.public_inputs.len()
            || public_values
                .iter()
                .any(|value| *value >= GOLDILOCKS_MODULUS_U64)
        {
            return Err(WorkloadError::InvalidShape);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(
            air.package
                .digest()
                .map_err(|_| WorkloadError::InvalidShape)?
                .as_slice(),
        );
        hasher.update(&rows.to_le_bytes());
        for value in public_values {
            hasher.update(&value.to_le_bytes());
        }
        Ok(Self {
            air,
            rows,
            public_values: public_values.to_vec(),
            input_digest: *hasher.finalize().as_bytes(),
        })
    }
}

impl ResourceBoundedWorkload for DeclarativeStatement {
    type Air = DeclarativeAir;

    fn identity(&self) -> WorkloadIdentityV1 {
        WorkloadIdentityV1 {
            id: DECLARATIVE_WORKLOAD_ID,
            version: 1,
        }
    }

    fn rows(&self) -> u64 {
        self.rows
    }

    fn air(&self) -> Self::Air {
        self.air.clone()
    }

    fn public_values(&self) -> Vec<Goldilocks> {
        self.public_values
            .iter()
            .copied()
            .map(Goldilocks::from_u64)
            .collect()
    }

    fn input_digest(&self) -> [u8; 32] {
        self.input_digest
    }

    fn write_trace<S: MatrixStore<GoldilocksWord>>(
        &self,
        _store: &mut S,
        _block_rows: usize,
    ) -> Result<GeneratedTraceV1, WorkloadError> {
        Err(WorkloadError::InvalidShape)
    }
}

pub fn verify_declarative_proof(
    air: AirPackageV1,
    rows: u64,
    public_values: &[u64],
    proof_bytes: &[u8],
) -> Result<(), WorkloadError> {
    let statement = DeclarativeStatement::new(air, rows, public_values)?;
    verify_resource_bounded_proof(&statement, proof_bytes).map_err(|_| WorkloadError::InvalidShape)
}

pub fn estimate_declarative_statement(
    air: AirPackageV1,
    rows: u64,
    public_values: &[u64],
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate, WorkloadError> {
    let statement = DeclarativeStatement::new(air, rows, public_values)?;
    estimate_resource_bounded_workload(&statement, policy).map_err(|_| WorkloadError::InvalidShape)
}

/// Return both conventional and bounded estimates without performing resource
/// preflight. The exact-contract doctor uses this so an insufficient budget
/// still produces a complete, actionable report instead of losing the
/// estimates inside an error.
pub fn estimate_declarative_execution_paths(
    air: AirPackageV1,
    rows: u64,
    public_values: &[u64],
    policy: &ResourcePolicyV1,
) -> std::result::Result<(ResourceEstimate, ResourceEstimate), crate::BoundedProverError> {
    let statement = DeclarativeStatement::new(air, rows, public_values)?;
    let conventional = crate::estimate_resource_conventional_workload(&statement)?;
    let bounded = crate::estimate_resource_bounded_workload(&statement, policy)?;
    Ok((conventional, bounded))
}

/// Mode-aware conventional/bounded plan for a declarative AIR statement.
/// Trace bytes are not read; the caller must separately validate the trace
/// manifest before presenting this estimate as applicable to an upload.
pub fn plan_declarative_statement(
    air: AirPackageV1,
    rows: u64,
    public_values: &[u64],
    policy: &ResourcePolicyV1,
) -> std::result::Result<ResourceExecutionPlanV1, crate::BoundedProverError> {
    let statement = DeclarativeStatement::new(air, rows, public_values)?;
    plan_resource_workload(&statement, policy)
}

fn open_validated_chunk(
    path: &Path,
    expected_bytes: u64,
    expected_digest: &str,
) -> Result<File, WorkloadError> {
    let details = fs::symlink_metadata(path).map_err(|_| WorkloadError::InvalidShape)?;
    if !details.file_type().is_file() || details.len() != expected_bytes {
        return Err(WorkloadError::InvalidShape);
    }
    let mut file = File::open(path).map_err(|_| WorkloadError::InvalidShape)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| WorkloadError::InvalidShape)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if hex_lower(hasher.finalize().as_bytes()) != expected_digest {
        return Err(WorkloadError::InvalidShape);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WorkloadError::InvalidShape)?;
    Ok(file)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        AirConstraintV1, AirProofBundleV1, PublicInputSlotV1, PublicInputsV1, TraceChunkV1,
        MIN_CUSTOM_TRACE_ROWS,
    };
    use crate::{prove_resource_bounded, prove_resource_reference, verify_resource_bounded_proof};
    use hc_stream::{CheckpointPolicy, ResourceMode, ResourcePolicyV1};
    use tempfile::tempdir;

    fn fibonacci_air() -> AirPackageV1 {
        AirPackageV1 {
            schema_version: 1,
            backend: "plonky3".into(),
            profile: crate::COMPATIBILITY_PROFILE.into(),
            field: "goldilocks".into(),
            expected_verifier: "p3_uni_stark_0.6.1".into(),
            trace_width: 2,
            public_inputs: ["initial_a", "initial_b", "final_value"]
                .into_iter()
                .map(|name| PublicInputSlotV1 { name: name.into() })
                .collect(),
            expressions: vec![
                AirExpressionV1::Current { column: 0 },
                AirExpressionV1::Public { index: 0 },
                AirExpressionV1::Sub { left: 0, right: 1 },
                AirExpressionV1::Current { column: 1 },
                AirExpressionV1::Public { index: 1 },
                AirExpressionV1::Sub { left: 3, right: 4 },
                AirExpressionV1::Next { column: 0 },
                AirExpressionV1::Sub { left: 6, right: 3 },
                AirExpressionV1::Next { column: 1 },
                AirExpressionV1::Add { left: 0, right: 3 },
                AirExpressionV1::Sub { left: 8, right: 9 },
                AirExpressionV1::Public { index: 2 },
                AirExpressionV1::Sub { left: 3, right: 11 },
            ],
            constraints: vec![
                AirConstraintV1 {
                    kind: AirConstraintKindV1::FirstRow,
                    expression: 2,
                },
                AirConstraintV1 {
                    kind: AirConstraintKindV1::FirstRow,
                    expression: 5,
                },
                AirConstraintV1 {
                    kind: AirConstraintKindV1::Transition,
                    expression: 7,
                },
                AirConstraintV1 {
                    kind: AirConstraintKindV1::Transition,
                    expression: 10,
                },
                AirConstraintV1 {
                    kind: AirConstraintKindV1::LastRow,
                    expression: 12,
                },
            ],
        }
    }

    fn packed_fibonacci(dir: &Path) -> (TraceManifestV1, Vec<u64>) {
        let rows = MIN_CUSTOM_TRACE_ROWS;
        let mut left = 0u64;
        let mut right = 1u64;
        let mut raw = Vec::with_capacity(rows as usize * 16);
        for _ in 0..rows {
            raw.extend_from_slice(&left.to_le_bytes());
            raw.extend_from_slice(&right.to_le_bytes());
            (left, right) = (
                right,
                ((u128::from(left) + u128::from(right)) % u128::from(GOLDILOCKS_MODULUS_U64))
                    as u64,
            );
        }
        let public = vec![
            0,
            1,
            u64::from_le_bytes(raw[raw.len() - 8..].try_into().unwrap()),
        ];
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        fs::write(dir.join("chunk-000000.zst"), &compressed).unwrap();
        let air = fibonacci_air();
        (
            TraceManifestV1 {
                schema_version: 1,
                air_digest_hex: hex_lower(&air.digest().unwrap()),
                trace_digest_hex: hex_lower(blake3::hash(&raw).as_bytes()),
                logical_rows: rows,
                trace_width: 2,
                field_encoding: "goldilocks_u64_le".into(),
                compression: "zstd".into(),
                chunk_uncompressed_bytes: raw.len() as u64,
                chunks: vec![TraceChunkV1 {
                    index: 0,
                    compressed_bytes: compressed.len() as u64,
                    uncompressed_bytes: raw.len() as u64,
                    blake3_hex: hex_lower(blake3::hash(&compressed).as_bytes()),
                }],
            },
            public,
        )
    }

    fn customer_cubic8_air() -> AirPackageV1 {
        fn push(expressions: &mut Vec<AirExpressionV1>, value: AirExpressionV1) -> u32 {
            expressions.push(value);
            u32::try_from(expressions.len() - 1).unwrap()
        }

        let mut expressions = Vec::new();
        let mut constraints = Vec::new();
        for column in 0..8u32 {
            let current = push(&mut expressions, AirExpressionV1::Current { column });
            let initial = push(&mut expressions, AirExpressionV1::Public { index: column });
            let first = push(
                &mut expressions,
                AirExpressionV1::Sub {
                    left: current,
                    right: initial,
                },
            );
            constraints.push(AirConstraintV1 {
                kind: AirConstraintKindV1::FirstRow,
                expression: first,
            });

            let square = push(
                &mut expressions,
                AirExpressionV1::Mul {
                    left: current,
                    right: current,
                },
            );
            let cube = push(
                &mut expressions,
                AirExpressionV1::Mul {
                    left: square,
                    right: current,
                },
            );
            let neighbor = push(
                &mut expressions,
                AirExpressionV1::Current {
                    column: (column + 1) % 8,
                },
            );
            let expected = push(
                &mut expressions,
                AirExpressionV1::Add {
                    left: cube,
                    right: neighbor,
                },
            );
            let next = push(&mut expressions, AirExpressionV1::Next { column });
            let transition = push(
                &mut expressions,
                AirExpressionV1::Sub {
                    left: next,
                    right: expected,
                },
            );
            constraints.push(AirConstraintV1 {
                kind: AirConstraintKindV1::Transition,
                expression: transition,
            });

            let final_value = push(
                &mut expressions,
                AirExpressionV1::Public { index: 8 + column },
            );
            let last = push(
                &mut expressions,
                AirExpressionV1::Sub {
                    left: current,
                    right: final_value,
                },
            );
            constraints.push(AirConstraintV1 {
                kind: AirConstraintKindV1::LastRow,
                expression: last,
            });
        }
        AirPackageV1 {
            schema_version: 1,
            backend: "plonky3".into(),
            profile: crate::COMPATIBILITY_PROFILE.into(),
            field: "goldilocks".into(),
            expected_verifier: "p3_uni_stark_0.6.1".into(),
            trace_width: 8,
            public_inputs: (0..16)
                .map(|index| PublicInputSlotV1 {
                    name: if index < 8 {
                        format!("initial_{index}")
                    } else {
                        format!("final_{}", index - 8)
                    },
                })
                .collect(),
            expressions,
            constraints,
        }
    }

    fn packed_customer_cubic8(dir: &Path) -> (TraceManifestV1, Vec<u64>) {
        fn mul_mod(left: u64, right: u64) -> u64 {
            (u128::from(left) * u128::from(right) % u128::from(GOLDILOCKS_MODULUS_U64)) as u64
        }

        let rows = MIN_CUSTOM_TRACE_ROWS;
        let initial: [u64; 8] = std::array::from_fn(|index| index as u64 + 1);
        let mut state = initial;
        let mut final_row = initial;
        let mut raw = Vec::with_capacity(rows as usize * 8 * 8);
        for _ in 0..rows {
            final_row = state;
            for value in state {
                raw.extend_from_slice(&value.to_le_bytes());
            }
            state = std::array::from_fn(|column| {
                let cube = mul_mod(
                    mul_mod(final_row[column], final_row[column]),
                    final_row[column],
                );
                ((u128::from(cube) + u128::from(final_row[(column + 1) % 8]))
                    % u128::from(GOLDILOCKS_MODULUS_U64)) as u64
            });
        }
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        fs::write(dir.join("chunk-000000.zst"), &compressed).unwrap();
        let air = customer_cubic8_air();
        (
            TraceManifestV1 {
                schema_version: 1,
                air_digest_hex: hex_lower(&air.digest().unwrap()),
                trace_digest_hex: hex_lower(blake3::hash(&raw).as_bytes()),
                logical_rows: rows,
                trace_width: 8,
                field_encoding: "goldilocks_u64_le".into(),
                compression: "zstd".into(),
                chunk_uncompressed_bytes: raw.len() as u64,
                chunks: vec![TraceChunkV1 {
                    index: 0,
                    compressed_bytes: compressed.len() as u64,
                    uncompressed_bytes: raw.len() as u64,
                    blake3_hex: hex_lower(blake3::hash(&compressed).as_bytes()),
                }],
            },
            initial.into_iter().chain(final_row).collect(),
        )
    }

    #[test]
    fn uploaded_declarative_trace_is_official_and_byte_identical() {
        let dir = tempdir().unwrap();
        let chunks = dir.path().join("chunks");
        fs::create_dir(&chunks).unwrap();
        let (manifest, public) = packed_fibonacci(&chunks);
        let workload =
            UploadedTraceWorkload::new(fibonacci_air(), manifest.clone(), public.clone(), &chunks)
                .unwrap();
        let policy = ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 128 * 1024 * 1024,
            max_scratch_bytes: 2 * 1024 * 1024 * 1024,
            scratch_dir: dir.path().join("scratch"),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        };
        let bounded = prove_resource_bounded(&workload, &policy).unwrap();
        let reference = prove_resource_reference(&workload).unwrap();
        assert_eq!(bounded, reference);
        verify_resource_bounded_proof(&workload, &bounded).unwrap();
        let air = fibonacci_air();
        let public_inputs = PublicInputsV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&air.digest().unwrap()),
            values: public,
        };
        let bundle =
            AirProofBundleV1::from_proof(air, manifest, public_inputs, bounded, "test-release")
                .unwrap();
        bundle.verify_local_registration_proof().unwrap();
    }

    /// The verify path is the one the admission gate could not close on its
    /// own. `AirPackageV1::validate` now admits any field this crate has
    /// canonicality rules for, but every workload here is
    /// `ResourceBoundedWorkload<8, 4, GoldilocksProfile>`, so a BabyBear AIR
    /// must be refused rather than proved — or verified — over Goldilocks.
    #[test]
    fn declarative_prove_and_verify_refuse_a_non_goldilocks_air() {
        let babybear = AirPackageV1 {
            field: crate::profile::BabyBearProfile::FIELD_NAME.into(),
            ..fibonacci_air()
        };
        // It is a well-formed declaration...
        babybear
            .validate()
            .expect("a BabyBear AIR must be declarable");

        // ...that this Goldilocks-typed executor refuses at every entry point.
        assert!(matches!(
            DeclarativeAir::new(babybear.clone()),
            Err(WorkloadError::InvalidShape)
        ));
        assert!(matches!(
            verify_declarative_proof(
                babybear.clone(),
                MIN_CUSTOM_TRACE_ROWS,
                &[0, 1, 1],
                &[0u8; 8]
            ),
            Err(WorkloadError::InvalidShape)
        ));

        let dir = tempdir().unwrap();
        let chunks = dir.path().join("chunks");
        fs::create_dir(&chunks).unwrap();
        let (manifest, public) = packed_fibonacci(&chunks);
        assert!(matches!(
            UploadedTraceWorkload::new(babybear, manifest, public, &chunks),
            Err(WorkloadError::InvalidShape)
        ));
    }

    #[test]
    fn uploaded_degree_three_cubic8_is_official_and_byte_identical() {
        let dir = tempdir().unwrap();
        let chunks = dir.path().join("chunks");
        fs::create_dir(&chunks).unwrap();
        let air = customer_cubic8_air();
        let (manifest, public) = packed_customer_cubic8(&chunks);
        let workload = UploadedTraceWorkload::new(air, manifest, public, &chunks).unwrap();
        let policy = ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 128 * 1024 * 1024,
            max_scratch_bytes: 2 * 1024 * 1024 * 1024,
            scratch_dir: dir.path().join("scratch"),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        };
        let bounded = prove_resource_bounded(&workload, &policy).unwrap();
        let reference = prove_resource_reference(&workload).unwrap();
        assert_eq!(bounded, reference);
        verify_resource_bounded_proof(&workload, &bounded).unwrap();
    }

    #[test]
    fn uploaded_declarative_trace_resumes_from_its_bound_checkpoint() {
        let dir = tempdir().unwrap();
        let chunks = dir.path().join("chunks");
        fs::create_dir(&chunks).unwrap();
        let air = fibonacci_air();
        let (manifest, public) = packed_fibonacci(&chunks);
        let workload = UploadedTraceWorkload::new(air, manifest, public, &chunks).unwrap();
        let scratch = dir.path().join("scratch");
        let policy = ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 128 * 1024 * 1024,
            max_scratch_bytes: 2 * 1024 * 1024 * 1024,
            scratch_dir: scratch.clone(),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::RetainOnFailure,
        };
        let cancellation = crate::CancellationToken::new();
        let observer_token = cancellation.clone();
        let interrupted = crate::prove_resource_bounded_observed_with_cancellation(
            &workload,
            &policy,
            cancellation,
            move |event| {
                if matches!(
                    event,
                    crate::ProverEventV1::Phase {
                        phase: hc_stream::PipelinePhaseV1::Trace,
                        ..
                    }
                ) {
                    observer_token.cancel();
                }
            },
        );
        assert!(matches!(
            interrupted,
            Err(crate::BoundedProverError::Cancelled)
        ));
        let checkpoint = fs::read_dir(&scratch)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path().join("checkpoint.json"))
            .find(|path| path.is_file())
            .unwrap();
        let resumed = crate::resume_resource_bounded_with(&checkpoint, &workload).unwrap();
        let reference = prove_resource_reference(&workload).unwrap();
        assert_eq!(resumed, reference);
        verify_resource_bounded_proof(&workload, &resumed).unwrap();
    }
}
