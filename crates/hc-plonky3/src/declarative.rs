use crate::contracts::{AirConstraintKindV1, AirExpressionV1, AirPackageV1, TraceManifestV1};
use crate::{
    estimate_resource_bounded_workload, verify_resource_bounded_proof, GeneratedTraceV1,
    GoldilocksWord, ResourceBoundedWorkload, WorkloadError, WorkloadIdentityV1,
    GOLDILOCKS_MODULUS_U64,
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

impl DeclarativeAir {
    pub fn new(package: AirPackageV1) -> Result<Self, WorkloadError> {
        package
            .validate()
            .map_err(|_| WorkloadError::InvalidShape)?;
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
            let mut decoder =
                zstd::stream::read::Decoder::new(file).map_err(|_| WorkloadError::InvalidShape)?;
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
}
