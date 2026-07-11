//! Resource-bounded storage and deterministic recovery primitives.
//!
//! This crate deliberately has no proof-system dependency. It owns policy,
//! canonical matrix artifacts, integrity checks, and checkpoint identity. A
//! backend remains responsible for transcript and proof semantics.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
#[cfg(any(not(unix), test))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};

const STORE_MAGIC: &[u8; 8] = b"TZMATV1\0";
const STORE_HEADER_LEN: u64 = 8 + 8 + 8 + 8;
/// On-disk bytes preceding every [`ScratchMatrixStore`] payload.
pub const SCRATCH_STORE_HEADER_BYTES: u64 = STORE_HEADER_LEN;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CHALLENGER_STATE_BYTES: usize = 64 * 1024;
const MAX_RESUME_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_CHECKPOINT_ARTIFACTS: usize = 1024;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;

pub type Result<T> = std::result::Result<T, StreamError>;

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("invalid resource policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("resource requirement exceeds configured {resource}: need {required} bytes, cap {cap} bytes")]
    ResourceLimit {
        resource: &'static str,
        required: u64,
        cap: u64,
    },
    #[error("matrix range is out of bounds")]
    OutOfBounds,
    #[error("scratch artifact is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("checkpoint identity does not match this job")]
    CheckpointMismatch,
    #[error("unsafe scratch path")]
    UnsafePath,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMode {
    Auto,
    Memory,
    Scratch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointPolicy {
    Disabled,
    DeleteOnSuccess,
    RetainOnFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyV1 {
    pub mode: ResourceMode,
    pub max_resident_bytes: u64,
    pub max_scratch_bytes: u64,
    pub scratch_dir: PathBuf,
    pub max_threads: usize,
    pub checkpoint_policy: CheckpointPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Memory,
    Scratch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PhaseEstimate {
    pub phase: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceEstimate {
    pub peak_resident_bytes: u64,
    pub scratch_high_water_bytes: u64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub phases: Vec<PhaseEstimate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreflightReport {
    pub selected_mode: ExecutionMode,
    pub available_scratch_bytes: u64,
    pub memory_selection_threshold_bytes: u64,
    pub estimate: ResourceEstimate,
}

impl ResourcePolicyV1 {
    pub fn validate(&self) -> Result<()> {
        if self.max_resident_bytes < 16 * 1024 * 1024 {
            return Err(StreamError::InvalidPolicy(
                "max_resident_bytes must be at least 16 MiB",
            ));
        }
        if self.max_scratch_bytes == 0 {
            return Err(StreamError::InvalidPolicy(
                "max_scratch_bytes must be positive",
            ));
        }
        if self.scratch_dir.as_os_str().is_empty() {
            return Err(StreamError::InvalidPolicy("scratch_dir must be set"));
        }
        if self
            .scratch_dir
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(StreamError::UnsafePath);
        }
        if self.max_threads == 0 {
            return Err(StreamError::InvalidPolicy("max_threads must be positive"));
        }
        Ok(())
    }

    pub fn policy_hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(*blake3::hash(&serde_json::to_vec(self)?).as_bytes())
    }

    pub fn memory_selection_threshold(&self) -> u64 {
        self.max_resident_bytes.saturating_mul(7) / 10
    }

    pub fn select_mode(&self, estimate: &ResourceEstimate) -> Result<ExecutionMode> {
        self.validate()?;
        let selected = match self.mode {
            ResourceMode::Memory => ExecutionMode::Memory,
            ResourceMode::Scratch => ExecutionMode::Scratch,
            ResourceMode::Auto
                if estimate.peak_resident_bytes <= self.memory_selection_threshold() =>
            {
                ExecutionMode::Memory
            }
            ResourceMode::Auto => ExecutionMode::Scratch,
        };
        if selected == ExecutionMode::Memory
            && estimate.peak_resident_bytes > self.max_resident_bytes
        {
            return Err(StreamError::ResourceLimit {
                resource: "resident memory",
                required: estimate.peak_resident_bytes,
                cap: self.max_resident_bytes,
            });
        }
        if selected == ExecutionMode::Scratch
            && estimate.scratch_high_water_bytes > self.max_scratch_bytes
        {
            return Err(StreamError::ResourceLimit {
                resource: "scratch storage",
                required: estimate.scratch_high_water_bytes,
                cap: self.max_scratch_bytes,
            });
        }
        Ok(selected)
    }

    /// Validate configured limits, owner permissions, and actual free space
    /// before a backend reads the complete input.
    pub fn preflight(&self, estimate: ResourceEstimate) -> Result<PreflightReport> {
        let selected_mode = self.select_mode(&estimate)?;
        self.preflight_for_mode(selected_mode, estimate)
    }

    /// Preflight an already selected mode when the backend has distinct memory
    /// and scratch estimates. This prevents `Auto` from reselecting memory after
    /// the backend has calculated the lower resident footprint of scratch mode.
    pub fn preflight_for_mode(
        &self,
        selected_mode: ExecutionMode,
        estimate: ResourceEstimate,
    ) -> Result<PreflightReport> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (selected_mode, estimate);
            Err(StreamError::InvalidPolicy(
                "filesystem resource preflight is unavailable on wasm32",
            ))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.validate()?;
            self.validate_estimate(selected_mode, &estimate)?;
            ensure_private_dir(&self.scratch_dir)?;
            let probe = self.scratch_dir.join(format!(
                ".tinyzkp-preflight-{}-{}",
                std::process::id(),
                monotonic_suffix()
            ));
            let mut probe_file = create_private_file(&probe)?;
            probe_file.write_all(b"preflight")?;
            drop(probe_file);
            fs::remove_file(&probe)?;
            let available = fs2::available_space(&self.scratch_dir)?;
            if selected_mode == ExecutionMode::Scratch
                && estimate.scratch_high_water_bytes > available
            {
                return Err(StreamError::ResourceLimit {
                    resource: "available scratch storage",
                    required: estimate.scratch_high_water_bytes,
                    cap: available,
                });
            }
            Ok(PreflightReport {
                selected_mode,
                available_scratch_bytes: available,
                memory_selection_threshold_bytes: self.memory_selection_threshold(),
                estimate,
            })
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn validate_estimate(
        &self,
        selected_mode: ExecutionMode,
        estimate: &ResourceEstimate,
    ) -> Result<()> {
        if estimate.peak_resident_bytes > self.max_resident_bytes {
            return Err(StreamError::ResourceLimit {
                resource: "resident memory",
                required: estimate.peak_resident_bytes,
                cap: self.max_resident_bytes,
            });
        }
        if selected_mode == ExecutionMode::Scratch
            && estimate.scratch_high_water_bytes > self.max_scratch_bytes
        {
            return Err(StreamError::ResourceLimit {
                resource: "scratch storage",
                required: estimate.scratch_high_water_bytes,
                cap: self.max_scratch_bytes,
            });
        }
        Ok(())
    }

    /// Power-of-two row tile sized so two tiles and fixed backend overhead can
    /// coexist below half of the resident cap.
    pub fn tile_rows(&self, element_width: usize, columns: usize) -> Result<usize> {
        self.validate()?;
        if element_width == 0 || columns == 0 {
            return Err(StreamError::InvalidPolicy(
                "element width and columns must be positive",
            ));
        }
        let budget = self.max_resident_bytes / 2;
        let max_rows = budget
            .checked_div(2)
            .and_then(|bytes| bytes.checked_div(element_width as u64))
            .and_then(|elements| elements.checked_div(columns as u64))
            .unwrap_or(0);
        if max_rows == 0 {
            return Err(StreamError::ResourceLimit {
                resource: "resident memory",
                required: (element_width as u64).saturating_mul(columns as u64),
                cap: budget,
            });
        }
        let bounded = usize::try_from(max_rows).unwrap_or(usize::MAX);
        Ok(highest_power_of_two(bounded))
    }
}

fn highest_power_of_two(value: usize) -> usize {
    1usize << (usize::BITS - 1 - value.max(1).leading_zeros())
}

pub trait CanonicalElement: Copy + Default + Send + Sync + 'static {
    const WIDTH: usize;
    fn encode(self, out: &mut [u8]);
    fn decode(bytes: &[u8]) -> Result<Self>;
}

impl CanonicalElement for u8 {
    const WIDTH: usize = 1;

    fn encode(self, out: &mut [u8]) {
        out[0] = self;
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        bytes
            .first()
            .copied()
            .filter(|_| bytes.len() == 1)
            .ok_or(StreamError::Corrupt("invalid u8 width"))
    }
}

impl CanonicalElement for u64 {
    const WIDTH: usize = 8;

    fn encode(self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 8] = bytes
            .try_into()
            .map_err(|_| StreamError::Corrupt("invalid u64 width"))?;
        Ok(u64::from_le_bytes(bytes))
    }
}

pub trait BlockMatrix<T> {
    fn rows(&self) -> u64;
    fn columns(&self) -> usize;
    fn read_rows(&self, row_start: u64, row_count: usize, output: &mut [T]) -> Result<()>;

    /// Read a rectangular row-major tile into caller-owned storage.
    fn read_tile(
        &self,
        row_start: u64,
        row_count: usize,
        column_start: usize,
        column_count: usize,
        output: &mut [T],
    ) -> Result<()>
    where
        T: Copy + Default,
    {
        let expected = checked_tile_len(
            self.rows(),
            self.columns(),
            row_start,
            row_count,
            column_start,
            column_count,
        )?;
        if output.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        if column_start == 0 && column_count == self.columns() {
            return self.read_rows(row_start, row_count, output);
        }
        let full_len = row_count
            .checked_mul(self.columns())
            .ok_or(StreamError::OutOfBounds)?;
        let mut rows = vec![T::default(); full_len];
        self.read_rows(row_start, row_count, &mut rows)?;
        for row in 0..row_count {
            let source = row * self.columns() + column_start;
            let destination = row * column_count;
            output[destination..destination + column_count]
                .copy_from_slice(&rows[source..source + column_count]);
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.rows() == 0 || self.columns() == 0
    }
}

pub trait MatrixStore<T>: BlockMatrix<T> {
    fn write_rows(&mut self, row_start: u64, row_count: usize, values: &[T]) -> Result<()>;
    fn write_tile(
        &mut self,
        row_start: u64,
        row_count: usize,
        column_start: usize,
        column_count: usize,
        values: &[T],
    ) -> Result<()>
    where
        T: Copy + Default,
    {
        let expected = checked_tile_len(
            self.rows(),
            self.columns(),
            row_start,
            row_count,
            column_start,
            column_count,
        )?;
        if values.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        if column_start == 0 && column_count == self.columns() {
            return self.write_rows(row_start, row_count, values);
        }
        let full_len = row_count
            .checked_mul(self.columns())
            .ok_or(StreamError::OutOfBounds)?;
        let mut rows = vec![T::default(); full_len];
        self.read_rows(row_start, row_count, &mut rows)?;
        for row in 0..row_count {
            let source = row * column_count;
            let destination = row * self.columns() + column_start;
            rows[destination..destination + column_count]
                .copy_from_slice(&values[source..source + column_count]);
        }
        self.write_rows(row_start, row_count, &rows)
    }
    fn finalize(&mut self) -> Result<ArtifactDigest>;
    fn digest(&self) -> Option<ArtifactDigest>;
    fn remove(self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub rows: u64,
    pub columns: usize,
    pub element_width: usize,
    pub blake3: [u8; 32],
}

pub struct MemoryMatrix<T> {
    rows: u64,
    columns: usize,
    values: Vec<T>,
    digest: Option<ArtifactDigest>,
}

impl<T: CanonicalElement> MemoryMatrix<T> {
    pub fn preallocated(rows: u64, columns: usize) -> Result<Self> {
        if rows == 0 || columns == 0 {
            return Err(StreamError::OutOfBounds);
        }
        let elements = checked_elements(rows, columns)?;
        Ok(Self {
            rows,
            columns,
            values: vec![T::default(); elements],
            digest: None,
        })
    }
}

impl<T: CanonicalElement> BlockMatrix<T> for MemoryMatrix<T> {
    fn rows(&self) -> u64 {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn read_rows(&self, row_start: u64, row_count: usize, output: &mut [T]) -> Result<()> {
        let (start, end, expected) =
            checked_row_range(self.rows, self.columns, row_start, row_count)?;
        if output.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        output.copy_from_slice(&self.values[start..end]);
        Ok(())
    }

    fn read_tile(
        &self,
        row_start: u64,
        row_count: usize,
        column_start: usize,
        column_count: usize,
        output: &mut [T],
    ) -> Result<()> {
        let expected = checked_tile_len(
            self.rows,
            self.columns,
            row_start,
            row_count,
            column_start,
            column_count,
        )?;
        if output.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        let row_start = usize::try_from(row_start).map_err(|_| StreamError::OutOfBounds)?;
        for row in 0..row_count {
            let source = (row_start + row) * self.columns + column_start;
            let destination = row * column_count;
            output[destination..destination + column_count]
                .copy_from_slice(&self.values[source..source + column_count]);
        }
        Ok(())
    }
}

impl<T: CanonicalElement> MatrixStore<T> for MemoryMatrix<T> {
    fn write_rows(&mut self, row_start: u64, row_count: usize, values: &[T]) -> Result<()> {
        if self.digest.is_some() {
            return Err(StreamError::Corrupt("cannot mutate finalized matrix"));
        }
        let (start, end, expected) =
            checked_row_range(self.rows, self.columns, row_start, row_count)?;
        if values.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        self.values[start..end].copy_from_slice(values);
        Ok(())
    }

    fn write_tile(
        &mut self,
        row_start: u64,
        row_count: usize,
        column_start: usize,
        column_count: usize,
        values: &[T],
    ) -> Result<()> {
        if self.digest.is_some() {
            return Err(StreamError::Corrupt("cannot mutate finalized matrix"));
        }
        let expected = checked_tile_len(
            self.rows,
            self.columns,
            row_start,
            row_count,
            column_start,
            column_count,
        )?;
        if values.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        let row_start = usize::try_from(row_start).map_err(|_| StreamError::OutOfBounds)?;
        for row in 0..row_count {
            let source = row * column_count;
            let destination = (row_start + row) * self.columns + column_start;
            self.values[destination..destination + column_count]
                .copy_from_slice(&values[source..source + column_count]);
        }
        Ok(())
    }

    fn finalize(&mut self) -> Result<ArtifactDigest> {
        if let Some(digest) = self.digest {
            return Ok(digest);
        }
        let mut hasher = blake3::Hasher::new();
        let mut encoded = vec![0u8; T::WIDTH];
        for value in &self.values {
            value.encode(&mut encoded);
            hasher.update(&encoded);
        }
        let digest = ArtifactDigest {
            rows: self.rows,
            columns: self.columns,
            element_width: T::WIDTH,
            blake3: *hasher.finalize().as_bytes(),
        };
        self.digest = Some(digest);
        Ok(digest)
    }

    fn digest(&self) -> Option<ArtifactDigest> {
        self.digest
    }

    fn remove(self) -> Result<()> {
        Ok(())
    }
}

pub struct ScratchMatrixStore<T> {
    path: PathBuf,
    file: File,
    rows: u64,
    columns: usize,
    digest: Option<ArtifactDigest>,
    stable_identity: Option<StableFileIdentity>,
    _marker: PhantomData<T>,
}

impl<T: CanonicalElement> ScratchMatrixStore<T> {
    pub fn create(
        root: impl AsRef<Path>,
        file_name: &str,
        rows: u64,
        columns: usize,
    ) -> Result<Self> {
        let root = root.as_ref();
        if rows == 0 || columns == 0 {
            return Err(StreamError::OutOfBounds);
        }
        ensure_private_dir(root)?;
        validate_file_name(file_name)?;
        let path = root.join(file_name);
        let payload_len = checked_payload_bytes::<T>(rows, columns)?;
        let mut file = create_private_file(&path)?;
        file.write_all(STORE_MAGIC)?;
        file.write_all(&rows.to_le_bytes())?;
        file.write_all(&(columns as u64).to_le_bytes())?;
        file.write_all(&(T::WIDTH as u64).to_le_bytes())?;
        file.set_len(
            STORE_HEADER_LEN
                .checked_add(payload_len)
                .ok_or(StreamError::OutOfBounds)?,
        )?;
        file.sync_data()?;
        Ok(Self {
            path,
            file,
            rows,
            columns,
            digest: None,
            stable_identity: None,
            _marker: PhantomData,
        })
    }

    pub fn reopen(path: impl AsRef<Path>, expected: ArtifactDigest) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (mut file, opened_identity) = secure_open_existing_file(&path, true)?;
        let expected_payload = expected
            .rows
            .checked_mul(expected.columns as u64)
            .and_then(|elements| elements.checked_mul(expected.element_width as u64))
            .ok_or(StreamError::OutOfBounds)?;
        let expected_len = STORE_HEADER_LEN
            .checked_add(expected_payload)
            .ok_or(StreamError::OutOfBounds)?;
        if file.metadata()?.len() != expected_len {
            return Err(StreamError::Corrupt("artifact length mismatch"));
        }
        let actual_header = read_header(&mut file)?;
        if actual_header != (expected.rows, expected.columns, expected.element_width) {
            return Err(StreamError::Corrupt("artifact header mismatch"));
        }
        let actual = digest_payload::<T>(&mut file, expected.rows, expected.columns)?;
        if actual != expected {
            return Err(StreamError::Corrupt("artifact checksum mismatch"));
        }
        ensure_held_file_stable(&file, &opened_identity)?;
        Ok(Self {
            path,
            file,
            rows: expected.rows,
            columns: expected.columns,
            digest: Some(expected),
            stable_identity: Some(opened_identity),
            _marker: PhantomData,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl<T: CanonicalElement> BlockMatrix<T> for ScratchMatrixStore<T> {
    fn rows(&self) -> u64 {
        self.rows
    }

    fn columns(&self) -> usize {
        self.columns
    }

    fn read_rows(&self, row_start: u64, row_count: usize, output: &mut [T]) -> Result<()> {
        if let Some(identity) = &self.stable_identity {
            ensure_held_file_stable(&self.file, identity)?;
        }
        let (_, _, expected) = checked_row_range(self.rows, self.columns, row_start, row_count)?;
        if output.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(payload_offset::<T>(
            row_start,
            self.columns,
        )?))?;
        let byte_len = expected
            .checked_mul(T::WIDTH)
            .ok_or(StreamError::OutOfBounds)?;
        let mut bytes = vec![0u8; byte_len];
        file.read_exact(&mut bytes)?;
        for (slot, chunk) in output.iter_mut().zip(bytes.chunks_exact(T::WIDTH)) {
            *slot = T::decode(chunk)?;
        }
        if let Some(identity) = &self.stable_identity {
            ensure_held_file_stable(&self.file, identity)?;
        }
        Ok(())
    }

    fn read_tile(
        &self,
        row_start: u64,
        row_count: usize,
        column_start: usize,
        column_count: usize,
        output: &mut [T],
    ) -> Result<()> {
        if let Some(identity) = &self.stable_identity {
            ensure_held_file_stable(&self.file, identity)?;
        }
        let expected = checked_tile_len(
            self.rows,
            self.columns,
            row_start,
            row_count,
            column_start,
            column_count,
        )?;
        if output.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        let mut file = self.file.try_clone()?;
        let byte_len = column_count
            .checked_mul(T::WIDTH)
            .ok_or(StreamError::OutOfBounds)?;
        let mut bytes = vec![0u8; byte_len];
        for row in 0..row_count {
            let absolute_row = row_start
                .checked_add(row as u64)
                .ok_or(StreamError::OutOfBounds)?;
            file.seek(SeekFrom::Start(payload_tile_offset::<T>(
                absolute_row,
                self.columns,
                column_start,
            )?))?;
            file.read_exact(&mut bytes)?;
            let destination = row * column_count;
            for (slot, chunk) in output[destination..destination + column_count]
                .iter_mut()
                .zip(bytes.chunks_exact(T::WIDTH))
            {
                *slot = T::decode(chunk)?;
            }
        }
        if let Some(identity) = &self.stable_identity {
            ensure_held_file_stable(&self.file, identity)?;
        }
        Ok(())
    }
}

impl<T: CanonicalElement> MatrixStore<T> for ScratchMatrixStore<T> {
    fn write_rows(&mut self, row_start: u64, row_count: usize, values: &[T]) -> Result<()> {
        if self.digest.is_some() {
            return Err(StreamError::Corrupt("cannot mutate finalized matrix"));
        }
        let (_, _, expected) = checked_row_range(self.rows, self.columns, row_start, row_count)?;
        if values.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        self.file.seek(SeekFrom::Start(payload_offset::<T>(
            row_start,
            self.columns,
        )?))?;
        let mut bytes = vec![
            0u8;
            expected
                .checked_mul(T::WIDTH)
                .ok_or(StreamError::OutOfBounds)?
        ];
        for (value, output) in values.iter().zip(bytes.chunks_exact_mut(T::WIDTH)) {
            value.encode(output);
        }
        self.file.write_all(&bytes)?;
        Ok(())
    }

    fn write_tile(
        &mut self,
        row_start: u64,
        row_count: usize,
        column_start: usize,
        column_count: usize,
        values: &[T],
    ) -> Result<()> {
        if self.digest.is_some() {
            return Err(StreamError::Corrupt("cannot mutate finalized matrix"));
        }
        let expected = checked_tile_len(
            self.rows,
            self.columns,
            row_start,
            row_count,
            column_start,
            column_count,
        )?;
        if values.len() != expected {
            return Err(StreamError::OutOfBounds);
        }
        let byte_len = column_count
            .checked_mul(T::WIDTH)
            .ok_or(StreamError::OutOfBounds)?;
        let mut bytes = vec![0u8; byte_len];
        for row in 0..row_count {
            let source = row * column_count;
            for (value, output) in values[source..source + column_count]
                .iter()
                .zip(bytes.chunks_exact_mut(T::WIDTH))
            {
                value.encode(output);
            }
            let absolute_row = row_start
                .checked_add(row as u64)
                .ok_or(StreamError::OutOfBounds)?;
            self.file.seek(SeekFrom::Start(payload_tile_offset::<T>(
                absolute_row,
                self.columns,
                column_start,
            )?))?;
            self.file.write_all(&bytes)?;
        }
        Ok(())
    }

    fn finalize(&mut self) -> Result<ArtifactDigest> {
        if let Some(digest) = self.digest {
            if let Some(identity) = &self.stable_identity {
                ensure_held_file_stable(&self.file, identity)?;
            }
            return Ok(digest);
        }
        self.file.sync_all()?;
        let digest = digest_payload::<T>(&mut self.file, self.rows, self.columns)?;
        self.digest = Some(digest);
        #[cfg(unix)]
        {
            self.stable_identity = Some(stable_file_identity(&self.file)?);
        }
        Ok(digest)
    }

    fn digest(&self) -> Option<ArtifactDigest> {
        self.digest
    }

    fn remove(self) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        drop(self.file);
        #[cfg(target_arch = "wasm32")]
        let _file = self.file;
        fs::remove_file(self.path)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum PipelinePhaseV1 {
    Trace,
    TraceLde,
    TraceCommitment,
    Quotient,
    QuotientLde,
    QuotientCommitment,
    FriLayer { layer: u32 },
    Openings,
    ProofAssembly,
}

impl std::fmt::Display for PipelinePhaseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trace => formatter.write_str("trace"),
            Self::TraceLde => formatter.write_str("trace_lde"),
            Self::TraceCommitment => formatter.write_str("trace_commitment"),
            Self::Quotient => formatter.write_str("quotient"),
            Self::QuotientLde => formatter.write_str("quotient_lde"),
            Self::QuotientCommitment => formatter.write_str("quotient_commitment"),
            Self::FriLayer { layer } => write!(formatter, "fri_layer_{layer}"),
            Self::Openings => formatter.write_str("openings"),
            Self::ProofAssembly => formatter.write_str("proof_assembly"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PipelineArtifactKindV1 {
    Trace,
    TraceLde,
    TraceMmcsLevel,
    Quotient,
    QuotientLde,
    QuotientMmcsLevel,
    FriLayer,
    FriMmcsLevel,
    Openings,
    ProofBundle,
}

impl PipelineArtifactKindV1 {
    fn requires_ordinal(self) -> bool {
        matches!(
            self,
            Self::TraceMmcsLevel
                | Self::QuotientLde
                | Self::QuotientMmcsLevel
                | Self::FriLayer
                | Self::FriMmcsLevel
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointArtifactV2 {
    pub kind: PipelineArtifactKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    pub relative_path: PathBuf,
    pub digest: ArtifactDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifestV2 {
    pub schema_version: u32,
    pub backend_hash: [u8; 32],
    pub profile_hash: [u8; 32],
    pub release_hash: [u8; 32],
    pub dependency_lock_hash: [u8; 32],
    pub workload_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub resource_policy_hash: [u8; 32],
    pub completed_phase: PipelinePhaseV1,
    pub challenger_state: Vec<u8>,
    /// Backend-defined, schema-versioned public continuation metadata. This
    /// must never contain witness values; large state belongs in checksummed
    /// artifacts instead of the manifest.
    #[serde(default)]
    pub resume_payload: Vec<u8>,
    pub artifacts: Vec<CheckpointArtifactV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointIdentityV2 {
    pub backend_hash: [u8; 32],
    pub profile_hash: [u8; 32],
    pub release_hash: [u8; 32],
    pub dependency_lock_hash: [u8; 32],
    pub workload_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub resource_policy_hash: [u8; 32],
}

impl CheckpointManifestV2 {
    pub fn validate_structure(&self) -> Result<()> {
        if self.schema_version != 2
            || self.challenger_state.len() > MAX_CHALLENGER_STATE_BYTES
            || self.resume_payload.len() > MAX_RESUME_PAYLOAD_BYTES
            || self.artifacts.len() > MAX_CHECKPOINT_ARTIFACTS
        {
            return Err(StreamError::CheckpointMismatch);
        }
        let mut identities = HashSet::new();
        let mut paths = HashSet::new();
        for artifact in &self.artifacts {
            if artifact.kind.requires_ordinal() != artifact.ordinal.is_some()
                || artifact.digest.rows == 0
                || artifact.digest.columns == 0
                || artifact.digest.element_width == 0
            {
                return Err(StreamError::CheckpointMismatch);
            }
            validate_relative_path(&artifact.relative_path)?;
            if !identities.insert((artifact.kind, artifact.ordinal))
                || !paths.insert(artifact.relative_path.as_path())
            {
                return Err(StreamError::CheckpointMismatch);
            }
        }
        Ok(())
    }

    pub fn validate_identity(&self, expected: CheckpointIdentityV2) -> Result<()> {
        self.validate_structure()?;
        if self.backend_hash != expected.backend_hash
            || self.profile_hash != expected.profile_hash
            || self.release_hash != expected.release_hash
            || self.dependency_lock_hash != expected.dependency_lock_hash
            || self.workload_hash != expected.workload_hash
            || self.input_hash != expected.input_hash
            || self.resource_policy_hash != expected.resource_policy_hash
        {
            return Err(StreamError::CheckpointMismatch);
        }
        Ok(())
    }

    pub fn write_atomic(&self, path: impl AsRef<Path>) -> Result<()> {
        self.validate_structure()?;
        let path = path.as_ref();
        let parent = path.parent().ok_or(StreamError::UnsafePath)?;
        ensure_private_dir(parent)?;
        validate_file_name(
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or(StreamError::UnsafePath)?,
        )?;
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(StreamError::ResourceLimit {
                resource: "checkpoint manifest",
                required: bytes.len() as u64,
                cap: MAX_MANIFEST_BYTES,
            });
        }
        let temp_name = format!(
            ".checkpoint-{}-{}.tmp",
            std::process::id(),
            monotonic_suffix()
        );
        let temp = parent.join(temp_name);
        let mut file = create_private_file(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        sync_directory(parent)?;
        Ok(())
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let (mut file, opened_identity) = secure_open_existing_file(path, false)?;
        if opened_identity.len > MAX_MANIFEST_BYTES {
            return Err(StreamError::ResourceLimit {
                resource: "checkpoint manifest",
                required: opened_identity.len,
                cap: MAX_MANIFEST_BYTES,
            });
        }
        let mut bytes = Vec::with_capacity(opened_identity.len as usize);
        file.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != opened_identity.len {
            return Err(StreamError::Corrupt(
                "checkpoint length changed while reading",
            ));
        }
        ensure_held_file_stable(&file, &opened_identity)?;
        let manifest: Self = serde_json::from_slice(&bytes)?;
        manifest.validate_structure()?;
        Ok(manifest)
    }

    pub fn validate_artifacts(&self, root: impl AsRef<Path>) -> Result<()> {
        self.validate_structure()?;
        let root = root.as_ref();
        reject_symlink(root)?;
        for artifact in &self.artifacts {
            validate_relative_path(&artifact.relative_path)?;
            let path = root.join(&artifact.relative_path);
            validate_scratch_artifact(&path, artifact.digest)?;
        }
        Ok(())
    }
}

/// Validate a matrix artifact without assuming its field element width. Typed
/// reopening still performs canonical element decoding; checkpoint validation
/// only needs the immutable header and payload digest.
pub fn validate_scratch_artifact(path: impl AsRef<Path>, expected: ArtifactDigest) -> Result<()> {
    let path = path.as_ref();
    let (mut file, opened_identity) = secure_open_existing_file(path, false)?;
    if read_header(&mut file)? != (expected.rows, expected.columns, expected.element_width) {
        return Err(StreamError::Corrupt("artifact header mismatch"));
    }
    let actual = digest_raw_payload(&mut file, expected)?;
    if actual != expected {
        return Err(StreamError::Corrupt("artifact checksum mismatch"));
    }
    ensure_held_file_stable(&file, &opened_identity)?;
    Ok(())
}

pub fn cleanup_job_directory(
    path: impl AsRef<Path>,
    policy: CheckpointPolicy,
    succeeded: bool,
    resumable_failure: bool,
) -> Result<bool> {
    let retain = !succeeded && resumable_failure && policy == CheckpointPolicy::RetainOnFailure;
    if retain {
        return Ok(false);
    }
    let path = path.as_ref();
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    Ok(true)
}

fn checked_elements(rows: u64, columns: usize) -> Result<usize> {
    let rows = usize::try_from(rows).map_err(|_| StreamError::OutOfBounds)?;
    rows.checked_mul(columns).ok_or(StreamError::OutOfBounds)
}

fn checked_payload_bytes<T: CanonicalElement>(rows: u64, columns: usize) -> Result<u64> {
    rows.checked_mul(columns as u64)
        .and_then(|elements| elements.checked_mul(T::WIDTH as u64))
        .ok_or(StreamError::OutOfBounds)
}

fn checked_row_range(
    rows: u64,
    columns: usize,
    row_start: u64,
    row_count: usize,
) -> Result<(usize, usize, usize)> {
    let end_row = row_start
        .checked_add(row_count as u64)
        .ok_or(StreamError::OutOfBounds)?;
    if end_row > rows {
        return Err(StreamError::OutOfBounds);
    }
    let start = checked_elements(row_start, columns)?;
    let expected = row_count
        .checked_mul(columns)
        .ok_or(StreamError::OutOfBounds)?;
    let end = start
        .checked_add(expected)
        .ok_or(StreamError::OutOfBounds)?;
    Ok((start, end, expected))
}

fn checked_tile_len(
    rows: u64,
    columns: usize,
    row_start: u64,
    row_count: usize,
    column_start: usize,
    column_count: usize,
) -> Result<usize> {
    let end_row = row_start
        .checked_add(row_count as u64)
        .ok_or(StreamError::OutOfBounds)?;
    let end_column = column_start
        .checked_add(column_count)
        .ok_or(StreamError::OutOfBounds)?;
    if row_count == 0 || column_count == 0 || end_row > rows || end_column > columns {
        return Err(StreamError::OutOfBounds);
    }
    row_count
        .checked_mul(column_count)
        .ok_or(StreamError::OutOfBounds)
}

fn payload_offset<T: CanonicalElement>(row_start: u64, columns: usize) -> Result<u64> {
    let element = row_start
        .checked_mul(columns as u64)
        .and_then(|value| value.checked_mul(T::WIDTH as u64))
        .ok_or(StreamError::OutOfBounds)?;
    STORE_HEADER_LEN
        .checked_add(element)
        .ok_or(StreamError::OutOfBounds)
}

fn payload_tile_offset<T: CanonicalElement>(
    row: u64,
    columns: usize,
    column_start: usize,
) -> Result<u64> {
    let column_start = u64::try_from(column_start).map_err(|_| StreamError::OutOfBounds)?;
    let element = row
        .checked_mul(columns as u64)
        .and_then(|value| value.checked_add(column_start))
        .and_then(|value| value.checked_mul(T::WIDTH as u64))
        .ok_or(StreamError::OutOfBounds)?;
    STORE_HEADER_LEN
        .checked_add(element)
        .ok_or(StreamError::OutOfBounds)
}

fn digest_payload<T: CanonicalElement>(
    file: &mut File,
    rows: u64,
    columns: usize,
) -> Result<ArtifactDigest> {
    let expected = ArtifactDigest {
        rows,
        columns,
        element_width: T::WIDTH,
        blake3: [0; 32],
    };
    digest_raw_payload(file, expected)
}

fn digest_raw_payload(file: &mut File, shape: ArtifactDigest) -> Result<ArtifactDigest> {
    file.seek(SeekFrom::Start(STORE_HEADER_LEN))?;
    let mut remaining = shape
        .rows
        .checked_mul(shape.columns as u64)
        .and_then(|elements| elements.checked_mul(shape.element_width as u64))
        .ok_or(StreamError::OutOfBounds)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; HASH_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        file.read_exact(&mut buffer[..take])?;
        hasher.update(&buffer[..take]);
        remaining -= take as u64;
    }
    Ok(ArtifactDigest {
        rows: shape.rows,
        columns: shape.columns,
        element_width: shape.element_width,
        blake3: *hasher.finalize().as_bytes(),
    })
}

fn read_header(file: &mut File) -> Result<(u64, usize, usize)> {
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != STORE_MAGIC {
        return Err(StreamError::Corrupt("wrong artifact magic"));
    }
    let mut bytes = [0u8; 8];
    file.read_exact(&mut bytes)?;
    let rows = u64::from_le_bytes(bytes);
    file.read_exact(&mut bytes)?;
    let columns = usize::try_from(u64::from_le_bytes(bytes))
        .map_err(|_| StreamError::Corrupt("column count overflows host"))?;
    file.read_exact(&mut bytes)?;
    let width = usize::try_from(u64::from_le_bytes(bytes))
        .map_err(|_| StreamError::Corrupt("element width overflows host"))?;
    Ok((rows, columns, width))
}

fn validate_file_name(file_name: &str) -> Result<()> {
    if file_name.is_empty()
        || file_name == "."
        || file_name == ".."
        || file_name.contains('/')
        || file_name.contains('\\')
    {
        return Err(StreamError::UnsafePath);
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(StreamError::UnsafePath);
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    let created = !path.exists();
    if created {
        fs::create_dir_all(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StreamError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    Ok(options.open(path)?)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<File> {
    use rustix::fs::{openat, Mode, OFlags};

    let (directory, file_name) = open_parent_directory(path)?;
    let descriptor = openat(
        &directory,
        file_name,
        OFlags::CREATE
            | OFlags::EXCL
            | OFlags::RDWR
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| StreamError::Io(error.into()))?;
    let file = File::from(descriptor);
    stable_file_identity(&file)?;
    Ok(file)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StableFileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    owner: u32,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

/// Open an existing scratch file through descriptor-relative, no-follow
/// traversal and prove that two independent traversals reached the same inode.
/// The returned descriptor, rather than the pathname, is used for all reads.
#[cfg(unix)]
fn secure_open_existing_file(path: &Path, writable: bool) -> Result<(File, StableFileIdentity)> {
    secure_open_existing_file_with(path, writable, || {})
}

#[cfg(unix)]
fn secure_open_existing_file_with(
    path: &Path,
    writable: bool,
    between_opens: impl FnOnce(),
) -> Result<(File, StableFileIdentity)> {
    let first = open_existing_file_once(path, writable)?;
    let first_identity = stable_file_identity(&first)?;
    between_opens();
    let second = open_existing_file_once(path, writable)?;
    let second_identity = stable_file_identity(&second)?;
    if first_identity != second_identity {
        return Err(StreamError::UnsafePath);
    }
    Ok((first, first_identity))
}

#[cfg(unix)]
fn open_existing_file_once(path: &Path, writable: bool) -> Result<File> {
    use rustix::fs::{openat, Mode, OFlags};

    let (directory, file_name) = open_parent_directory(path)?;
    let access = if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    };
    let descriptor = openat(
        &directory,
        file_name,
        access | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| StreamError::UnsafePath)?;
    let file = File::from(descriptor);
    stable_file_identity(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn open_parent_directory(path: &Path) -> Result<(rustix::fd::OwnedFd, std::ffi::OsString)> {
    use rustix::fs::{openat, Mode, OFlags, CWD};
    use std::ffi::OsString;

    let normalized = platform_no_follow_path(path);
    let path = normalized.as_path();
    if path.as_os_str().is_empty() {
        return Err(StreamError::UnsafePath);
    }
    let mut names = Vec::<OsString>::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => return Err(StreamError::UnsafePath),
        }
    }
    let file_name = names.pop().ok_or(StreamError::UnsafePath)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = openat(
        CWD,
        if path.is_absolute() { "/" } else { "." },
        directory_flags,
        Mode::empty(),
    )
    .map_err(|_| StreamError::UnsafePath)?;
    for name in names {
        directory = openat(&directory, name, directory_flags, Mode::empty())
            .map_err(|_| StreamError::UnsafePath)?;
    }
    Ok((directory, file_name))
}

#[cfg(unix)]
fn platform_no_follow_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    if path.is_absolute() {
        let first = path.components().find_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        });
        // macOS defines these root-level compatibility links as part of the
        // sealed system layout. Resolve only those fixed prefixes before the
        // component-by-component O_NOFOLLOW traversal; arbitrary symlinks are
        // never canonicalized or followed.
        if matches!(first, Some("var" | "tmp" | "etc")) {
            if let Ok(relative) = path.strip_prefix("/") {
                return Path::new("/private").join(relative);
            }
        }
    }
    path.to_path_buf()
}

#[cfg(unix)]
fn stable_file_identity(file: &File) -> Result<StableFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    let identity = StableFileIdentity {
        len: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        owner: metadata.uid(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    };
    if !metadata.is_file()
        || identity.links != 1
        || identity.owner != rustix::process::geteuid().as_raw()
        || identity.mode & 0o077 != 0
    {
        return Err(StreamError::UnsafePath);
    }
    Ok(identity)
}

#[cfg(unix)]
fn ensure_held_file_stable(file: &File, expected: &StableFileIdentity) -> Result<()> {
    if &stable_file_identity(file)? != expected {
        return Err(StreamError::Corrupt("file changed while held open"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_open_existing_file(_path: &Path, _writable: bool) -> Result<(File, StableFileIdentity)> {
    // Production scratch/checkpoint recovery requires openat/O_NOFOLLOW-style
    // descriptor semantics. Unsupported targets fail closed rather than
    // silently falling back to a pathname check followed by a racy open.
    Err(StreamError::UnsafePath)
}

#[cfg(not(unix))]
fn ensure_held_file_stable(_file: &File, _expected: &StableFileIdentity) -> Result<()> {
    Err(StreamError::UnsafePath)
}

fn reject_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(StreamError::UnsafePath);
    }
    Ok(())
}

fn sync_directory(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(_path)?.sync_all()?;
    Ok(())
}

fn monotonic_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn policy(root: &Path, mode: ResourceMode) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode,
            max_resident_bytes: 100 * 1024 * 1024,
            max_scratch_bytes: 1024 * 1024 * 1024,
            scratch_dir: root.to_path_buf(),
            max_threads: 2,
            checkpoint_policy: CheckpointPolicy::RetainOnFailure,
        }
    }

    fn estimate(peak: u64, scratch: u64) -> ResourceEstimate {
        ResourceEstimate {
            peak_resident_bytes: peak,
            scratch_high_water_bytes: scratch,
            total_read_bytes: 0,
            total_write_bytes: 0,
            phases: vec![],
        }
    }

    #[test]
    fn auto_uses_strict_seventy_percent_threshold() {
        let dir = tempdir().unwrap();
        let policy = policy(dir.path(), ResourceMode::Auto);
        assert_eq!(
            policy.select_mode(&estimate(70 * 1024 * 1024, 1)).unwrap(),
            ExecutionMode::Memory
        );
        assert_eq!(
            policy
                .select_mode(&estimate(70 * 1024 * 1024 + 1, 1))
                .unwrap(),
            ExecutionMode::Scratch
        );
    }

    #[test]
    fn scratch_matrix_round_trips_and_detects_corruption() {
        let dir = tempdir().unwrap();
        let mut store = ScratchMatrixStore::<u64>::create(dir.path(), "trace.bin", 4, 2).unwrap();
        store.write_rows(0, 2, &[1, 2, 3, 4]).unwrap();
        store.write_rows(2, 2, &[5, 6, 7, 8]).unwrap();
        let mut output = [0; 4];
        store.read_rows(1, 2, &mut output).unwrap();
        assert_eq!(output, [3, 4, 5, 6]);
        let digest = store.finalize().unwrap();
        let path = store.path().to_path_buf();
        drop(store);
        ScratchMatrixStore::<u64>::reopen(&path, digest).unwrap();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[9]).unwrap();
        assert!(matches!(
            ScratchMatrixStore::<u64>::reopen(&path, digest),
            Err(StreamError::Corrupt("artifact checksum mismatch"))
        ));

        let mut truncated =
            ScratchMatrixStore::<u64>::create(dir.path(), "truncated.bin", 2, 2).unwrap();
        truncated.write_rows(0, 2, &[1, 2, 3, 4]).unwrap();
        let truncated_digest = truncated.finalize().unwrap();
        let truncated_path = truncated.path().to_path_buf();
        drop(truncated);
        let file = OpenOptions::new()
            .write(true)
            .open(&truncated_path)
            .unwrap();
        file.set_len(file.metadata().unwrap().len() - 1).unwrap();
        assert!(matches!(
            ScratchMatrixStore::<u64>::reopen(&truncated_path, truncated_digest),
            Err(StreamError::Corrupt("artifact length mismatch"))
        ));
    }

    #[test]
    fn memory_and_scratch_tiles_are_caller_buffered_and_bounded() {
        let dir = tempdir().unwrap();
        let values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let mut memory = MemoryMatrix::<u64>::preallocated(3, 4).unwrap();
        memory.write_rows(0, 3, &values).unwrap();
        memory.write_tile(1, 2, 1, 2, &[50, 60, 90, 100]).unwrap();
        let mut memory_tile = [0; 4];
        memory.read_tile(1, 2, 1, 2, &mut memory_tile).unwrap();
        assert_eq!(memory_tile, [50, 60, 90, 100]);

        let mut scratch = ScratchMatrixStore::<u64>::create(dir.path(), "tile.bin", 3, 4).unwrap();
        scratch.write_rows(0, 3, &values).unwrap();
        scratch.write_tile(1, 2, 1, 2, &[50, 60, 90, 100]).unwrap();
        let mut scratch_tile = [0; 4];
        scratch.read_tile(1, 2, 1, 2, &mut scratch_tile).unwrap();
        assert_eq!(scratch_tile, memory_tile);

        let mut full = [0; 12];
        scratch.read_rows(0, 3, &mut full).unwrap();
        assert_eq!(full, [1, 2, 3, 4, 5, 50, 60, 8, 9, 90, 100, 12]);
        assert!(matches!(
            scratch.read_tile(2, 2, 0, 1, &mut [0; 2]),
            Err(StreamError::OutOfBounds)
        ));
        assert!(matches!(
            scratch.write_tile(0, 1, 4, 1, &[1]),
            Err(StreamError::OutOfBounds)
        ));
    }

    #[test]
    fn finalized_matrices_are_immutable() {
        let dir = tempdir().unwrap();
        let mut store = ScratchMatrixStore::<u64>::create(dir.path(), "trace.bin", 1, 1).unwrap();
        store.write_rows(0, 1, &[7]).unwrap();
        store.finalize().unwrap();
        assert!(matches!(
            store.write_rows(0, 1, &[8]),
            Err(StreamError::Corrupt("cannot mutate finalized matrix"))
        ));
    }

    #[test]
    fn checkpoint_binds_all_resume_identity_and_artifacts() {
        let dir = tempdir().unwrap();
        let mut store = ScratchMatrixStore::<u64>::create(dir.path(), "trace.bin", 1, 2).unwrap();
        store.write_rows(0, 1, &[3, 5]).unwrap();
        let digest = store.finalize().unwrap();
        drop(store);
        let identity = CheckpointIdentityV2 {
            backend_hash: [1; 32],
            profile_hash: [2; 32],
            release_hash: [3; 32],
            dependency_lock_hash: [4; 32],
            workload_hash: [5; 32],
            input_hash: [6; 32],
            resource_policy_hash: [7; 32],
        };
        let manifest = CheckpointManifestV2 {
            schema_version: 2,
            backend_hash: identity.backend_hash,
            profile_hash: identity.profile_hash,
            release_hash: identity.release_hash,
            dependency_lock_hash: identity.dependency_lock_hash,
            workload_hash: identity.workload_hash,
            input_hash: identity.input_hash,
            resource_policy_hash: identity.resource_policy_hash,
            completed_phase: PipelinePhaseV1::Trace,
            challenger_state: vec![8, 9],
            resume_payload: br#"{"workload":"test"}"#.to_vec(),
            artifacts: vec![CheckpointArtifactV2 {
                kind: PipelineArtifactKindV1::Trace,
                ordinal: None,
                relative_path: PathBuf::from("trace.bin"),
                digest,
            }],
        };
        let manifest_path = dir.path().join("checkpoint.json");
        manifest.write_atomic(&manifest_path).unwrap();
        let loaded = CheckpointManifestV2::read(&manifest_path).unwrap();
        loaded.validate_identity(identity).unwrap();
        loaded.validate_artifacts(dir.path()).unwrap();
        let mut missing_ordinal = loaded.clone();
        missing_ordinal.artifacts[0].kind = PipelineArtifactKindV1::FriLayer;
        assert!(matches!(
            missing_ordinal.validate_structure(),
            Err(StreamError::CheckpointMismatch)
        ));
        let mut duplicate = loaded.clone();
        duplicate.artifacts.push(duplicate.artifacts[0].clone());
        assert!(matches!(
            duplicate.validate_structure(),
            Err(StreamError::CheckpointMismatch)
        ));
        let mutations: [fn(&mut CheckpointIdentityV2); 7] = [
            |value| value.backend_hash = [0; 32],
            |value| value.profile_hash = [0; 32],
            |value| value.release_hash = [0; 32],
            |value| value.dependency_lock_hash = [0; 32],
            |value| value.workload_hash = [0; 32],
            |value| value.input_hash = [0; 32],
            |value| value.resource_policy_hash = [0; 32],
        ];
        for mutate in mutations {
            let mut wrong = identity;
            mutate(&mut wrong);
            assert!(matches!(
                loaded.validate_identity(wrong),
                Err(StreamError::CheckpointMismatch)
            ));
        }
    }

    #[test]
    fn path_traversal_and_unnoted_retention_are_rejected() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            ScratchMatrixStore::<u64>::create(dir.path(), "empty.bin", 0, 1),
            Err(StreamError::OutOfBounds)
        ));
        assert!(matches!(
            MemoryMatrix::<u64>::preallocated(1, 0),
            Err(StreamError::OutOfBounds)
        ));
        assert!(matches!(
            ScratchMatrixStore::<u64>::create(dir.path(), "../escape", 1, 1),
            Err(StreamError::UnsafePath)
        ));
        let traversal_policy = ResourcePolicyV1 {
            scratch_dir: dir.path().join("job").join("..").join("escape"),
            ..policy(dir.path(), ResourceMode::Scratch)
        };
        assert!(matches!(
            traversal_policy.validate(),
            Err(StreamError::UnsafePath)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let shared = dir.path().join("shared");
            fs::create_dir(&shared).unwrap();
            fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
            let shared_policy = ResourcePolicyV1 {
                scratch_dir: shared.clone(),
                ..policy(dir.path(), ResourceMode::Scratch)
            };
            shared_policy.preflight(estimate(1, 1)).unwrap();
            assert_eq!(
                fs::metadata(&shared).unwrap().permissions().mode() & 0o777,
                0o755,
                "preflight must not silently chmod the configured base directory"
            );
        }
        let job = dir.path().join("job");
        fs::create_dir(&job).unwrap();
        assert!(
            cleanup_job_directory(&job, CheckpointPolicy::RetainOnFailure, false, true)
                .is_ok_and(|removed| !removed)
        );
        assert!(job.exists());
        cleanup_job_directory(&job, CheckpointPolicy::RetainOnFailure, false, false).unwrap();
        assert!(!job.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_roots_and_artifacts_fail_closed() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        let linked_root = dir.path().join("linked-root");
        symlink(&target, &linked_root).unwrap();
        let linked_policy = ResourcePolicyV1 {
            scratch_dir: linked_root,
            ..policy(dir.path(), ResourceMode::Scratch)
        };
        assert!(matches!(
            linked_policy.preflight(estimate(1, 1)),
            Err(StreamError::UnsafePath)
        ));

        let mut store = ScratchMatrixStore::<u64>::create(&target, "real.bin", 1, 1).unwrap();
        store.write_rows(0, 1, &[9]).unwrap();
        let digest = store.finalize().unwrap();
        let real = store.path().to_path_buf();
        drop(store);
        let linked_artifact = target.join("linked.bin");
        symlink(&real, &linked_artifact).unwrap();
        assert!(matches!(
            ScratchMatrixStore::<u64>::reopen(&linked_artifact, digest),
            Err(StreamError::UnsafePath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn final_file_hardlinks_are_rejected_by_all_artifact_readers() {
        let dir = tempdir().unwrap();
        let mut store =
            ScratchMatrixStore::<u64>::create(dir.path(), "original.bin", 1, 1).unwrap();
        store.write_rows(0, 1, &[17]).unwrap();
        let digest = store.finalize().unwrap();
        let original = store.path().to_path_buf();
        let alias = dir.path().join("alias.bin");
        fs::hard_link(&original, &alias).unwrap();

        assert!(matches!(
            store.read_rows(0, 1, &mut [0]),
            Err(StreamError::UnsafePath)
        ));
        drop(store);
        assert!(matches!(
            ScratchMatrixStore::<u64>::reopen(&original, digest),
            Err(StreamError::UnsafePath)
        ));
        assert!(matches!(
            validate_scratch_artifact(&original, digest),
            Err(StreamError::UnsafePath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn replacement_between_secure_opens_is_rejected() {
        let dir = tempdir().unwrap();
        let mut victim = ScratchMatrixStore::<u64>::create(dir.path(), "victim.bin", 1, 1).unwrap();
        victim.write_rows(0, 1, &[23]).unwrap();
        victim.finalize().unwrap();
        let victim_path = victim.path().to_path_buf();
        drop(victim);

        let mut replacement =
            ScratchMatrixStore::<u64>::create(dir.path(), "replacement.bin", 1, 1).unwrap();
        replacement.write_rows(0, 1, &[29]).unwrap();
        replacement.finalize().unwrap();
        let replacement_path = replacement.path().to_path_buf();
        drop(replacement);

        let saved_path = dir.path().join("saved-victim.bin");
        let result = secure_open_existing_file_with(&victim_path, false, || {
            fs::rename(&victim_path, &saved_path).unwrap();
            fs::rename(&replacement_path, &victim_path).unwrap();
        });
        assert!(matches!(result, Err(StreamError::UnsafePath)));
    }

    #[cfg(unix)]
    #[test]
    fn held_descriptor_stays_on_verified_inode_after_path_replacement() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().unwrap();
        let mut original = ScratchMatrixStore::<u64>::create(dir.path(), "held.bin", 1, 1).unwrap();
        original.write_rows(0, 1, &[31]).unwrap();
        let original_digest = original.finalize().unwrap();
        let original_path = original.path().to_path_buf();
        drop(original);

        let mut replacement =
            ScratchMatrixStore::<u64>::create(dir.path(), "new.bin", 1, 1).unwrap();
        replacement.write_rows(0, 1, &[37]).unwrap();
        replacement.finalize().unwrap();
        let replacement_path = replacement.path().to_path_buf();
        drop(replacement);

        let (mut held, identity) = secure_open_existing_file(&original_path, false).unwrap();
        let held_inode = held.metadata().unwrap().ino();
        let saved_path = dir.path().join("saved-held.bin");
        fs::rename(&original_path, &saved_path).unwrap();
        fs::rename(&replacement_path, &original_path).unwrap();

        assert_eq!(held.metadata().unwrap().ino(), held_inode);
        assert_ne!(fs::metadata(&original_path).unwrap().ino(), held_inode);
        assert_eq!(read_header(&mut held).unwrap(), (1, 1, u64::WIDTH));
        assert_eq!(
            digest_payload::<u64>(&mut held, 1, 1).unwrap(),
            original_digest
        );
        assert!(matches!(
            ensure_held_file_stable(&held, &identity),
            Err(StreamError::Corrupt("file changed while held open"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_any_parent_component_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real_parent = dir.path().join("real-parent");
        let nested = real_parent.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let mut store = ScratchMatrixStore::<u64>::create(&nested, "trace.bin", 1, 1).unwrap();
        store.write_rows(0, 1, &[41]).unwrap();
        let digest = store.finalize().unwrap();
        drop(store);

        let linked_parent = dir.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let through_link = linked_parent.join("nested").join("trace.bin");
        assert!(matches!(
            ScratchMatrixStore::<u64>::reopen(&through_link, digest),
            Err(StreamError::UnsafePath)
        ));
        assert!(matches!(
            validate_scratch_artifact(&through_link, digest),
            Err(StreamError::UnsafePath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_and_artifact_readers_reject_unsafe_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let mut store = ScratchMatrixStore::<u64>::create(dir.path(), "trace.bin", 1, 1).unwrap();
        store.write_rows(0, 1, &[43]).unwrap();
        let digest = store.finalize().unwrap();
        let artifact_path = store.path().to_path_buf();
        drop(store);

        let manifest = CheckpointManifestV2 {
            schema_version: 2,
            backend_hash: [1; 32],
            profile_hash: [2; 32],
            release_hash: [3; 32],
            dependency_lock_hash: [4; 32],
            workload_hash: [5; 32],
            input_hash: [6; 32],
            resource_policy_hash: [7; 32],
            completed_phase: PipelinePhaseV1::Trace,
            challenger_state: vec![8, 9],
            resume_payload: br#"{"workload":"mode-test"}"#.to_vec(),
            artifacts: vec![CheckpointArtifactV2 {
                kind: PipelineArtifactKindV1::Trace,
                ordinal: None,
                relative_path: PathBuf::from("trace.bin"),
                digest,
            }],
        };
        let manifest_path = dir.path().join("checkpoint.json");
        manifest.write_atomic(&manifest_path).unwrap();

        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            validate_scratch_artifact(&artifact_path, digest),
            Err(StreamError::UnsafePath)
        ));
        assert!(matches!(
            manifest.validate_artifacts(dir.path()),
            Err(StreamError::UnsafePath)
        ));
        fs::set_permissions(&artifact_path, fs::Permissions::from_mode(0o600)).unwrap();

        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            CheckpointManifestV2::read(&manifest_path),
            Err(StreamError::UnsafePath)
        ));
    }
}
