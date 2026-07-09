//! Resource-bounded storage and deterministic recovery primitives.
//!
//! This crate deliberately has no proof-system dependency. It owns policy,
//! canonical matrix artifacts, integrity checks, and checkpoint identity. A
//! backend remains responsible for transcript and proof semantics.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};

const STORE_MAGIC: &[u8; 8] = b"TZMATV1\0";
const STORE_HEADER_LEN: u64 = 8 + 8 + 8 + 8;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMode {
    Auto,
    Memory,
    Scratch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointPolicy {
    Disabled,
    DeleteOnSuccess,
    RetainOnFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyV1 {
    pub mode: ResourceMode,
    pub max_resident_bytes: u64,
    pub max_scratch_bytes: u64,
    pub scratch_dir: PathBuf,
    pub max_threads: usize,
    pub checkpoint_policy: CheckpointPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Memory,
    Scratch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseEstimate {
    pub phase: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceEstimate {
    pub peak_resident_bytes: u64,
    pub scratch_high_water_bytes: u64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub phases: Vec<PhaseEstimate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
        ensure_private_dir(&self.scratch_dir)?;
        reject_symlink(&self.scratch_dir)?;
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
        if selected_mode == ExecutionMode::Scratch && estimate.scratch_high_water_bytes > available
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

    fn is_empty(&self) -> bool {
        self.rows() == 0 || self.columns() == 0
    }
}

pub trait MatrixStore<T>: BlockMatrix<T> {
    fn write_rows(&mut self, row_start: u64, row_count: usize, values: &[T]) -> Result<()>;
    fn finalize(&mut self) -> Result<ArtifactDigest>;
    fn digest(&self) -> Option<ArtifactDigest>;
    fn remove(self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
        ensure_private_dir(root)?;
        reject_symlink(root)?;
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
            _marker: PhantomData,
        })
    }

    pub fn reopen(path: impl AsRef<Path>, expected: ArtifactDigest) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        reject_symlink(&path)?;
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        let actual_header = read_header(&mut file)?;
        if actual_header != (expected.rows, expected.columns, expected.element_width) {
            return Err(StreamError::Corrupt("artifact header mismatch"));
        }
        let actual = digest_payload::<T>(&mut file, expected.rows, expected.columns)?;
        if actual != expected {
            return Err(StreamError::Corrupt("artifact checksum mismatch"));
        }
        Ok(Self {
            path,
            file,
            rows: expected.rows,
            columns: expected.columns,
            digest: Some(expected),
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

    fn finalize(&mut self) -> Result<ArtifactDigest> {
        if let Some(digest) = self.digest {
            return Ok(digest);
        }
        self.file.sync_all()?;
        let digest = digest_payload::<T>(&mut self.file, self.rows, self.columns)?;
        self.digest = Some(digest);
        Ok(digest)
    }

    fn digest(&self) -> Option<ArtifactDigest> {
        self.digest
    }

    fn remove(self) -> Result<()> {
        drop(self.file);
        fs::remove_file(self.path)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointArtifactV2 {
    pub name: String,
    pub relative_path: PathBuf,
    pub digest: ArtifactDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    pub completed_phase: String,
    pub challenger_state: Vec<u8>,
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
    pub fn validate_identity(&self, expected: CheckpointIdentityV2) -> Result<()> {
        if self.schema_version != 2
            || self.backend_hash != expected.backend_hash
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
        if self.schema_version != 2 {
            return Err(StreamError::CheckpointMismatch);
        }
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
        reject_symlink(path)?;
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_MANIFEST_BYTES {
            return Err(StreamError::ResourceLimit {
                resource: "checkpoint manifest",
                required: metadata.len(),
                cap: MAX_MANIFEST_BYTES,
            });
        }
        let manifest: Self = serde_json::from_slice(&fs::read(path)?)?;
        if manifest.schema_version != 2 {
            return Err(StreamError::CheckpointMismatch);
        }
        Ok(manifest)
    }

    pub fn validate_artifacts(&self, root: impl AsRef<Path>) -> Result<()> {
        let root = root.as_ref();
        reject_symlink(root)?;
        for artifact in &self.artifacts {
            validate_relative_path(&artifact.relative_path)?;
            let path = root.join(&artifact.relative_path);
            let store = ScratchMatrixStore::<u64>::reopen(&path, artifact.digest)?;
            drop(store);
        }
        Ok(())
    }
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

fn payload_offset<T: CanonicalElement>(row_start: u64, columns: usize) -> Result<u64> {
    let element = row_start
        .checked_mul(columns as u64)
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
    file.seek(SeekFrom::Start(STORE_HEADER_LEN))?;
    let mut remaining = checked_payload_bytes::<T>(rows, columns)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; HASH_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        file.read_exact(&mut buffer[..take])?;
        hasher.update(&buffer[..take]);
        remaining -= take as u64;
    }
    Ok(ArtifactDigest {
        rows,
        columns,
        element_width: T::WIDTH,
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
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn reject_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(StreamError::UnsafePath);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
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
            completed_phase: "trace".into(),
            challenger_state: vec![8, 9],
            artifacts: vec![CheckpointArtifactV2 {
                name: "trace".into(),
                relative_path: PathBuf::from("trace.bin"),
                digest,
            }],
        };
        let manifest_path = dir.path().join("checkpoint.json");
        manifest.write_atomic(&manifest_path).unwrap();
        let loaded = CheckpointManifestV2::read(&manifest_path).unwrap();
        loaded.validate_identity(identity).unwrap();
        loaded.validate_artifacts(dir.path()).unwrap();
        let mut wrong = identity;
        wrong.release_hash = [0; 32];
        assert!(matches!(
            loaded.validate_identity(wrong),
            Err(StreamError::CheckpointMismatch)
        ));
    }

    #[test]
    fn path_traversal_and_unnoted_retention_are_rejected() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            ScratchMatrixStore::<u64>::create(dir.path(), "../escape", 1, 1),
            Err(StreamError::UnsafePath)
        ));
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
}
