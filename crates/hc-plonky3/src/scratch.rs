use hc_stream::{Result, StreamError};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Allocate an owner-only scratch directory without assuming that a process
/// identifier/counter pair is unused. Retained checkpoints can outlive a
/// container process, so a restarted process must skip names created by the
/// prior process instead of failing the resumed proof with `AlreadyExists`.
pub(crate) fn create_unique_job_dir(
    root: &Path,
    prefix: &str,
    counter: &AtomicU64,
) -> Result<PathBuf> {
    fs::create_dir_all(root)?;
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StreamError::UnsafePath);
    }

    loop {
        let id = counter.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("{prefix}-{}-{id}", std::process::id()));
        let created = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).create(&path)
            }
            #[cfg(not(unix))]
            {
                fs::create_dir(&path)
            }
        };
        match created {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_a_directory_retained_by_a_previous_process() {
        let root = tempfile::tempdir().unwrap();
        let counter = AtomicU64::new(0);
        let collision = root.path().join(format!("dft-{}-0", std::process::id()));
        fs::create_dir(&collision).unwrap();

        let allocated = create_unique_job_dir(root.path(), "dft", &counter).unwrap();

        assert_ne!(allocated, collision);
        assert_eq!(
            allocated.file_name().and_then(|name| name.to_str()),
            Some(format!("dft-{}-1", std::process::id()).as_str())
        );
    }
}
