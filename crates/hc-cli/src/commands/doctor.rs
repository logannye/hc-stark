use crate::protocol::{emit_progress, ProtocolFailure};
use anyhow::Result;
use hc_plonky3::contracts::{
    AirPackageV1, ContractError, PublicInputsV1, TraceManifestV1, MAX_AIR_JSON_BYTES,
    MAX_TRACE_MANIFEST_JSON_BYTES,
};
use hc_plonky3::estimate_declarative_execution_paths;
use hc_stream::{CheckpointPolicy, ResourceMode, ResourcePolicyV1};
use serde::de::DeserializeOwned;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use tinyzkp_contracts::{
    declaration_failure_preflight, failed_resource_preflight, parse_strict_json,
    select_and_preflight, DoctorReportV1, EngineProgressEventV1, ExitClassV1, JobManifestV1,
    PlatformIdentifierV1, ReasonCodeV1, ReasonV1, RequestedModeV1, ResourceEstimateV1,
    ResourceEstimatesV1, ResourcePreflightV1, COMPATIBILITY_PROFILE, MAX_AIR_BYTES,
    MAX_MANIFEST_BYTES, MAX_PUBLIC_INPUT_BYTES, MAX_TRACE_COMPRESSED_BYTES,
    MAX_TRACE_MANIFEST_BYTES,
};

#[derive(Clone, Debug)]
struct ResolvedDoctorPaths {
    air_package: PathBuf,
    trace_manifest: PathBuf,
    chunks_dir: PathBuf,
    public_inputs: PathBuf,
    _job_dir: PathBuf,
    _output_dir: PathBuf,
    scratch_dir: PathBuf,
    scratch_measurement_root: PathBuf,
}

pub fn run(job_path: &Path) -> Result<u8> {
    let cwd =
        std::env::current_dir().map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    run_with_host(
        &cwd,
        job_path,
        std::env::consts::OS,
        std::env::consts::ARCH,
        None,
    )
}

fn run_with_host(
    cwd: &Path,
    job_path: &Path,
    operating_system: &str,
    architecture: &str,
    available_override: Option<u64>,
) -> Result<u8> {
    emit_progress(&EngineProgressEventV1::simple(
        &hc_plonky3::release_identity(),
        "doctor_started",
        "validation",
    ));
    let manifest_path = resolve_manifest_path(cwd, job_path)?;
    let manifest: JobManifestV1 = read_json_limited(&manifest_path, MAX_MANIFEST_BYTES)?;

    let declared_reasons = manifest.compatibility_reasons();
    if let Some(reason) = declared_reasons
        .iter()
        .find(|reason| reason.class == ExitClassV1::InvalidInput)
    {
        return Err(ProtocolFailure {
            reason: reason.clone(),
            resumable: false,
            checkpoint_present: false,
        }
        .into());
    }

    // Validate every path in the manifest before returning a compatibility
    // report. This is read-only: missing job/output/scratch leaf directories
    // are accepted but never created.
    let paths = resolve_job_paths(&manifest_path, &manifest)?;

    let mut incompatibility_reasons: Vec<_> = declared_reasons
        .iter()
        .filter(|reason| reason.class == ExitClassV1::Incompatible)
        .cloned()
        .collect();
    if operating_system != "linux" || architecture != "x86_64" {
        incompatibility_reasons.push(ReasonV1::new(ReasonCodeV1::UnsupportedPlatform).platforms(
            Some(PlatformIdentifierV1::LinuxX86_64),
            Some(platform_identifier(operating_system, architecture)),
        ));
    }
    if !incompatibility_reasons.is_empty() {
        return write_report(
            &manifest,
            false,
            None,
            None,
            empty_preflight(&manifest, None),
            incompatibility_reasons,
            ExitClassV1::Incompatible.exit_code(),
        );
    }

    emit_progress(&EngineProgressEventV1::simple(
        &hc_plonky3::release_identity(),
        "doctor_paths_validated",
        "validation",
    ));
    let air: AirPackageV1 = read_json_limited(
        &paths.air_package,
        u64::try_from(MAX_AIR_JSON_BYTES).unwrap_or(MAX_AIR_BYTES),
    )?;
    let trace: TraceManifestV1 = read_json_limited(
        &paths.trace_manifest,
        u64::try_from(MAX_TRACE_MANIFEST_JSON_BYTES).unwrap_or(MAX_TRACE_MANIFEST_BYTES),
    )?;
    let public_inputs: PublicInputsV1 =
        read_json_limited(&paths.public_inputs, MAX_PUBLIC_INPUT_BYTES)?;

    match air.validate() {
        Ok(()) => {}
        Err(ContractError::ProfileMismatch) => {
            return write_report(
                &manifest,
                false,
                None,
                None,
                empty_preflight(&manifest, None),
                vec![ReasonV1::new(ReasonCodeV1::UnsupportedProfile)],
                ExitClassV1::Incompatible.exit_code(),
            )
        }
        Err(ContractError::SizeLimit) => {
            return Err(ProtocolFailure::new(ReasonCodeV1::InputLimitExceeded).into())
        }
        Err(_) => return Err(ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid).into()),
    }
    validate_contract(trace.validate_for_air(&air))?;
    validate_contract(public_inputs.validate_for_air(&air))?;
    if manifest.workload.logical_rows != trace.logical_rows
        || manifest.workload.trace_width != air.trace_width
        || manifest.workload.trace_width != trace.trace_width
    {
        return Err(ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid).into());
    }
    validate_trace_chunks(&paths.chunks_dir, &trace)?;

    emit_progress(&EngineProgressEventV1::simple(
        &hc_plonky3::release_identity(),
        "doctor_inputs_validated",
        "validation",
    ));
    let resource_minimum_reasons: Vec<_> = declared_reasons
        .iter()
        .filter(|reason| reason.class == ExitClassV1::InsufficientResources)
        .cloned()
        .collect();
    let policy = ResourcePolicyV1 {
        mode: match manifest.mode {
            RequestedModeV1::Auto => ResourceMode::Auto,
            RequestedModeV1::Conventional => ResourceMode::Memory,
            RequestedModeV1::Bounded => ResourceMode::Scratch,
        },
        max_resident_bytes: manifest.ram_budget_bytes,
        max_scratch_bytes: manifest.scratch_budget_bytes,
        scratch_dir: paths.scratch_dir,
        max_threads: usize::from(manifest.max_threads),
        checkpoint_policy: CheckpointPolicy::RetainOnFailure,
    };
    // Estimation itself requires a structurally valid policy. For a manifest
    // below the hard declaration minima, clamp only this read-only estimation
    // copy so the complete exit-12 report can still include both estimates.
    let mut estimation_policy = policy;
    if !resource_minimum_reasons.is_empty() {
        estimation_policy.max_resident_bytes =
            estimation_policy.max_resident_bytes.max(16 * 1024 * 1024);
        estimation_policy.max_scratch_bytes = estimation_policy.max_scratch_bytes.max(1);
    }
    emit_progress(&EngineProgressEventV1::simple(
        &hc_plonky3::release_identity(),
        "doctor_estimating",
        "resource_estimate",
    ));
    let (conventional, bounded) = estimate_declarative_execution_paths(
        air,
        trace.logical_rows,
        &public_inputs.values,
        &estimation_policy,
    )
    .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid))?;
    let estimates = ResourceEstimatesV1 {
        conventional: convert_estimate(conventional),
        bounded: convert_estimate(bounded),
    };
    let available = match available_override {
        Some(value) => Some(value),
        None => fs2::available_space(&paths.scratch_measurement_root).ok(),
    };

    if !resource_minimum_reasons.is_empty() {
        return write_report(
            &manifest,
            false,
            None,
            Some(estimates),
            empty_preflight(&manifest, available),
            resource_minimum_reasons,
            ExitClassV1::InsufficientResources.exit_code(),
        );
    }

    match select_and_preflight(&manifest, &estimates, available) {
        Ok((selected, preflight)) => write_report(
            &manifest,
            true,
            Some(selected),
            Some(estimates),
            preflight,
            Vec::new(),
            0,
        ),
        Err(reason) => {
            let preflight = failed_resource_preflight(&manifest, available, &reason);
            write_report(
                &manifest,
                false,
                None,
                Some(estimates),
                preflight,
                vec![reason],
                ExitClassV1::InsufficientResources.exit_code(),
            )
        }
    }
}

fn write_report(
    manifest: &JobManifestV1,
    ready: bool,
    selected_mode: Option<tinyzkp_contracts::SelectedModeV1>,
    estimates: Option<ResourceEstimatesV1>,
    preflight: ResourcePreflightV1,
    reasons: Vec<ReasonV1>,
    exit_code: u8,
) -> Result<u8> {
    let release_identity = hc_plonky3::release_identity();
    let report = DoctorReportV1 {
        schema_version: 1,
        engine_release_identity: release_identity.clone(),
        compatibility_profile: COMPATIBILITY_PROFILE.to_owned(),
        ready,
        requested_mode: manifest.mode,
        selected_mode,
        estimates,
        preflight,
        reasons,
    };
    if !report.validate_for_manifest(&release_identity, manifest) {
        return Err(ProtocolFailure::new(ReasonCodeV1::InternalError).into());
    }
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &report)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    stdout
        .write_all(b"\n")
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    stdout
        .flush()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::InternalError))?;
    emit_progress(&EngineProgressEventV1::simple(
        &hc_plonky3::release_identity(),
        "doctor_completed",
        "complete",
    ));
    Ok(exit_code)
}

fn empty_preflight(
    manifest: &JobManifestV1,
    available_scratch_bytes: Option<u64>,
) -> ResourcePreflightV1 {
    declaration_failure_preflight(manifest, available_scratch_bytes)
}

fn platform_identifier(operating_system: &str, architecture: &str) -> PlatformIdentifierV1 {
    match (operating_system, architecture) {
        ("linux", "x86_64") => PlatformIdentifierV1::LinuxX86_64,
        ("linux", _) => PlatformIdentifierV1::LinuxOther,
        ("macos", _) => PlatformIdentifierV1::Macos,
        ("windows", _) => PlatformIdentifierV1::Windows,
        _ => PlatformIdentifierV1::Other,
    }
}

fn convert_estimate(value: hc_stream::ResourceEstimate) -> ResourceEstimateV1 {
    ResourceEstimateV1 {
        peak_resident_bytes: value.peak_resident_bytes,
        scratch_high_water_bytes: value.scratch_high_water_bytes,
        total_read_bytes: value.total_read_bytes,
        total_write_bytes: value.total_write_bytes,
    }
}

fn validate_contract(result: hc_plonky3::contracts::Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(ContractError::ProfileMismatch) => {
            Err(ProtocolFailure::new(ReasonCodeV1::UnsupportedProfile).into())
        }
        Err(ContractError::SizeLimit) => {
            Err(ProtocolFailure::new(ReasonCodeV1::InputLimitExceeded).into())
        }
        Err(_) => Err(ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid).into()),
    }
}

fn resolve_job_paths(
    manifest_path: &Path,
    manifest: &JobManifestV1,
) -> Result<ResolvedDoctorPaths> {
    let base = manifest_path
        .parent()
        .ok_or_else(|| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    let input_root = resolve_existing(
        base,
        &manifest.roots.input_root,
        ExpectedKind::Directory,
        u64::MAX,
    )?;
    let job_root = resolve_existing(
        base,
        &manifest.roots.job_root,
        ExpectedKind::Directory,
        u64::MAX,
    )?;
    let output_root = resolve_existing(
        base,
        &manifest.roots.output_root,
        ExpectedKind::Directory,
        u64::MAX,
    )?;
    let scratch_root = resolve_existing(
        base,
        &manifest.roots.scratch_root,
        ExpectedKind::Directory,
        u64::MAX,
    )?;
    reject_overlapping_roots(&[&input_root, &job_root, &output_root, &scratch_root])?;
    let air_package = resolve_existing(
        &input_root,
        &manifest.workload.air_package,
        ExpectedKind::File,
        MAX_AIR_BYTES,
    )?;
    let trace_manifest = resolve_existing(
        &input_root,
        &manifest.workload.trace_manifest,
        ExpectedKind::File,
        MAX_TRACE_MANIFEST_BYTES,
    )?;
    let chunks_dir = resolve_existing(
        &input_root,
        &manifest.workload.chunks_dir,
        ExpectedKind::Directory,
        u64::MAX,
    )?;
    let public_inputs = resolve_existing(
        &input_root,
        &manifest.workload.public_inputs,
        ExpectedKind::File,
        MAX_PUBLIC_INPUT_BYTES,
    )?;
    let job_dir = resolve_declared_directory(&job_root, &manifest.job_dir)?;
    let output_dir = resolve_declared_directory(&output_root, &manifest.output_dir)?;
    let scratch_dir = resolve_declared_directory(&scratch_root, &manifest.scratch_dir)?;
    Ok(ResolvedDoctorPaths {
        air_package,
        trace_manifest,
        chunks_dir,
        public_inputs,
        _job_dir: job_dir,
        _output_dir: output_dir,
        scratch_dir,
        scratch_measurement_root: scratch_root,
    })
}

fn resolve_manifest_path(cwd: &Path, path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
    }
    resolve_existing(cwd, path, ExpectedKind::File, MAX_MANIFEST_BYTES)
}

#[derive(Clone, Copy)]
enum ExpectedKind {
    File,
    Directory,
}

fn validate_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
    }
    Ok(())
}

fn resolve_existing(
    root: &Path,
    relative: &Path,
    expected: ExpectedKind,
    maximum_bytes: u64,
) -> Result<PathBuf> {
    validate_relative(relative)?;
    let root = root
        .canonicalize()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    let mut current = root.clone();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
        };
        current.push(part);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
        if metadata.file_type().is_symlink() {
            return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
        }
    }
    let canonical = current
        .canonicalize()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    if !canonical.starts_with(&root) {
        return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    let kind_ok = match expected {
        ExpectedKind::File => metadata.file_type().is_file(),
        ExpectedKind::Directory => metadata.file_type().is_dir(),
    };
    if !kind_ok {
        return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
    }
    if matches!(expected, ExpectedKind::File) && metadata.len() > maximum_bytes {
        return Err(ProtocolFailure::new(ReasonCodeV1::InputLimitExceeded).into());
    }
    Ok(canonical)
}

/// Validate a relative future directory without creating it. Every existing
/// ancestor must be a real directory and not a symlink.
fn resolve_declared_directory(root: &Path, relative: &Path) -> Result<PathBuf> {
    validate_relative(relative)?;
    let root = root
        .canonicalize()
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    let mut current = root.clone();
    let mut found_missing = false;
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
        };
        current.push(part);
        if found_missing {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
                return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                found_missing = true;
            }
            Err(_) => return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into()),
        }
    }
    if !current.starts_with(&root) {
        return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
    }
    Ok(current)
}

fn reject_overlapping_roots(roots: &[&PathBuf]) -> Result<()> {
    for (index, left) in roots.iter().enumerate() {
        for right in roots.iter().skip(index + 1) {
            if left.starts_with(right) || right.starts_with(left) {
                return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
            }
        }
    }
    Ok(())
}

fn validate_trace_chunks(chunks_dir: &Path, trace: &TraceManifestV1) -> Result<()> {
    let mut compressed_total = 0u64;
    for chunk in &trace.chunks {
        let path = chunks_dir.join(format!("chunk-{:06}.zst", chunk.index));
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
        }
        if metadata.len() != chunk.compressed_bytes {
            return Err(ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid).into());
        }
        compressed_total = compressed_total
            .checked_add(metadata.len())
            .ok_or_else(|| ProtocolFailure::new(ReasonCodeV1::InputLimitExceeded))?;
        if compressed_total > MAX_TRACE_COMPRESSED_BYTES {
            return Err(ProtocolFailure::new(ReasonCodeV1::InputLimitExceeded).into());
        }
    }
    Ok(())
}

fn read_json_limited<T: DeserializeOwned>(path: &Path, maximum_bytes: u64) -> Result<T> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    if !metadata.file_type().is_file() {
        return Err(ProtocolFailure::new(ReasonCodeV1::UnsafePath).into());
    }
    if metadata.len() > maximum_bytes {
        return Err(ProtocolFailure::new(ReasonCodeV1::InputLimitExceeded).into());
    }
    let file = fs::File::open(path).map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::UnsafePath))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(ProtocolFailure::new(ReasonCodeV1::InputLimitExceeded).into());
    }
    parse_strict_json(&bytes)
        .map_err(|_| ProtocolFailure::new(ReasonCodeV1::ManifestContractInvalid).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_plonky3::contracts::{
        AirConstraintKindV1, AirConstraintV1, AirExpressionV1, PublicInputSlotV1, TraceChunkV1,
    };
    use tinyzkp_contracts::{
        AirFeaturesV1, JobRootsV1, WorkloadInputV1, EXTENSION_DEGREE, FIELD, PERMUTATION, VERIFIER,
    };

    fn fixture(root: &Path) -> JobManifestV1 {
        for directory in ["inputs/chunks", "jobs", "outputs", "scratch"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        let air = AirPackageV1 {
            schema_version: 1,
            backend: "plonky3".into(),
            profile: COMPATIBILITY_PROFILE.into(),
            field: FIELD.into(),
            expected_verifier: VERIFIER.into(),
            trace_width: 1,
            public_inputs: vec![PublicInputSlotV1 { name: "x".into() }],
            expressions: vec![
                AirExpressionV1::Current { column: 0 },
                AirExpressionV1::Next { column: 0 },
                AirExpressionV1::Sub { left: 1, right: 0 },
            ],
            constraints: vec![AirConstraintV1 {
                kind: AirConstraintKindV1::Transition,
                expression: 2,
            }],
        };
        fs::write(
            root.join("inputs/air.json"),
            serde_json::to_vec(&air).unwrap(),
        )
        .unwrap();
        let air_digest = air.digest().unwrap();
        let trace = TraceManifestV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&air_digest),
            trace_digest_hex: "00".repeat(32),
            logical_rows: 1 << 10,
            trace_width: 1,
            field_encoding: "goldilocks_u64_le".into(),
            compression: "zstd".into(),
            chunk_uncompressed_bytes: 8192,
            chunks: vec![TraceChunkV1 {
                index: 0,
                compressed_bytes: 1,
                uncompressed_bytes: 8192,
                blake3_hex: "11".repeat(32),
            }],
        };
        fs::write(
            root.join("inputs/trace.json"),
            serde_json::to_vec(&trace).unwrap(),
        )
        .unwrap();
        let public = PublicInputsV1 {
            schema_version: 1,
            air_digest_hex: hex_lower(&air_digest),
            values: vec![0],
        };
        fs::write(
            root.join("inputs/public.json"),
            serde_json::to_vec(&public).unwrap(),
        )
        .unwrap();
        fs::write(root.join("inputs/chunks/chunk-000000.zst"), [0]).unwrap();
        JobManifestV1 {
            schema_version: 1,
            compatibility_profile: COMPATIBILITY_PROFILE.into(),
            workload: WorkloadInputV1 {
                air_package: "air.json".into(),
                trace_manifest: "trace.json".into(),
                chunks_dir: "chunks".into(),
                public_inputs: "public.json".into(),
                logical_rows: 1 << 10,
                trace_width: 1,
                max_constraint_degree: 1,
                field: FIELD.into(),
                extension_degree: EXTENSION_DEGREE,
                permutation: PERMUTATION.into(),
                verifier: VERIFIER.into(),
                features: AirFeaturesV1 {
                    uses_lookups: false,
                    uses_buses: false,
                    uses_permutations: false,
                    uses_multi_table: false,
                    uses_preprocessed_columns: false,
                    uses_periodic_columns: false,
                    uses_recursion: false,
                    uses_gpu: false,
                },
            },
            mode: RequestedModeV1::Auto,
            ram_budget_bytes: 4 * 1024 * 1024 * 1024,
            scratch_budget_bytes: 16 * 1024 * 1024 * 1024,
            max_threads: 1,
            roots: JobRootsV1 {
                input_root: "inputs".into(),
                job_root: "jobs".into(),
                output_root: "outputs".into(),
                scratch_root: "scratch".into(),
            },
            job_dir: "job".into(),
            output_dir: "job".into(),
            scratch_dir: "job".into(),
        }
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn doctor_never_reads_trace_chunk_contents_or_creates_job_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let job = fixture(root);
        fs::write(root.join("job.json"), serde_json::to_vec(&job).unwrap()).unwrap();
        let chunk = root.join("inputs/chunks/chunk-000000.zst");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&chunk, fs::Permissions::from_mode(0o000)).unwrap();
        }
        let result = run_with_host(
            root,
            Path::new("job.json"),
            "linux",
            "x86_64",
            Some(u64::MAX),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&chunk, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(result.unwrap(), 0);
        assert!(!root.join("jobs/job").exists());
        assert!(!root.join("outputs/job").exists());
        assert!(!root.join("scratch/job").exists());
    }

    #[test]
    fn job_and_output_traversal_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut job = fixture(root);
        job.job_dir = "../escape".into();
        assert_eq!(
            resolve_job_paths(&root.join("job.json"), &job)
                .unwrap_err()
                .downcast_ref::<ProtocolFailure>()
                .unwrap()
                .reason
                .code,
            ReasonCodeV1::UnsafePath
        );
        job.job_dir = "job".into();
        job.output_dir = "../escape".into();
        assert!(resolve_job_paths(&root.join("job.json"), &job).is_err());
    }

    #[test]
    fn absolute_job_manifest_path_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let job = fixture(root);
        let manifest = root.join("job.json");
        fs::write(&manifest, serde_json::to_vec(&job).unwrap()).unwrap();
        let error = resolve_manifest_path(root, &manifest).unwrap_err();
        assert_eq!(
            error.downcast_ref::<ProtocolFailure>().unwrap().reason.code,
            ReasonCodeV1::UnsafePath
        );
        assert!(resolve_manifest_path(root, Path::new("job.json")).is_ok());
    }

    #[test]
    fn root_overlap_and_missing_chunk_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut job = fixture(root);
        job.roots.job_root = "inputs".into();
        assert!(resolve_job_paths(&root.join("job.json"), &job).is_err());
        job.roots.job_root = "jobs".into();
        let paths = resolve_job_paths(&root.join("job.json"), &job).unwrap();
        fs::remove_file(root.join("inputs/chunks/chunk-000000.zst")).unwrap();
        let trace: TraceManifestV1 =
            read_json_limited(&root.join("inputs/trace.json"), MAX_TRACE_MANIFEST_BYTES).unwrap();
        assert!(validate_trace_chunks(&paths.chunks_dir, &trace).is_err());
    }

    #[test]
    fn failed_preflight_reports_scratch_required_only_for_scratch_failures() {
        let temp = tempfile::tempdir().unwrap();
        let job = fixture(temp.path());
        let ram = ReasonV1::new(ReasonCodeV1::RamBudgetInsufficient).resource(
            256 * 1024 * 1024,
            None,
            Some(job.ram_budget_bytes),
        );
        assert_eq!(
            failed_resource_preflight(&job, Some(900), &ram).scratch_required_with_headroom_bytes,
            None
        );

        for code in [
            ReasonCodeV1::ScratchBudgetInsufficient,
            ReasonCodeV1::ScratchSpaceInsufficient,
        ] {
            let scratch =
                ReasonV1::new(code).resource(1_000, Some(900), Some(job.scratch_budget_bytes));
            assert_eq!(
                failed_resource_preflight(&job, Some(900), &scratch)
                    .scratch_required_with_headroom_bytes,
                Some(1_000)
            );
        }
    }
}
