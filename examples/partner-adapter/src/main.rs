use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use tinyzkp_partner_adapter_example::{PartnerCounterWorkload, PartnerEvaluationManifestV1};

#[derive(Clone, Copy)]
enum Mode {
    Compare,
    Bounded,
    Conventional,
    Doctor,
}

impl Mode {
    fn parse(value: &str) -> Result<Self, Box<dyn std::error::Error>> {
        match value {
            "compare" => Ok(Self::Compare),
            "bounded" => Ok(Self::Bounded),
            "conventional" => Ok(Self::Conventional),
            "doctor" => Ok(Self::Doctor),
            _ => Err("mode must be compare, bounded, conventional, or doctor".into()),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Compare => "compare",
            Self::Bounded => "bounded",
            Self::Conventional => "conventional",
            Self::Doctor => "doctor",
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next().ok_or("manifest path is required")?;
    let (mode, manifest_path) = if first == "--mode" {
        let raw_mode = arguments.next().ok_or("mode is required")?;
        let mode = Mode::parse(raw_mode.to_str().ok_or("mode must be UTF-8")?)?;
        let manifest = arguments.next().ok_or("manifest path is required")?;
        (mode, PathBuf::from(manifest))
    } else {
        (Mode::Compare, PathBuf::from(first))
    };
    let output_path = PathBuf::from(arguments.next().ok_or("output path is required")?);
    if arguments.next().is_some() {
        return Err(
            "usage: partner-adapter [--mode compare|bounded|conventional|doctor] <manifest.json> <evidence.json>"
                .into(),
        );
    }
    let manifest: PartnerEvaluationManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest.validate()?;
    let manifest_bytes = hc_plonky3::contracts::canonical_json_bytes_v1(&manifest)?;
    let manifest_digest_hex = blake3::hash(&manifest_bytes).to_hex().to_string();
    let workload = PartnerCounterWorkload {
        start: manifest.start,
        logical_rows: manifest.logical_rows,
    };
    let preflight_estimate =
        hc_plonky3::estimate_resource_bounded_workload(&workload, &manifest.resource_policy)?;
    manifest.resource_policy.preflight_for_mode(
        hc_stream::ExecutionMode::Scratch,
        preflight_estimate.clone(),
    )?;

    let mut evidence = serde_json::json!({
        "schema_version": 1,
        "mode": mode.as_str(),
        "profile": hc_plonky3::COMPATIBILITY_PROFILE,
        "plonky3_version": hc_plonky3::PLONKY3_VERSION,
        "release_sha": hc_plonky3::release_identity(),
        "dependency_lock_sha256": hc_plonky3::DEPENDENCY_LOCK_SHA256,
        "workload_id": "partner_counter_example",
        "logical_rows": manifest.logical_rows,
        "manifest_digest_hex": manifest_digest_hex,
        "preflight_estimate": preflight_estimate,
        "witness_data_included": false
    });
    if !matches!(mode, Mode::Doctor) {
        let mut prover_scratch_high_water_bytes = 0_u64;
        let mut bounded_proof = || {
            hc_plonky3::prove_resource_bounded_observed(
                &workload,
                &manifest.resource_policy,
                |event| {
                    if let hc_plonky3::ProverEventV1::Phase { resource_usage, .. } = event {
                        prover_scratch_high_water_bytes =
                            prover_scratch_high_water_bytes.max(resource_usage.scratch_bytes);
                    }
                },
            )
        };
        let (proof, equal) = match mode {
            Mode::Compare => {
                let bounded = bounded_proof()?;
                let conventional = hc_plonky3::prove_resource_reference(&workload)?;
                if bounded != conventional {
                    return Err("bounded and conventional official proof bytes differ".into());
                }
                (bounded, Some(true))
            }
            Mode::Bounded => (bounded_proof()?, None),
            Mode::Conventional => (hc_plonky3::prove_resource_reference(&workload)?, None),
            Mode::Doctor => unreachable!(),
        };
        let object = evidence
            .as_object_mut()
            .ok_or("evidence must be an object")?;
        let verification_started = std::time::Instant::now();
        hc_plonky3::verify_resource_bounded_proof(&workload, &proof)?;
        let verification_time_ms = verification_started.elapsed().as_millis() as u64;
        object.insert("official_verification".into(), true.into());
        object.insert(
            "prover_scratch_high_water_bytes".into(),
            prover_scratch_high_water_bytes.into(),
        );
        object.insert("verification_time_ms".into(), verification_time_ms.into());
        object.insert("proof_size_bytes".into(), proof.len().into());
        object.insert(
            "proof_blake3_hex".into(),
            blake3::hash(&proof).to_hex().to_string().into(),
        );
        if let Some(equal) = equal {
            object.insert("bounded_equals_conventional".into(), equal.into());
        }
    }
    write_json_atomic(&output_path, &evidence)?;
    Ok(())
}

fn write_json_atomic(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("evidence.json");
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}
