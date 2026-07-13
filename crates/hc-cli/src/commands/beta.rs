use anyhow::{bail, Context, Result};
use hc_beta_client::{
    credentials_from_environment_or_file, input_digest, load_or_create_state, save_state,
    write_owner_file, BetaClient,
};
use hc_plonky3::{
    beta_fixtures::BetaFixture,
    contracts::{
        AirPackageV1, AirProofBundleV1, HostedProofBundleV1, PublicInputsV1, TraceManifestV1,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{fs, io::Write, path::Path, time::Duration};

pub struct SubmitPaths<'a> {
    pub air: &'a Path,
    pub qualification_trace: &'a Path,
    pub qualification_public_inputs: &'a Path,
    pub job_trace: &'a Path,
    pub row_count: u64,
    pub job_public_inputs: &'a Path,
    pub policy: &'a Path,
    pub output_bundle: &'a Path,
    pub state: &'a Path,
    pub credentials_file: Option<&'a Path>,
}

pub fn quickstart(fixture_name: &str, output_dir: &Path) -> Result<()> {
    let fixture = BetaFixture::parse(fixture_name)
        .context("fixture must be fibonacci, poseidon2, or customer_cubic8")?;
    if output_dir.exists() {
        bail!("quickstart output directory already exists");
    }
    fs::create_dir_all(output_dir)?;
    let air = fixture.air();
    write_json(&output_dir.join("air.json"), &air)?;
    for (label, rows) in [("qualification", 1 << 10), ("job", 1 << 14)] {
        let trace = output_dir.join(format!("{label}.trace"));
        let values = write_trace(&trace, fixture, rows)?;
        let public = PublicInputsV1 {
            schema_version: 1,
            air_digest_hex: fixture.air_digest_hex(),
            values,
        };
        write_json(
            &output_dir.join(format!("{label}-public-inputs.json")),
            &public,
        )?;
    }
    write_json(
        &output_dir.join("policy.json"),
        &json!({
            "mode":"scratch","max_resident_bytes":2147483648u64,
            "max_scratch_bytes":107374182400u64,"scratch_dir":output_dir.join("scratch"),
            "max_threads":2,"checkpoint_policy":"retain_on_failure"
        }),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "fixture":fixture.name(),"air":output_dir.join("air.json"),
            "qualification_trace":output_dir.join("qualification.trace"),
            "qualification_public_inputs":output_dir.join("qualification-public-inputs.json"),
            "job_trace":output_dir.join("job.trace"),"job_rows":16384,
            "job_public_inputs":output_dir.join("job-public-inputs.json"),
            "policy":output_dir.join("policy.json")
        }))?
    );
    Ok(())
}

pub fn submit(paths: SubmitPaths<'_>) -> Result<()> {
    let digest = input_digest(&[
        paths.air,
        paths.qualification_trace,
        paths.qualification_public_inputs,
        paths.job_trace,
        paths.job_public_inputs,
        paths.policy,
    ])?;
    let release_sha = hc_plonky3::release_identity();
    let mut state = load_or_create_state(paths.state, &release_sha, &digest)?;
    let api_key = credentials_from_environment_or_file(paths.credentials_file)?;

    let work = paths
        .state
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".tinyzkp-{}", &digest[..16]));
    fs::create_dir_all(&work)?;
    let qualification_packed = work.join("qualification-packed");
    let job_packed = work.join("job-packed");
    let local_proof_path = work.join("qualification-proof.json");
    if !qualification_packed
        .join("trace-manifest-v1.json")
        .is_file()
    {
        super::plonky3::pack_trace(
            paths.air,
            paths.qualification_trace,
            1024,
            &qualification_packed,
            8 * 1024 * 1024,
        )?;
    }
    if !job_packed.join("trace-manifest-v1.json").is_file() {
        super::plonky3::pack_trace(
            paths.air,
            paths.job_trace,
            paths.row_count,
            &job_packed,
            8 * 1024 * 1024,
        )?;
    }
    if !local_proof_path.is_file() {
        super::plonky3::prove_air(
            paths.air,
            &qualification_packed.join("trace-manifest-v1.json"),
            &qualification_packed,
            paths.qualification_public_inputs,
            paths.policy,
            &local_proof_path,
            false,
        )?;
    }
    let air: AirPackageV1 = read_json(paths.air)?;
    let local_proof: AirProofBundleV1 = read_json(&local_proof_path)?;
    let manifest: TraceManifestV1 = read_json(&job_packed.join("trace-manifest-v1.json"))?;
    let public_inputs: PublicInputsV1 = read_json(paths.job_public_inputs)?;
    air.validate().map_err(anyhow::Error::msg)?;
    manifest
        .validate_for_air(&air)
        .map_err(anyhow::Error::msg)?;
    public_inputs
        .validate_for_air(&air)
        .map_err(anyhow::Error::msg)?;
    let _: hc_stream::ResourcePolicyV1 = read_json(paths.policy)?;
    let client = BetaClient::production(api_key)?;

    let air_package_id = match state.air_package_id.clone() {
        Some(id) => id,
        None => {
            let operation = state.operation("register-air");
            let response = client.register_air(&air, &local_proof, &operation)?;
            let id = response
                .get("air_package_id")
                .and_then(Value::as_str)
                .context("registration response lacks ID")?
                .to_owned();
            state.air_package_id = Some(id.clone());
            save_state(paths.state, &state)?;
            id
        }
    };
    let upload_id = match state.upload_id.clone() {
        Some(id) => id,
        None => {
            let attempt = state.upload_attempt;
            let operation = state.operation(&format!("create-upload-{attempt}"));
            state.upload_attempt = state
                .upload_attempt
                .checked_add(1)
                .context("upload attempt counter exhausted")?;
            // Persist the next attempt before any network I/O. If this process is
            // interrupted, the next invocation obtains fresh signed URLs instead
            // of replaying an expired idempotent response.
            save_state(paths.state, &state)?;
            let upload = client.create_upload(&air_package_id, &manifest, &operation)?;
            client.upload_chunks(&upload, &job_packed)?;
            let id = upload.upload_id;
            state.upload_id = Some(id.clone());
            save_state(paths.state, &state)?;
            id
        }
    };
    let job_id = match state.job_id.clone() {
        Some(id) => id,
        None => {
            let operation = state.operation("submit-job");
            let job = client.submit_job(&air_package_id, &upload_id, &public_inputs, &operation)?;
            let id = job.job_id;
            state.job_id = Some(id.clone());
            save_state(paths.state, &state)?;
            id
        }
    };
    let status = client.wait(&job_id, Duration::from_secs(3600))?;
    if status.status != "completed" {
        bail!(
            "hosted job ended in {} ({:?})",
            status.status,
            status.error_code
        );
    }
    let bundle_digest = client.download(&job_id, paths.output_bundle)?;
    let bundle: HostedProofBundleV1 = read_json(paths.output_bundle)?;
    bundle.verify().map_err(anyhow::Error::msg)?;
    let remote = client.verify_remote(&bundle)?;
    if remote.get("valid") != Some(&Value::Bool(true)) {
        bail!("remote official verification failed");
    }
    state.bundle_digest_hex = Some(bundle_digest.clone());
    save_state(paths.state, &state)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "release_sha":release_sha,"air_digest_hex":manifest.air_digest_hex,
            "trace_digest_hex":manifest.trace_digest_hex,"public_inputs_digest_hex":bundle.proof.public_inputs_digest_hex,
            "job_id":job_id,"state":status.status,"reservation_millicredits":status.estimate.get("reservation_millicredits"),
            "final_charge_millicredits":status.settled_millicredits,"bundle_path":paths.output_bundle,
            "bundle_digest_hex":bundle_digest,"official_verification":true
        }))?
    );
    Ok(())
}

pub fn status(state_path: &Path, credentials_file: Option<&Path>) -> Result<()> {
    let state: hc_beta_client::ResumeStateV1 = read_owner_json(state_path)?;
    let job = state
        .job_id
        .context("resume state does not contain a job")?;
    let client = BetaClient::production(credentials_from_environment_or_file(credentials_file)?)?;
    println!("{}", serde_json::to_string_pretty(&client.status(&job)?)?);
    Ok(())
}

pub fn cancel(state_path: &Path, credentials_file: Option<&Path>) -> Result<()> {
    let mut state: hc_beta_client::ResumeStateV1 = read_owner_json(state_path)?;
    let job = state
        .job_id
        .clone()
        .context("resume state does not contain a job")?;
    let operation = state.operation("cancel-job");
    save_state(state_path, &state)?;
    let client = BetaClient::production(credentials_from_environment_or_file(credentials_file)?)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&client.cancel(&job, &operation)?)?
    );
    Ok(())
}

pub fn download(state_path: &Path, output: &Path, credentials_file: Option<&Path>) -> Result<()> {
    let mut state: hc_beta_client::ResumeStateV1 = read_owner_json(state_path)?;
    let job = state
        .job_id
        .clone()
        .context("resume state does not contain a job")?;
    let client = BetaClient::production(credentials_from_environment_or_file(credentials_file)?)?;
    let digest = client.download(&job, output)?;
    state.bundle_digest_hex = Some(digest.clone());
    save_state(state_path, &state)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"bundle_path":output,"bundle_digest_hex":digest}))?
    );
    Ok(())
}

pub fn verify(bundle_path: &Path, credentials_file: Option<&Path>, remote: bool) -> Result<()> {
    let bundle: HostedProofBundleV1 = read_json(bundle_path)?;
    bundle.verify().map_err(anyhow::Error::msg)?;
    if remote {
        let client =
            BetaClient::production(credentials_from_environment_or_file(credentials_file)?)?;
        let response = client.verify_remote(&bundle)?;
        if response.get("valid") != Some(&Value::Bool(true)) {
            bail!("remote verification failed");
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"valid":true,"proof_digest_hex":bundle.proof.proof_digest_hex})
        )?
    );
    Ok(())
}

pub fn doctor(credentials_file: Option<&Path>) -> Result<()> {
    let client = BetaClient::production(credentials_from_environment_or_file(credentials_file)?)?;
    let discovery = client.discovery()?;
    let expected = hc_plonky3::release_identity();
    let actual = discovery
        .get("release_sha")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actual != expected {
        bail!("CLI/API release mismatch: CLI {expected}, API {actual}");
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"healthy":true,"release_sha":expected,"discovery":discovery})
        )?
    );
    Ok(())
}

fn write_trace(path: &Path, fixture: BetaFixture, rows: u64) -> Result<Vec<u64>> {
    let mut output = fs::File::create(path)?;
    let initial = fixture.initial_state();
    let mut state = initial.clone();
    let mut last = Vec::new();
    for _ in 0..rows {
        let (row, next) = fixture.trace_row_and_next(&state);
        for value in &row {
            output.write_all(&value.to_le_bytes())?;
        }
        last = row;
        state = next;
    }
    output.sync_all()?;
    Ok(fixture.public_values(&initial, &last))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_owner_file(path, &bytes)
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn read_owner_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            bail!("state file must be mode 0600");
        }
    }
    read_json(path)
}
