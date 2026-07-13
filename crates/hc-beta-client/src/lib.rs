//! Redacting, resumable client for TinyZKP's paid public-beta API.

use anyhow::{bail, Context, Result};
use hc_plonky3::contracts::{
    AirPackageV1, AirProofBundleV1, HostedProofBundleV1, PublicInputsV1, TraceManifestV1,
};
use reqwest::blocking::{Client as HttpClient, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::Duration};

pub const PRODUCTION_API: &str = "https://api.tinyzkp.com";
const TERMINAL: [&str; 4] = [
    "completed",
    "cancelled",
    "platform_failed",
    "customer_failed",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeStateV1 {
    pub schema_version: u32,
    pub release_sha: String,
    pub input_sha256: String,
    pub operations: BTreeMap<String, String>,
    pub air_package_id: Option<String>,
    /// The next upload creation attempt. Each attempt receives fresh, short-lived
    /// signed URLs; URLs themselves are never persisted in resume state.
    #[serde(default)]
    pub upload_attempt: u32,
    pub upload_id: Option<String>,
    pub job_id: Option<String>,
    pub bundle_digest_hex: Option<String>,
}

impl ResumeStateV1 {
    pub fn new(release_sha: String, input_sha256: String) -> Self {
        Self {
            schema_version: 1,
            release_sha,
            input_sha256,
            operations: BTreeMap::new(),
            air_package_id: None,
            upload_attempt: 0,
            upload_id: None,
            job_id: None,
            bundle_digest_hex: None,
        }
    }

    pub fn operation(&mut self, name: &str) -> String {
        self.operations
            .entry(name.to_owned())
            .or_insert_with(|| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"tinyzkp-beta-operation-v1\0");
                hasher.update(self.input_sha256.as_bytes());
                hasher.update(b"\0");
                hasher.update(name.as_bytes());
                format!("cli-{}", hasher.finalize().to_hex())
            })
            .clone()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignedUrl {
    pub url: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UploadChunk {
    pub index: u32,
    pub upload: SignedUrl,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UploadResponse {
    pub upload_id: String,
    pub chunks: Vec<UploadChunk>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JobStatus {
    pub job_id: String,
    pub status: String,
    pub estimate: Value,
    pub progress: Option<Value>,
    pub settled_millicredits: Option<u64>,
    pub measured_cost_millicredits: Option<u64>,
    pub realized_gross_margin_bps: Option<i32>,
    pub error_code: Option<String>,
}

pub struct BetaClient {
    http: HttpClient,
    base_url: String,
    api_key: String,
}

impl BetaClient {
    pub fn production(api_key: String) -> Result<Self> {
        Self::with_endpoint(PRODUCTION_API, api_key)
    }

    fn with_endpoint(base_url: &str, api_key: String) -> Result<Self> {
        if !base_url.starts_with("https://") && !cfg!(any(test, feature = "test-endpoint")) {
            bail!("release clients require the production HTTPS endpoint");
        }
        if !api_key.starts_with("tzb_") || api_key.len() < 32 {
            bail!("TINYZKP_API_KEY is malformed");
        }
        Ok(Self {
            http: HttpClient::builder()
                .timeout(Duration::from_secs(120))
                .build()?,
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
        })
    }

    #[cfg(any(test, feature = "test-endpoint"))]
    pub fn test_endpoint(base_url: &str, api_key: String) -> Result<Self> {
        Self::with_endpoint(base_url, api_key)
    }

    pub fn register_air(
        &self,
        air: &AirPackageV1,
        proof: &AirProofBundleV1,
        operation: &str,
    ) -> Result<Value> {
        self.write(
            "/v1/air-packages",
            operation,
            &json!({"air":air,"local_proof":proof}),
        )
    }

    pub fn create_upload(
        &self,
        air_package_id: &str,
        manifest: &TraceManifestV1,
        operation: &str,
    ) -> Result<UploadResponse> {
        self.write(
            "/v1/uploads",
            operation,
            &json!({"air_package_id":air_package_id,"manifest":manifest}),
        )
    }

    pub fn upload_chunks(&self, upload: &UploadResponse, chunks_dir: &Path) -> Result<()> {
        for chunk in &upload.chunks {
            let path = chunks_dir.join(format!("chunk-{:06}.zst", chunk.index));
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let mut request = self.http.put(&chunk.upload.url).body(bytes);
            for (name, value) in &chunk.upload.headers {
                request = request.header(name, value);
            }
            redact_response(request.send()).context("R2 upload failed")?;
        }
        Ok(())
    }

    pub fn submit_job(
        &self,
        air_package_id: &str,
        upload_id: &str,
        public_inputs: &PublicInputsV1,
        operation: &str,
    ) -> Result<JobStatus> {
        self.write(
            "/v1/proof-jobs",
            operation,
            &json!({
                "air_package_id":air_package_id,"upload_id":upload_id,"public_inputs":public_inputs
            }),
        )
    }

    pub fn status(&self, job_id: &str) -> Result<JobStatus> {
        self.read(&format!("/v1/proof-jobs/{job_id}"))
    }

    pub fn wait(&self, job_id: &str, timeout: Duration) -> Result<JobStatus> {
        let started = std::time::Instant::now();
        loop {
            let status = self.status(job_id)?;
            if TERMINAL.contains(&status.status.as_str()) {
                return Ok(status);
            }
            if started.elapsed() >= timeout {
                bail!("job polling timed out; resume with hc-cli beta status");
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    pub fn cancel(&self, job_id: &str, operation: &str) -> Result<Value> {
        self.write::<Value, _>(
            &format!("/v1/proof-jobs/{job_id}/cancel"),
            operation,
            &json!({}),
        )
    }

    pub fn download(&self, job_id: &str, output: &Path) -> Result<String> {
        let descriptor: Value = self.read(&format!("/v1/proof-jobs/{job_id}/bundle"))?;
        let signed = descriptor
            .get("download")
            .context("bundle response lacks download")?;
        let signed: SignedUrl = serde_json::from_value(signed.clone())?;
        let mut request = self.http.get(&signed.url);
        for (name, value) in signed.headers {
            request = request.header(name, value);
        }
        let bytes = redact_response(request.send())?.bytes()?.to_vec();
        write_owner_file(output, &bytes)?;
        let digest = blake3::hash(&bytes).to_hex().to_string();
        if descriptor.get("blake3_hex").and_then(Value::as_str) != Some(&digest) {
            let _ = fs::remove_file(output);
            bail!("downloaded bundle digest does not match the API response");
        }
        Ok(digest)
    }

    pub fn verify_remote(&self, bundle: &HostedProofBundleV1) -> Result<Value> {
        let response = self
            .http
            .post(format!("{}/v1/verify", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&json!({"bundle":bundle}))
            .send();
        decode(redact_response(response)?)
    }

    pub fn discovery(&self) -> Result<Value> {
        let response = self
            .http
            .get(format!("{}/v1/discovery", self.base_url))
            .send();
        decode(redact_response(response)?)
    }

    fn read<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .http
            .get(format!("{}{path}", self.base_url))
            .bearer_auth(&self.api_key)
            .send();
        decode(redact_response(response)?)
    }

    fn write<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        operation: &str,
        body: &B,
    ) -> Result<T> {
        let response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(&self.api_key)
            .header("Idempotency-Key", operation)
            .json(body)
            .send();
        decode(redact_response(response)?)
    }
}

fn redact_response(response: std::result::Result<Response, reqwest::Error>) -> Result<Response> {
    let response = response
        .map_err(|error| anyhow::anyhow!("network request failed: {}", error.without_url()))?;
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let code = response
        .json::<Value>()
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/code")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "request_failed".into());
    bail!("TinyZKP API returned HTTP {status}: {code}")
}

fn decode<T: DeserializeOwned>(response: Response) -> Result<T> {
    response.json().context("decode TinyZKP API response")
}

pub fn credentials_from_environment_or_file(path: Option<&Path>) -> Result<String> {
    if let Ok(value) = std::env::var("TINYZKP_API_KEY") {
        let value = value.trim().to_owned();
        if !value.is_empty() {
            return Ok(value);
        }
    }
    let path = path.context("set TINYZKP_API_KEY or provide --credentials-file")?;
    ensure_owner_only(path)?;
    let value = fs::read_to_string(path)?.trim().to_owned();
    if value.is_empty() {
        bail!("credentials file is empty");
    }
    Ok(value)
}

pub fn input_digest(paths: &[&Path]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"tinyzkp-beta-submit-input-v1\0");
    for path in paths {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn load_or_create_state(
    path: &Path,
    release_sha: &str,
    input_sha256: &str,
) -> Result<ResumeStateV1> {
    if path.exists() {
        ensure_owner_only(path)?;
        let state: ResumeStateV1 = serde_json::from_slice(&fs::read(path)?)?;
        if state.release_sha != release_sha || state.input_sha256 != input_sha256 {
            bail!("resume state belongs to different inputs or release; no HTTP request was sent");
        }
        Ok(state)
    } else {
        Ok(ResumeStateV1::new(
            release_sha.to_owned(),
            input_sha256.to_owned(),
        ))
    }
}

pub fn save_state(path: &Path, state: &ResumeStateV1) -> Result<()> {
    write_owner_file(path, &serde_json::to_vec_pretty(state)?)
}

pub fn write_owner_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("state")
    ));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn ensure_owner_only(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("credentials/state path must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("credentials/state file must be owner-owned and mode 0600");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_never_serializes_credentials_or_urls() {
        let mut state = ResumeStateV1::new("a".repeat(40), "b".repeat(64));
        state.operation("register");
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("api_key"));
        assert!(!json.contains("http"));
    }

    #[test]
    fn old_state_defaults_upload_attempt_to_zero() {
        let state: ResumeStateV1 = serde_json::from_value(json!({
            "schema_version": 1,
            "release_sha": "a".repeat(40),
            "input_sha256": "b".repeat(64),
            "operations": {},
            "air_package_id": null,
            "upload_id": null,
            "job_id": null,
            "bundle_digest_hex": null
        }))
        .unwrap();
        assert_eq!(state.upload_attempt, 0);
    }
}
