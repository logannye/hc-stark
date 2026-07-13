use anyhow::{bail, Context};
use hc_plonky3::{
    contracts::{
        hosted_charge_millicredits, AirPackageV1, AirProofBundleV1, HostedProofBundleV1,
        HostedResourceReportV1, PublicInputsV1, TraceManifestV1,
    },
    prove_resource_bounded_observed_with_cancellation, resume_resource_bounded_with_cancellation,
    UploadedTraceWorkload,
};
use hc_stream::{CheckpointManifestV2, CheckpointPolicy, ResourceMode, ResourcePolicyV1};
use reqwest::{Client, Method};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    fs,
    io::AsyncWriteExt,
    sync::{mpsc, Mutex, Semaphore},
    task::JoinSet,
};
use uuid::Uuid;

#[derive(Clone)]
struct Config {
    api_url: String,
    worker_id: String,
    credential: String,
    release_sha: String,
    scratch: PathBuf,
    slots: usize,
}

#[derive(Clone)]
struct Worker {
    config: Arc<Config>,
    http: Client,
    draining: Arc<AtomicBool>,
    active: Arc<Mutex<BTreeMap<Uuid, hc_plonky3::CancellationToken>>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseRecord {
    schema_version: u32,
    job_id: Uuid,
    attempt: u32,
    lease_epoch: u64,
    release_sha: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SignedUrl {
    url: String,
    headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ChunkUrl {
    index: u32,
    upload: SignedUrl,
}

#[derive(Clone, Debug, Deserialize)]
struct Claim {
    job_id: Uuid,
    attempt: u32,
    lease_epoch: u64,
    air: AirPackageV1,
    manifest: TraceManifestV1,
    public_inputs: PublicInputsV1,
    input_chunks: Vec<ChunkUrl>,
}

#[derive(Serialize)]
struct ClaimRequest<'a> {
    release_sha: &'a str,
    free_scratch_bytes: u64,
}

#[derive(Serialize)]
struct DrainingRequest<'a> {
    release_sha: &'a str,
    draining: bool,
}

#[derive(Serialize)]
struct StartupLeaseRequest<'a> {
    job_id: Uuid,
    attempt: u32,
    lease_epoch: u64,
    release_sha: &'a str,
    checkpoint_identity: &'a str,
}

#[derive(Serialize)]
struct HeartbeatRequest {
    attempt: u32,
    lease_epoch: u64,
    free_scratch_bytes: u64,
    progress: Option<Value>,
    checkpoint_identity: Option<String>,
}

#[derive(Deserialize)]
struct HeartbeatResponse {
    cancel_requested: bool,
}

#[derive(Deserialize)]
struct FailureResponse {
    status: String,
}

#[derive(Serialize)]
struct OutputRequest<'a> {
    attempt: u32,
    lease_epoch: u64,
    content_length: u64,
    blake3_hex: &'a str,
}

#[derive(Deserialize)]
struct OutputResponse {
    object_key: String,
    upload: SignedUrl,
}

#[derive(Serialize)]
struct CompleteRequest<'a> {
    attempt: u32,
    lease_epoch: u64,
    object_key: &'a str,
    content_length: u64,
    blake3_hex: &'a str,
}

#[derive(Serialize)]
struct FailureRequest<'a> {
    attempt: u32,
    lease_epoch: u64,
    code: &'a str,
    retryable: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let config = Arc::new(Config::from_env()?);
    let worker = Worker {
        config: config.clone(),
        http: Client::builder().timeout(Duration::from_secs(60)).build()?,
        draining: Arc::new(AtomicBool::new(false)),
        active: Arc::new(Mutex::new(BTreeMap::new())),
    };
    prepare_scratch(&config.scratch).await?;
    let slots = Arc::new(Semaphore::new(config.slots));
    let mut tasks = JoinSet::new();
    for claim in worker.reconcile_startup().await? {
        spawn_claim(&mut tasks, slots.clone(), worker.clone(), claim).await?;
    }
    worker.set_draining(false).await?;
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                tracing::error!(%error, "worker job task panicked");
            }
        }
        if slots.available_permits() == 0 {
            tokio::select! {
                _ = shutdown_signal() => break,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            continue;
        }
        let claim = tokio::select! {
            _ = shutdown_signal() => break,
            result = worker.claim() => result,
        };
        match claim {
            Ok(Some(claim)) => {
                spawn_claim(&mut tasks, slots.clone(), worker.clone(), claim).await?;
            }
            Ok(None) => tokio::select! {
                _ = shutdown_signal() => break,
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            },
            Err(error) => {
                tracing::warn!(%error, "lease claim failed");
                tokio::select! {
                    _ = shutdown_signal() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    }
    worker.drain(&mut tasks).await;
    Ok(())
}

async fn spawn_claim(
    tasks: &mut JoinSet<()>,
    slots: Arc<Semaphore>,
    worker: Worker,
    claim: Claim,
) -> anyhow::Result<()> {
    let permit = slots.acquire_owned().await?;
    tasks.spawn(async move {
        let _permit = permit;
        if let Err(error) = worker.run_job(claim).await {
            tracing::error!(error=?error, "hosted proof job failed");
        }
    });
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("install interrupt handler");
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let slots = optional("TINYZKP_WORKER_SLOTS", "4").parse::<usize>()?;
        if !(1..=4).contains(&slots) {
            bail!("TINYZKP_WORKER_SLOTS must be between 1 and 4");
        }
        let release_sha = required("HC_RELEASE_SHA")?;
        if release_sha.len() != 40 {
            bail!("HC_RELEASE_SHA must be a full Git SHA");
        }
        Ok(Self {
            api_url: required("TINYZKP_WORKER_API_URL")?
                .trim_end_matches('/')
                .to_owned(),
            worker_id: required("TINYZKP_WORKER_ID")?,
            credential: required("TINYZKP_WORKER_CREDENTIAL")?,
            release_sha,
            scratch: PathBuf::from(optional("TINYZKP_WORKER_SCRATCH", "/scratch/tinyzkp")),
            slots,
        })
    }
}

impl Worker {
    async fn set_draining(&self, draining: bool) -> anyhow::Result<()> {
        let _: Value = tokio::time::timeout(
            Duration::from_secs(3),
            self.json(
                Method::POST,
                "/internal/v1/workers/draining",
                &DrainingRequest {
                    release_sha: &self.config.release_sha,
                    draining,
                },
            ),
        )
        .await
        .context("worker draining update timed out")??;
        Ok(())
    }

    async fn drain(&self, tasks: &mut JoinSet<()>) {
        let drain_complete = Arc::new(AtomicBool::new(false));
        let watchdog_complete = drain_complete.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(75));
            if !watchdog_complete.load(Ordering::Acquire) {
                // A cancelled spawn_blocking task can otherwise keep Tokio's
                // runtime destructor alive past the container stop deadline.
                std::process::exit(0);
            }
        });
        self.draining.store(true, Ordering::Release);
        if let Err(error) = self.set_draining(true).await {
            tracing::warn!(%error, "failed to publish worker draining state");
        }
        let active = self.active.lock().await;
        for cancellation in active.values() {
            cancellation.cancel();
        }
        drop(active);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(70);
        while !tasks.is_empty() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                tracing::error!(
                    active_tasks = tasks.len(),
                    "worker drain deadline exhausted"
                );
                tasks.abort_all();
                break;
            }
            match tokio::time::timeout(remaining, tasks.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(error))) => tracing::warn!(%error, "worker job stopped during drain"),
                Ok(None) => break,
                Err(_) => {
                    tracing::error!(active_tasks = tasks.len(), "worker drain timed out");
                    tasks.abort_all();
                    break;
                }
            }
        }
        drain_complete.store(true, Ordering::Release);
        tracing::info!("worker drain complete");
    }

    async fn reconcile_startup(&self) -> anyhow::Result<Vec<Claim>> {
        let mut recovered = Vec::new();
        #[cfg(unix)]
        let scratch_uid = {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(&self.config.scratch).await?.uid()
        };
        let mut entries = fs::read_dir(&self.config.scratch).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).await?;
            let job_id = entry
                .file_name()
                .to_str()
                .and_then(|name| Uuid::parse_str(name).ok());
            if metadata.file_type().is_symlink() || !metadata.is_dir() || job_id.is_none() {
                remove_entry_without_following(&path, &metadata).await?;
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.permissions().mode() & 0o777 != 0o700 || metadata.uid() != scratch_uid {
                    fs::remove_dir_all(&path).await?;
                    continue;
                }
            }
            let lease_path = path.join("lease.json");
            let lease_metadata = match fs::symlink_metadata(&lease_path).await {
                Ok(value) if value.is_file() && !value.file_type().is_symlink() => value,
                _ => {
                    fs::remove_dir_all(&path).await?;
                    continue;
                }
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if lease_metadata.permissions().mode() & 0o777 != 0o600 {
                    fs::remove_dir_all(&path).await?;
                    continue;
                }
            }
            let lease: LeaseRecord = serde_json::from_slice(&fs::read(&lease_path).await?)?;
            if lease.schema_version != 1
                || Some(lease.job_id) != job_id
                || lease.release_sha != self.config.release_sha
            {
                fs::remove_dir_all(&path).await?;
                continue;
            }
            let Some((_, checkpoint_identity)) = checkpoint(&path)? else {
                fs::remove_dir_all(&path).await?;
                continue;
            };
            let response = self
                .json::<_, Option<Claim>>(
                    Method::POST,
                    "/internal/v1/leases/startup-validate",
                    &StartupLeaseRequest {
                        job_id: lease.job_id,
                        attempt: lease.attempt,
                        lease_epoch: lease.lease_epoch,
                        release_sha: &lease.release_sha,
                        checkpoint_identity: &checkpoint_identity,
                    },
                )
                .await;
            match response {
                Ok(Some(claim)) => recovered.push(claim),
                Ok(None) => fs::remove_dir_all(&path).await?,
                Err(error) => {
                    tracing::warn!(%error, path=%path.display(), "startup lease validation failed closed");
                    fs::remove_dir_all(&path).await?;
                }
            }
        }
        Ok(recovered)
    }

    async fn claim(&self) -> anyhow::Result<Option<Claim>> {
        self.json(
            Method::POST,
            "/internal/v1/leases/claim",
            &ClaimRequest {
                release_sha: &self.config.release_sha,
                free_scratch_bytes: free_space(&self.config.scratch)?,
            },
        )
        .await
    }

    async fn run_job(&self, claim: Claim) -> anyhow::Result<()> {
        let job_dir = self.config.scratch.join(claim.job_id.to_string());
        private_dir(&job_dir).await?;
        write_lease(&job_dir, &claim, &self.config.release_sha).await?;
        let chunks_dir = job_dir.join("chunks");
        private_dir(&chunks_dir).await?;
        let cancellation = hc_plonky3::CancellationToken::new();
        self.active
            .lock()
            .await
            .insert(claim.job_id, cancellation.clone());
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<Value>();
        let endpoint = format!("/internal/v1/jobs/{}/heartbeat", claim.job_id);
        let initial: anyhow::Result<HeartbeatResponse> = self
            .json(
                Method::POST,
                &endpoint,
                &HeartbeatRequest {
                    attempt: claim.attempt,
                    lease_epoch: claim.lease_epoch,
                    free_scratch_bytes: free_space(&self.config.scratch).unwrap_or(0),
                    progress: Some(json!({"event":"lease_claimed"})),
                    checkpoint_identity: checkpoint(&job_dir)
                        .ok()
                        .flatten()
                        .map(|(_, identity)| identity),
                },
            )
            .await;
        let mut heartbeat = None;
        let result = match initial {
            Err(error) => Err(error.context("initial lease heartbeat failed")),
            Ok(initial) => {
                if initial.cancel_requested {
                    cancellation.cancel();
                }
                let heartbeat_token = cancellation.clone();
                let heartbeat_worker = self.clone();
                let heartbeat_claim = (claim.job_id, claim.attempt, claim.lease_epoch);
                let heartbeat_job_dir = job_dir.to_path_buf();
                heartbeat = Some(tokio::spawn(async move {
                    let mut latest = None;
                    loop {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        while let Ok(progress) = progress_rx.try_recv() {
                            latest = Some(progress);
                        }
                        let endpoint = format!("/internal/v1/jobs/{}/heartbeat", heartbeat_claim.0);
                        let response = heartbeat_worker
                            .json::<_, HeartbeatResponse>(
                                Method::POST,
                                &endpoint,
                                &HeartbeatRequest {
                                    attempt: heartbeat_claim.1,
                                    lease_epoch: heartbeat_claim.2,
                                    free_scratch_bytes: free_space(
                                        &heartbeat_worker.config.scratch,
                                    )
                                    .unwrap_or(0),
                                    progress: latest.take(),
                                    checkpoint_identity: checkpoint(&heartbeat_job_dir)
                                        .ok()
                                        .flatten()
                                        .map(|(_, identity)| identity),
                                },
                            )
                            .await;
                        match response {
                            Ok(response) if response.cancel_requested => {
                                heartbeat_token.cancel();
                                break;
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::warn!(%error, "heartbeat failed; cancelling local prover");
                                heartbeat_token.cancel();
                                break;
                            }
                        }
                    }
                }));
                if cancellation.is_cancelled() {
                    Err(anyhow::anyhow!("operation cancelled"))
                } else {
                    self.execute(&claim, &job_dir, &chunks_dir, cancellation, progress_tx)
                        .await
                }
            }
        };
        if let Some(heartbeat) = heartbeat {
            heartbeat.abort();
        }
        self.active.lock().await.remove(&claim.job_id);
        if self.draining.load(Ordering::Acquire) && result.is_err() {
            if let Ok(Some((_, checkpoint_identity))) = checkpoint(&job_dir) {
                let endpoint = format!("/internal/v1/jobs/{}/heartbeat", claim.job_id);
                let _: HeartbeatResponse = self
                    .json(
                        Method::POST,
                        &endpoint,
                        &HeartbeatRequest {
                            attempt: claim.attempt,
                            lease_epoch: claim.lease_epoch,
                            free_scratch_bytes: free_space(&self.config.scratch).unwrap_or(0),
                            progress: Some(json!({"event":"worker_draining"})),
                            checkpoint_identity: Some(checkpoint_identity),
                        },
                    )
                    .await?;
                return Ok(());
            }
            let endpoint = format!("/internal/v1/jobs/{}/failure", claim.job_id);
            let _: Value = self
                .json(
                    Method::POST,
                    &endpoint,
                    &FailureRequest {
                        attempt: claim.attempt,
                        lease_epoch: claim.lease_epoch,
                        code: "worker_shutdown_before_checkpoint",
                        retryable: false,
                    },
                )
                .await?;
            if let Err(error) = fs::remove_dir_all(&job_dir).await {
                tracing::warn!(%error, path=%job_dir.display(), "scratch cleanup failed");
            }
            return Ok(());
        }
        let mut retain_retry_scratch = false;
        if let Err(error) = &result {
            let code = classify_error(error);
            let action = if code == "cancelled" {
                "cancelled"
            } else {
                "failure"
            };
            let endpoint = format!("/internal/v1/jobs/{}/{action}", claim.job_id);
            match self
                .json::<_, FailureResponse>(
                    Method::POST,
                    &endpoint,
                    &FailureRequest {
                        attempt: claim.attempt,
                        lease_epoch: claim.lease_epoch,
                        code,
                        retryable: matches!(code, "network" | "platform_io" | "prover_interrupted"),
                    },
                )
                .await
            {
                Ok(response) => {
                    retain_retry_scratch = should_retain_retry_scratch(&response.status)
                }
                Err(report_error) => {
                    tracing::warn!(%report_error, "failed to report hosted job failure")
                }
            }
        }
        if !retain_retry_scratch {
            if let Err(error) = fs::remove_dir_all(&job_dir).await {
                tracing::warn!(%error, path=%job_dir.display(), "scratch cleanup failed");
            }
        }
        result
    }

    async fn execute(
        &self,
        claim: &Claim,
        job_dir: &Path,
        chunks_dir: &Path,
        cancellation: hc_plonky3::CancellationToken,
        progress_tx: mpsc::UnboundedSender<Value>,
    ) -> anyhow::Result<()> {
        claim.air.validate().map_err(anyhow::Error::msg)?;
        claim
            .manifest
            .validate_for_air(&claim.air)
            .map_err(anyhow::Error::msg)?;
        claim
            .public_inputs
            .validate_for_air(&claim.air)
            .map_err(anyhow::Error::msg)?;
        if claim.input_chunks.len() != claim.manifest.chunks.len() {
            bail!("input chunk count mismatch");
        }
        let mut downloaded = 0u64;
        for (expected, signed) in claim.manifest.chunks.iter().zip(&claim.input_chunks) {
            if cancellation.is_cancelled() {
                bail!("operation cancelled");
            }
            if expected.index != signed.index {
                bail!("input chunk order mismatch");
            }
            let path = chunks_dir.join(format!("chunk-{:06}.zst", expected.index));
            download_exact(
                &self.http,
                &signed.upload,
                &path,
                expected.compressed_bytes,
                &expected.blake3_hex,
                &cancellation,
            )
            .await?;
            downloaded = downloaded.saturating_add(expected.compressed_bytes);
        }
        let workload = UploadedTraceWorkload::new(
            claim.air.clone(),
            claim.manifest.clone(),
            claim.public_inputs.values.clone(),
            chunks_dir,
        )
        .map_err(anyhow::Error::msg)?;
        let policy = ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 2 * 1024 * 1024 * 1024,
            max_scratch_bytes: free_space(&self.config.scratch)?.saturating_mul(70) / 100,
            scratch_dir: job_dir.join("prover"),
            max_threads: 2,
            checkpoint_policy: CheckpointPolicy::RetainOnFailure,
        };
        private_dir(&policy.scratch_dir).await?;
        let started = Instant::now();
        let air = claim.air.clone();
        let manifest = claim.manifest.clone();
        let public_inputs = claim.public_inputs.clone();
        let resume = checkpoint(job_dir)?.map(|(path, _)| path);
        let prover_cancellation = cancellation.clone();
        let proof = tokio::task::spawn_blocking(move || {
            if let Some(checkpoint) = resume {
                resume_resource_bounded_with_cancellation(
                    &checkpoint,
                    &workload,
                    prover_cancellation,
                )
            } else {
                prove_resource_bounded_observed_with_cancellation(
                    &workload,
                    &policy,
                    prover_cancellation,
                    |event| {
                        let _ = progress_tx.send(
                            serde_json::to_value(event)
                                .unwrap_or_else(|_| json!({"event":"progress_encoding_failed"})),
                        );
                    },
                )
            }
        })
        .await
        .context("prover task panicked")?;
        let proof = proof.map_err(anyhow::Error::msg)?;
        if cancellation.is_cancelled() {
            bail!("operation cancelled");
        }
        let proof_bundle = AirProofBundleV1::from_proof(
            air,
            manifest,
            public_inputs,
            proof,
            self.config.release_sha.clone(),
        )
        .map_err(anyhow::Error::msg)?;
        proof_bundle.verify().map_err(anyhow::Error::msg)?;
        let wall_time_ms = started.elapsed().as_millis().max(1) as u64;
        let scratch = directory_size(job_dir).await?;
        let resource_report = HostedResourceReportV1 {
            peak_resident_bytes: peak_rss_bytes().unwrap_or(1),
            scratch_high_water_bytes: scratch,
            total_read_bytes: downloaded,
            total_write_bytes: scratch,
            wall_time_ms,
        };
        let hosted = HostedProofBundleV1 {
            schema_version: 1,
            proof: proof_bundle,
            charge_millicredits: hosted_charge_millicredits(&resource_report),
            resource_report,
            official_verification: true,
        };
        hosted.verify().map_err(anyhow::Error::msg)?;
        let bytes = serde_json::to_vec(&hosted)?;
        let digest = hex::encode(blake3::hash(&bytes).as_bytes());
        let endpoint = format!("/internal/v1/jobs/{}/output-url", claim.job_id);
        let output = self
            .json::<_, OutputResponse>(
                Method::POST,
                &endpoint,
                &OutputRequest {
                    attempt: claim.attempt,
                    lease_epoch: claim.lease_epoch,
                    content_length: bytes.len() as u64,
                    blake3_hex: &digest,
                },
            )
            .await?;
        upload_exact(&self.http, &output.upload, bytes).await?;
        let endpoint = format!("/internal/v1/jobs/{}/complete", claim.job_id);
        let _: Value = self
            .json(
                Method::POST,
                &endpoint,
                &CompleteRequest {
                    attempt: claim.attempt,
                    lease_epoch: claim.lease_epoch,
                    object_key: &output.object_key,
                    content_length: hosted_json_size(&hosted)?,
                    blake3_hex: &digest,
                },
            )
            .await?;
        Ok(())
    }

    async fn json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: &T,
    ) -> anyhow::Result<R> {
        self.http
            .request(method, format!("{}{}", self.config.api_url, path))
            .header(
                "Authorization",
                format!("Bearer {}", self.config.credential),
            )
            .header("x-tinyzkp-worker-id", &self.config.worker_id)
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }
}

async fn download_exact(
    http: &Client,
    signed: &SignedUrl,
    path: &Path,
    expected: u64,
    digest: &str,
    cancellation: &hc_plonky3::CancellationToken,
) -> anyhow::Result<()> {
    if cancellation.is_cancelled() {
        bail!("operation cancelled");
    }
    let mut request = http.get(&signed.url);
    for (name, value) in &signed.headers {
        request = request.header(name, value);
    }
    let mut response = request.send().await?.error_for_status()?;
    if response.content_length() != Some(expected) {
        bail!("input content length mismatch");
    }
    let temporary = path.with_extension("part");
    let mut file = fs::File::create(&temporary).await?;
    let mut total = 0u64;
    let mut hasher = blake3::Hasher::new();
    while let Some(chunk) = response.chunk().await? {
        if cancellation.is_cancelled() {
            bail!("operation cancelled");
        }
        total = total.saturating_add(chunk.len() as u64);
        if total > expected {
            bail!("input chunk exceeded signed length");
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    if total != expected || hex::encode(hasher.finalize().as_bytes()) != digest {
        bail!("input chunk digest mismatch");
    }
    fs::rename(temporary, path).await?;
    Ok(())
}

async fn upload_exact(http: &Client, signed: &SignedUrl, bytes: Vec<u8>) -> anyhow::Result<()> {
    let mut request = http.put(&signed.url);
    for (name, value) in &signed.headers {
        request = request.header(name, value);
    }
    request.body(bytes).send().await?.error_for_status()?;
    Ok(())
}

async fn write_lease(job_dir: &Path, claim: &Claim, release_sha: &str) -> anyhow::Result<()> {
    let path = job_dir.join("lease.json");
    let temporary = job_dir.join(".lease.json.tmp");
    let bytes = serde_json::to_vec(&LeaseRecord {
        schema_version: 1,
        job_id: claim.job_id,
        attempt: claim.attempt,
        lease_epoch: claim.lease_epoch,
        release_sha: release_sha.to_owned(),
    })?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = match options.open(&temporary).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary).await?;
            options.open(&temporary).await?
        }
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await?;
    }
    file.write_all(&bytes).await?;
    file.sync_all().await?;
    fs::rename(temporary, path).await?;
    Ok(())
}

fn checkpoint(job_dir: &Path) -> anyhow::Result<Option<(PathBuf, String)>> {
    let prover = job_dir.join("prover");
    let mut found = None;
    let entries = match std::fs::read_dir(&prover) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_bounded_prover_directory(&name) {
            continue;
        }
        let path = entry.path().join("checkpoint.json");
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(value) if value.is_file() && !value.file_type().is_symlink() => value,
            _ => continue,
        };
        if metadata.len() == 0 {
            continue;
        }
        let manifest = CheckpointManifestV2::read(&path)?;
        manifest.validate_artifacts(entry.path())?;
        let bytes = std::fs::read(&path)?;
        let identity = hex::encode(blake3::hash(&bytes).as_bytes());
        if found.replace((path, identity)).is_some() {
            bail!("multiple resumable checkpoints found for one hosted job");
        }
    }
    Ok(found)
}

fn is_bounded_prover_directory(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("bounded-prover-") else {
        return false;
    };
    let mut parts = rest.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(process), Some(counter), None)
            if process.parse::<u32>().is_ok() && counter.parse::<u64>().is_ok()
    )
}

fn should_retain_retry_scratch(status: &str) -> bool {
    status == "queued"
}

async fn remove_entry_without_following(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).await?;
    } else {
        fs::remove_file(path).await?;
    }
    Ok(())
}

async fn prepare_scratch(path: &Path) -> anyhow::Result<()> {
    private_dir(path).await?;
    Ok(())
}

async fn private_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

fn free_space(path: &Path) -> anyhow::Result<u64> {
    let output = std::process::Command::new("df")
        .args(["-Pk", path.to_str().context("scratch path encoding")?])
        .output()?;
    if !output.status.success() {
        bail!("df failed");
    }
    let line = String::from_utf8(output.stdout)?
        .lines()
        .last()
        .context("df output missing")?
        .to_owned();
    let blocks = line
        .split_whitespace()
        .nth(3)
        .context("df available blocks missing")?
        .parse::<u64>()?;
    Ok(blocks.saturating_mul(1024))
}

async fn directory_size(path: &Path) -> anyhow::Result<u64> {
    let output = tokio::process::Command::new("du")
        .args(["-sk", path.to_str().context("scratch path encoding")?])
        .output()
        .await?;
    if !output.status.success() {
        bail!("du failed");
    }
    let blocks = String::from_utf8(output.stdout)?
        .split_whitespace()
        .next()
        .context("du output missing")?
        .parse::<u64>()?;
    Ok(blocks.saturating_mul(1024))
}

fn peak_rss_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = text.lines().find_map(|line| {
        line.strip_prefix("VmHWM:")?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    })?;
    Some(kb.saturating_mul(1024))
}

fn hosted_json_size(bundle: &HostedProofBundleV1) -> anyhow::Result<u64> {
    Ok(serde_json::to_vec(bundle)?.len() as u64)
}

fn classify_error(error: &anyhow::Error) -> &'static str {
    let message = error.to_string().to_lowercase();
    if message.contains("cancel") {
        "cancelled"
    } else if message.contains("digest") || message.contains("shape") {
        "invalid_customer_artifact"
    } else if message.contains("http") || message.contains("network") {
        "network"
    } else if message.contains("space") || message.contains("io") {
        "platform_io"
    } else {
        "prover_interrupted"
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        bail!("{name} is empty");
    }
    Ok(value.trim().to_owned())
}

fn optional(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("tinyzkp-worker-test-{}", Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_worker(scratch: PathBuf) -> Worker {
        Worker {
            config: Arc::new(Config {
                api_url: "http://127.0.0.1:9".into(),
                worker_id: "test-worker".into(),
                credential: "test-credential".into(),
                release_sha: "a".repeat(40),
                scratch,
                slots: 4,
            }),
            http: Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .unwrap(),
            draining: Arc::new(AtomicBool::new(false)),
            active: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[tokio::test]
    async fn idle_drain_finishes_well_below_container_deadline() {
        let directory = TestDir::new();
        let worker = test_worker(directory.path().to_path_buf());
        let mut tasks = JoinSet::new();
        let started = Instant::now();
        worker.drain(&mut tasks).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(worker.draining.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn active_drain_cancels_owned_job_and_joins_it() {
        let directory = TestDir::new();
        let worker = test_worker(directory.path().to_path_buf());
        let cancellation = hc_plonky3::CancellationToken::new();
        worker
            .active
            .lock()
            .await
            .insert(Uuid::new_v4(), cancellation.clone());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            while !cancellation.is_cancelled() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let started = Instant::now();
        worker.drain(&mut tasks).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn startup_removes_non_uuid_and_incomplete_uuid_directories() {
        let directory = TestDir::new();
        private_dir(directory.path()).await.unwrap();
        let worker = test_worker(directory.path().to_path_buf());
        let non_uuid = directory.path().join("unexpected");
        private_dir(&non_uuid).await.unwrap();
        let incomplete = directory.path().join(Uuid::new_v4().to_string());
        private_dir(&incomplete).await.unwrap();

        assert!(worker.reconcile_startup().await.unwrap().is_empty());
        assert!(!non_uuid.exists());
        assert!(!incomplete.exists());
    }

    #[tokio::test]
    async fn cancelled_input_download_stops_before_network_io() {
        let directory = TestDir::new();
        let cancellation = hc_plonky3::CancellationToken::new();
        cancellation.cancel();
        let error = download_exact(
            &Client::new(),
            &SignedUrl {
                url: "http://127.0.0.1:9/unreachable".into(),
                headers: BTreeMap::new(),
            },
            &directory.path().join("chunk.zst"),
            1,
            &"0".repeat(64),
            &cancellation,
        )
        .await
        .unwrap_err();
        assert_eq!(classify_error(&error), "cancelled");
        assert!(!directory.path().join("chunk.zst").exists());
    }

    #[test]
    fn customer_cancellation_is_not_confused_with_platform_io() {
        assert_eq!(
            classify_error(&anyhow::anyhow!("operation cancelled")),
            "cancelled"
        );
        assert_eq!(
            classify_error(&anyhow::anyhow!("network HTTP failed")),
            "network"
        );
    }

    #[test]
    fn checkpoint_discovery_accepts_only_bounded_prover_directories() {
        assert!(is_bounded_prover_directory("bounded-prover-1-5"));
        assert!(is_bounded_prover_directory(
            "bounded-prover-4294967295-18446744073709551615"
        ));
        for invalid in [
            "bounded-prover",
            "bounded-prover-1",
            "bounded-prover-1-2-extra",
            "bounded-prover-pid-2",
            "../bounded-prover-1-2",
            "550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert!(!is_bounded_prover_directory(invalid), "{invalid}");
        }
    }

    #[test]
    fn only_requeued_failures_retain_retry_scratch() {
        assert!(should_retain_retry_scratch("queued"));
        for terminal in [
            "platform_failed",
            "customer_failed",
            "cancelled",
            "completed",
        ] {
            assert!(!should_retain_retry_scratch(terminal), "{terminal}");
        }
    }

    #[test]
    fn checkpoint_discovery_finds_the_prover_runtime_directory() {
        let directory = TestDir::new();
        let prover = directory.path().join("prover/bounded-prover-123-4");
        std::fs::create_dir_all(&prover).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&prover, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        CheckpointManifestV2 {
            schema_version: 2,
            backend_hash: [1; 32],
            profile_hash: [2; 32],
            release_hash: [3; 32],
            dependency_lock_hash: [4; 32],
            workload_hash: [5; 32],
            input_hash: [6; 32],
            resource_policy_hash: [7; 32],
            completed_phase: hc_stream::PipelinePhaseV1::Trace,
            challenger_state: vec![],
            resume_payload: vec![],
            artifacts: vec![],
        }
        .write_atomic(prover.join("checkpoint.json"))
        .unwrap();

        let (path, identity) = checkpoint(directory.path()).unwrap().unwrap();
        assert_eq!(path, prover.join("checkpoint.json"));
        assert_eq!(identity.len(), 64);
    }
}
