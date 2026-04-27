//! Async HTTP client for the TinyZKP proving API.
//!
//! # Usage
//!
//! ```rust,ignore
//! use tinyzkp::{HcClient, TemplateProveOptions};
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), tinyzkp::Error> {
//!     let client = HcClient::new("https://api.tinyzkp.com")
//!         .with_api_key("tzk_...");
//!
//!     // Prove via a template (recommended).
//!     let job_id = client
//!         .prove_template(
//!             "range_proof",
//!             json!({ "min": 0, "max": 100, "witness_steps": [42, 44] }),
//!             TemplateProveOptions::default(),
//!         )
//!         .await?;
//!
//!     // Poll until ready.
//!     let proof = client.wait_for_proof(&job_id, None).await?;
//!
//!     // Verify (always free).
//!     let result = client.verify(&proof, true).await?;
//!     assert!(result.ok);
//!     Ok(())
//! }
//! ```

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---- Types ----

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBytes {
    pub version: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyResult {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProveRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub block_size: usize,
    pub fri_final_poly_size: usize,
    pub query_count: usize,
    pub lde_blowup_factor: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zk_mask_degree: Option<usize>,
}

impl Default for ProveRequest {
    fn default() -> Self {
        Self {
            program: None,
            workload_id: None,
            initial_acc: 0,
            final_acc: 0,
            block_size: 2,
            fri_final_poly_size: 2,
            query_count: 30,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TemplateProveOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zk: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fri_final_poly_size: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TemplateSummary {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub cost_category: String,
    #[serde(default = "default_backend")]
    pub backend: String,
}

fn default_backend() -> String {
    "vm".to_string()
}

#[derive(Clone, Debug, Deserialize)]
pub struct TemplateListResponse {
    pub templates: Vec<TemplateSummary>,
    pub count: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct ProveSubmitResponse {
    job_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ProveJobStatus {
    Pending,
    Running,
    Succeeded { proof: ProofBytes },
    Failed { error: String },
}

#[derive(Clone, Debug, Serialize)]
struct VerifyRequest<'a> {
    proof: &'a ProofBytes,
    allow_legacy_v2: bool,
}

#[derive(Clone, Debug, Serialize)]
struct TemplateProveBody {
    params: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    zk: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fri_final_poly_size: Option<usize>,
}

// ---- Errors ----

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("prove job failed: {0}")]
    ProveFailed(String),
    #[error("prove job timed out after {0:?}")]
    Timeout(Duration),
}

// ---- Poll options ----

#[derive(Clone, Debug)]
pub struct PollOptions {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for PollOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(300),
        }
    }
}

// ---- Client ----

pub struct HcClient {
    base_url: String,
    client: reqwest::Client,
}

/// Friendly alias matching the marketing name.
pub type TinyZKP = HcClient;

impl HcClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("client build"),
        }
    }

    /// Set the Bearer API key. Returns a new client; previous client is consumed.
    pub fn with_api_key(self, api_key: &str) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        let val = format!("Bearer {api_key}");
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&val).expect("valid header value"),
        );
        Self {
            base_url: self.base_url,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .default_headers(headers)
                .build()
                .expect("client build"),
        }
    }

    /// Override the default 30s request timeout.
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self {
            base_url: self.base_url,
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .expect("client build"),
        }
    }

    async fn handle<T: for<'de> Deserialize<'de>>(
        resp: reqwest::Response,
    ) -> Result<T, Error> {
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(Error::Http { status, message });
        }
        Ok(resp.json().await?)
    }

    /// Check server health.
    pub async fn healthz(&self) -> bool {
        self.client
            .get(format!("{}/healthz", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// List all available proof templates (no auth required).
    pub async fn templates(&self) -> Result<Vec<TemplateSummary>, Error> {
        let resp = self
            .client
            .get(format!("{}/templates", self.base_url))
            .send()
            .await?;
        let parsed: TemplateListResponse = Self::handle(resp).await?;
        Ok(parsed.templates)
    }

    /// Get full template info including parameter schema (no auth required).
    pub async fn template(&self, template_id: &str) -> Result<Value, Error> {
        let resp = self
            .client
            .get(format!("{}/templates/{}", self.base_url, template_id))
            .send()
            .await?;
        Self::handle(resp).await
    }

    /// Verify a proof. Always free; never charges your usage.
    pub async fn verify(
        &self,
        proof: &ProofBytes,
        allow_legacy_v2: bool,
    ) -> Result<VerifyResult, Error> {
        let body = VerifyRequest { proof, allow_legacy_v2 };
        let resp = self
            .client
            .post(format!("{}/verify", self.base_url))
            .json(&body)
            .send()
            .await?;
        Self::handle(resp).await
    }

    /// Submit a raw prove job and return the job_id.
    pub async fn prove(&self, req: ProveRequest) -> Result<String, Error> {
        let resp = self
            .client
            .post(format!("{}/prove", self.base_url))
            .json(&req)
            .send()
            .await?;
        let body: ProveSubmitResponse = Self::handle(resp).await?;
        Ok(body.job_id)
    }

    /// Submit a prove job using a named template. Returns the job_id.
    pub async fn prove_template(
        &self,
        template_id: &str,
        params: Value,
        options: TemplateProveOptions,
    ) -> Result<String, Error> {
        let body = TemplateProveBody {
            params,
            zk: options.zk,
            block_size: options.block_size,
            fri_final_poly_size: options.fri_final_poly_size,
        };
        let resp = self
            .client
            .post(format!("{}/prove/template/{}", self.base_url, template_id))
            .json(&body)
            .send()
            .await?;
        let parsed: ProveSubmitResponse = Self::handle(resp).await?;
        Ok(parsed.job_id)
    }

    /// Get the status of a prove job.
    pub async fn prove_status(&self, job_id: &str) -> Result<ProveJobStatus, Error> {
        let resp = self
            .client
            .get(format!("{}/prove/{}", self.base_url, job_id))
            .send()
            .await?;
        Self::handle(resp).await
    }

    /// Poll a prove job until it completes; return the proof on success.
    pub async fn wait_for_proof(
        &self,
        job_id: &str,
        options: Option<PollOptions>,
    ) -> Result<ProofBytes, Error> {
        let opts = options.unwrap_or_default();
        let deadline = tokio::time::Instant::now() + opts.timeout;

        loop {
            let status = self.prove_status(job_id).await?;
            match status {
                ProveJobStatus::Succeeded { proof } => return Ok(proof),
                ProveJobStatus::Failed { error } => return Err(Error::ProveFailed(error)),
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Timeout(opts.timeout));
            }
            tokio::time::sleep(opts.interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_request_default() {
        let req = ProveRequest::default();
        assert_eq!(req.block_size, 2);
        assert_eq!(req.query_count, 30);
        assert!(req.program.is_none());
    }

    #[test]
    fn prove_request_serializes() {
        let req = ProveRequest {
            program: Some(vec!["add 1".into()]),
            initial_acc: 5,
            final_acc: 6,
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"initial_acc\":5"));
        assert!(json.contains("\"program\":[\"add 1\"]"));
        assert!(!json.contains("zk_mask_degree"));
    }

    #[test]
    fn template_options_omits_none() {
        let opts = TemplateProveOptions::default();
        let json = serde_json::to_string(&opts).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn template_options_includes_set_fields() {
        let opts = TemplateProveOptions {
            zk: Some(true),
            block_size: Some(8),
            fri_final_poly_size: None,
        };
        let json = serde_json::to_string(&opts).unwrap();
        assert!(json.contains("\"zk\":true"));
        assert!(json.contains("\"block_size\":8"));
        assert!(!json.contains("fri_final_poly_size"));
    }

    #[test]
    fn job_status_deserialize_pending() {
        let json = r#"{"status":"pending"}"#;
        let status: ProveJobStatus = serde_json::from_str(json).unwrap();
        assert!(matches!(status, ProveJobStatus::Pending));
    }

    #[test]
    fn job_status_deserialize_failed() {
        let json = r#"{"status":"failed","error":"oom"}"#;
        let status: ProveJobStatus = serde_json::from_str(json).unwrap();
        match status {
            ProveJobStatus::Failed { error } => assert_eq!(error, "oom"),
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn job_status_deserialize_succeeded() {
        let json = r#"{"status":"succeeded","proof":{"version":3,"bytes":[1,2,3]}}"#;
        let status: ProveJobStatus = serde_json::from_str(json).unwrap();
        match status {
            ProveJobStatus::Succeeded { proof } => {
                assert_eq!(proof.version, 3);
                assert_eq!(proof.bytes, vec![1, 2, 3]);
            }
            _ => panic!("expected Succeeded"),
        }
    }

    #[test]
    fn template_summary_defaults_backend() {
        let json = r#"{"id":"range_proof","summary":"x"}"#;
        let t: TemplateSummary = serde_json::from_str(json).unwrap();
        assert_eq!(t.backend, "vm");
        assert!(t.tags.is_empty());
    }
}
