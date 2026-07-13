use crate::{models::*, AppState};
use axum::{extract::State, Json};
use hc_plonky3::contracts::{
    AirPackageV1, AirProofBundleV1, HostedProofBundleV1, PublicInputsV1, TraceManifestV1,
};
use serde_json::{json, Map, Value};

fn schema<T: schemars::JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("JSON Schema serializes")
}

fn error_responses(success_status: &str, success: Value) -> Value {
    let mut responses = json!({
        "400": {"$ref":"#/components/responses/Error"},
        "401": {"$ref":"#/components/responses/Error"},
        "402": {"$ref":"#/components/responses/Error"},
        "404": {"$ref":"#/components/responses/Error"},
        "409": {"$ref":"#/components/responses/Error"},
        "422": {"$ref":"#/components/responses/Error"},
        "429": {"$ref":"#/components/responses/Error"},
        "503": {"$ref":"#/components/responses/Error"}
    });
    responses[success_status] = success;
    responses
}

fn operation(
    summary: &str,
    description: &str,
    write: bool,
    authenticated: bool,
    request_schema: Option<&str>,
    response_schema: &str,
    success_status: &str,
) -> Value {
    let mut value = json!({
        "summary": summary,
        "description": description,
        "security": if authenticated { json!([{"apiKey": []}, {"dashboardSession": []}]) } else { json!([]) },
        "responses": error_responses(success_status, json!({
            "description":"Success",
            "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{response_schema}")}}}
        }))
    });
    if write {
        value["parameters"] = json!([{"$ref":"#/components/parameters/IdempotencyKey"}]);
    }
    if let Some(name) = request_schema {
        value["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{name}")}}}});
    }
    value
}

fn path_parameter() -> Value {
    json!({"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}})
}

pub fn contract(release_sha: &str) -> Value {
    let mut paths = Map::new();
    paths.insert("/v1/auth/github/start".into(), json!({"get":{
        "summary":"Start GitHub OAuth with state and PKCE","security":[],
        "parameters":[{"name":"return_path","in":"query","schema":{"type":"string","default":"/dashboard"}}],
        "responses":{"307":{"description":"Redirect to GitHub"},"503":{"$ref":"#/components/responses/Error"}}
    }}));
    paths.insert("/v1/auth/github/callback".into(), json!({"get":{
        "summary":"Complete one-use GitHub OAuth callback","security":[],
        "parameters":[{"name":"code","in":"query","required":true,"schema":{"type":"string"}},{"name":"state","in":"query","required":true,"schema":{"type":"string"}}],
        "responses":{"303":{"description":"Secure dashboard session created"},"401":{"$ref":"#/components/responses/Error"}}
    }}));
    paths.insert(
        "/v1/me".into(),
        json!({"get":operation("Get plan, balance, and freeze state","Returns separate subscription, purchased, and reserved balances plus the nonfungible Sandbox entitlement.",false,true,None,"MeResponse","200")}),
    );
    paths.insert("/v1/api-keys".into(), json!({
        "get":operation("List API-key prefixes","Returns at most 100 key records; raw key material is never returned.",false,true,None,"ApiKeyListResponse","200"),
        "post":operation("Create an API key; the secret is returned once","The first response includes the secret. An exact idempotent replay returns key=null.",true,true,Some("CreateApiKeyRequest"),"ApiKeyResponse","201")
    }));
    paths.insert("/v1/api-keys/{id}".into(), json!({"delete":{
        "summary":"Revoke an API key immediately","security":[{"apiKey":[]},{"dashboardSession":[]}],
        "parameters":[path_parameter(),{"$ref":"#/components/parameters/IdempotencyKey"}],"responses":error_responses("200",json!({"description":"Revoked","content":{"application/json":{"schema":{"$ref":"#/components/schemas/RevokeApiKeyResponse"}}}}))
    }}));
    paths.insert("/v1/account".into(), json!({"delete":operation("Delete the account and queue retained artifacts for deletion","Fails while a job is active. Sessions and API keys are revoked; immutable accounting records are pseudonymized and retained.",true,true,None,"DeleteAccountResponse","200")}));
    paths.insert("/v1/air-packages".into(), json!({"post":operation("Register an AIR after verifying its 1,024-row local proof","Goldilocks and Plonky3 0.6.1 only: degree <=3, <=256 columns, <=1,024 constraints, and <=8,192 expression nodes.",true,true,Some("RegisterAirRequest"),"RegisterAirResponse","201")}));
    paths.insert("/v1/uploads".into(), json!({"post":operation("Create exact-length and checksum-bound R2 chunk uploads","Trace rows must be a power of two from 2^10 through 2^24. Uploads are <=8 GiB compressed and <=32 GiB expanded; signed URLs expire after 15 minutes.",true,true,Some("CreateUploadRequest"),"CreateUploadResponse","201")}));
    paths.insert("/v1/proof-jobs".into(), json!({
        "get":operation("List recent jobs","Returns at most 100 jobs in descending creation order.",false,true,None,"JobListResponse","200"),
        "post":operation("Validate upload, reserve 125% of quote, and queue a job","Rejects predicted RSS above 2 GiB, wall time above 60 minutes, or scratch above 70% of worker free space. Status transitions are queued -> leased -> proving -> verifying -> completed; cancellation and failures are terminal.",true,true,Some("CreateJobRequest"),"CreateJobResponse","201")
    }));
    paths.insert("/v1/proof-jobs/{id}".into(), json!({"get":{
        "summary":"Get job status, resources, cost, charge, and progress","security":[{"apiKey":[]},{"dashboardSession":[]}],
        "parameters":[path_parameter()],"responses":error_responses("200",json!({"description":"Job","content":{"application/json":{"schema":{"$ref":"#/components/schemas/JobResponse"}}}}))
    }}));
    paths.insert("/v1/proof-jobs/{id}/cancel".into(), json!({"post":{
        "summary":"Cancel idempotently; queued work releases its full reservation","security":[{"apiKey":[]},{"dashboardSession":[]}],
        "parameters":[path_parameter(),{"$ref":"#/components/parameters/IdempotencyKey"}],
        "responses":error_responses("200",json!({"description":"Cancellation state","content":{"application/json":{"schema":{"$ref":"#/components/schemas/CancelJobResponse"}}}}))
    }}));
    paths.insert("/v1/proof-jobs/{id}/bundle".into(), json!({"get":{
        "summary":"Authorize and issue a five-minute proof-bundle download","security":[{"apiKey":[]},{"dashboardSession":[]}],
        "parameters":[path_parameter()],"responses":error_responses("200",json!({"description":"Signed download","content":{"application/json":{"schema":{"$ref":"#/components/schemas/BundleResponse"}}}}))
    }}));
    paths.insert("/v1/verify".into(), json!({"post":operation("Verify a pinned dynamic-AIR hosted proof for free","Public and rate-limited. Accepts only the exact hosted proof contract for this release.",false,false,Some("VerifyRequest"),"VerifyResponse","200")}));
    paths.insert("/v1/billing/checkout-sessions".into(), json!({"post":operation("Create Stripe-hosted prepaid or subscription Checkout","SKU selection is server-side. Checkout uses automatic tax and requires a billing address. No automatic overages.",true,true,Some("CheckoutRequest"),"RedirectResponse","201")}));
    paths.insert("/v1/billing/portal-sessions".into(), json!({"post":operation("Open the isolated Stripe Customer Portal","Portal permits invoices, payment-method changes, and cancellation at period end; plan switching is disabled.",true,true,Some("PortalRequest"),"RedirectResponse","201")}));

    json!({
        "openapi":"3.1.0",
        "info":{"title":"TinyZKP Paid Public Beta API","version":release_sha,
            "description":"Prepaid self-service proving. Public beta; no SLA; not independently audited. Stable error codes are documented at https://tinyzkp.com/docs/errors."},
        "servers":[{"url":"https://api.tinyzkp.com"}],
        "paths":paths,
        "components":{
            "securitySchemes":{
                "apiKey":{"type":"http","scheme":"bearer","bearerFormat":"TINYZKP_API_KEY"},
                "dashboardSession":{"type":"apiKey","in":"cookie","name":"__Host-tinyzkp_beta"}
            },
            "parameters":{"IdempotencyKey":{"name":"Idempotency-Key","in":"header","required":true,
                "description":"Exact retries return the first response; changed-body reuse returns idempotency_conflict.",
                "schema":{"type":"string","minLength":8,"maxLength":200}}},
            "responses":{"Error":{"description":"Stable safe error",
                "content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}}},
            "schemas":{
                "AirPackageV1":schema::<AirPackageV1>(),
                "AirProofBundleV1":schema::<AirProofBundleV1>(),
                "TraceManifestV1":schema::<TraceManifestV1>(),
                "PublicInputsV1":schema::<PublicInputsV1>(),
                "HostedProofBundleV1":schema::<HostedProofBundleV1>(),
                "RegisterAirRequest":schema::<RegisterAirRequest>(),
                "RegisterAirResponse":schema::<RegisterAirResponse>(),
                "CreateUploadRequest":schema::<CreateUploadRequest>(),
                "CreateUploadResponse":schema::<CreateUploadResponse>(),
                "CreateJobRequest":schema::<CreateJobRequest>(),
                "CreateJobResponse":schema::<CreateJobResponse>(),
                "JobResponse":schema::<JobResponse>(),
                "JobList":{"type":"object","required":["jobs"],"properties":{"jobs":{"type":"array","items":{"$ref":"#/components/schemas/JobResponse"}}}},
                "BundleResponse":schema::<BundleResponse>(),
                "VerifyRequest":schema::<VerifyRequest>(),
                "VerifyResponse":schema::<VerifyResponse>(),
                "CreateApiKeyRequest":schema::<CreateApiKeyRequest>(),
                "ApiKeyResponse":schema::<ApiKeyResponse>(),
                "ApiKeyListResponse":schema::<ApiKeyListResponse>(),
                "RevokeApiKeyResponse":schema::<RevokeApiKeyResponse>(),
                "DeleteAccountResponse":schema::<DeleteAccountResponse>(),
                "MeResponse":schema::<MeResponse>(),
                "JobListResponse":schema::<JobListResponse>(),
                "CancelJobResponse":schema::<CancelJobResponse>(),
                "CheckoutRequest":schema::<CheckoutRequest>(),
                "PortalRequest":schema::<PortalRequest>(),
                "RedirectResponse":schema::<RedirectResponse>(),
                "Error":{"type":"object","required":["error"],"properties":{"error":{"type":"object","required":["code","message","action","documentation_url","request_id"],"properties":{"code":{"type":"string","description":"Stable machine-readable code. Common values include unauthorized, invalid_idempotency_key, idempotency_conflict, sandbox_fixture_only, sandbox_sample_already_used, insufficient_credits, plan_concurrency_exceeded, job_exceeds_beta_limits, paid_work_frozen, operationally_contained, verification_failed, rate_limited, and internal_error."},"message":{"type":"string"},"action":{"type":"string"},"documentation_url":{"type":"string","format":"uri"},"request_id":{"type":"string","format":"uuid"}}}}}
            }
        }
    })
}

pub async fn document(State(state): State<AppState>) -> Json<Value> {
    Json(contract(&state.config.release_sha))
}
