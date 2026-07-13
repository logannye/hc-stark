use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("authentication required")]
    Unauthorized,
    #[error("resource not found")]
    NotFound,
    #[error("request conflict: {0}")]
    Conflict(&'static str),
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    #[error("insufficient credits")]
    PaymentRequired,
    #[error("request rate limit exceeded")]
    RateLimited,
    #[error("operation is temporarily unavailable: {0}")]
    Unavailable(&'static str),
    #[error("internal service error")]
    Internal,
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    action: &'static str,
    documentation_url: String,
    request_id: String,
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::PaymentRequired => StatusCode::PAYMENT_REQUIRED,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::Conflict(code) => code,
            Self::Invalid(code) => code,
            Self::PaymentRequired => "insufficient_credits",
            Self::RateLimited => "rate_limited",
            Self::Unavailable(code) => code,
            Self::Internal => "internal_error",
        }
    }

    fn action(&self) -> &'static str {
        match self {
            Self::Unauthorized => "Sign in or provide a valid API key.",
            Self::NotFound => "Check the resource ID and tenant ownership.",
            Self::Conflict(_) => "Reuse the original request or choose a new idempotency key.",
            Self::Invalid(_) => "Correct the request using the API contract and retry.",
            Self::PaymentRequired => "Purchase prepaid credits or reduce the requested workload.",
            Self::RateLimited => "Wait before retrying with exponential backoff.",
            Self::Unavailable(_) => "Check service status and retry after recovery.",
            Self::Internal => "Retry later and provide the request ID if the failure persists.",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.code();
        let request_id = uuid::Uuid::new_v4().to_string();
        tracing::warn!(%status, code, %request_id, error = %self, "beta API request rejected");
        let mut response = (
            status,
            Json(ErrorBody {
                error: ErrorDetail {
                    code,
                    message: self.to_string(),
                    action: self.action(),
                    documentation_url: format!("https://tinyzkp.com/docs/errors#{code}"),
                    request_id: request_id.clone(),
                },
            }),
        )
            .into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_str(&request_id).expect("UUID is a valid header value"),
        );
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "PostgreSQL operation failed");
        Self::Internal
    }
}

impl From<reqwest::Error> for ApiError {
    fn from(error: reqwest::Error) -> Self {
        tracing::error!(%error, "upstream HTTP operation failed");
        Self::Unavailable("upstream_unavailable")
    }
}
