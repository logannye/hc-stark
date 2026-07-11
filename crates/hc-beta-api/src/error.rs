use axum::{
    http::StatusCode,
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
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.code();
        tracing::warn!(%status, code, error = %self, "beta API request rejected");
        (
            status,
            Json(ErrorBody {
                error: ErrorDetail {
                    code,
                    message: self.to_string(),
                },
            }),
        )
            .into_response()
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
