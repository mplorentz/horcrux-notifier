use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found")]
    NotFound,

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error(transparent)]
    Database(#[from] sqlx::Error),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, log_as_error) = match &self {
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone(), false),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone(), false),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone(), false),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".into(), false),
            ApiError::RateLimited(m) => (StatusCode::TOO_MANY_REQUESTS, m.clone(), false),
            ApiError::Upstream(m) => (StatusCode::BAD_GATEWAY, m.clone(), true),
            ApiError::Database(e) => {
                tracing::error!(error = %e, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".into(),
                    true,
                )
            }
            ApiError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".into(),
                    true,
                )
            }
        };

        if log_as_error {
            tracing::error!(status = %status, "request failed: {self}");
        } else {
            tracing::debug!(status = %status, "request rejected: {self}");
        }

        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
