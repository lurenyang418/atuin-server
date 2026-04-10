use atuin_server_database::DbError;
use salvo::http::ParseError;
use salvo::prelude::StatusCode;
use salvo::writing::Json;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("user not found")]
    UserNotFound,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("user already exists")]
    UserAlreadyExists,

    #[error("registration closed")]
    RegistrationClosed,

    #[error("invalid authorization header")]
    InvalidAuthHeader,

    #[error("missing authorization header")]
    MissingAuthHeader,

    #[error("invalid username: {0}")]
    InvalidUsername(String),

    #[error("invalid calendar month")]
    InvalidCalendarMonth,

    #[error("invalid focus: use year/month/day")]
    InvalidFocus,

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub reason: String,
}

impl ErrorResponse {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl ServerError {
    pub fn from_parse_error(error: &ParseError) -> Self {
        if matches!(error, ParseError::PayloadTooLarge) {
            ServerError::PayloadTooLarge
        } else {
            ServerError::Internal(format!("Failed to parse request: {}", error))
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            ServerError::UserNotFound => StatusCode::NOT_FOUND,
            ServerError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            ServerError::UserAlreadyExists => StatusCode::BAD_REQUEST,
            ServerError::RegistrationClosed => StatusCode::BAD_REQUEST,
            ServerError::InvalidAuthHeader => StatusCode::BAD_REQUEST,
            ServerError::MissingAuthHeader => StatusCode::BAD_REQUEST,
            ServerError::InvalidUsername(_) => StatusCode::BAD_REQUEST,
            ServerError::InvalidCalendarMonth => StatusCode::BAD_REQUEST,
            ServerError::InvalidFocus => StatusCode::BAD_REQUEST,
            ServerError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ServerError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn render(&self, res: &mut salvo::Response) {
        tracing::error!(error = %self, "server error");
        res.status_code = Some(self.status());
        let error_response = ErrorResponse::new(self.to_string());
        res.render(Json(error_response));
    }
}

impl From<DbError> for ServerError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::NotFound => ServerError::UserNotFound,
            DbError::Other(_) => ServerError::Internal(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_too_large_maps_to_413() {
        assert_eq!(ServerError::PayloadTooLarge.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn parse_error_payload_too_large_maps_to_server_error() {
        let err = ServerError::from_parse_error(&ParseError::PayloadTooLarge);
        assert!(matches!(err, ServerError::PayloadTooLarge));
    }

    #[test]
    fn parse_error_other_maps_to_internal() {
        let err = ServerError::from_parse_error(&ParseError::EmptyBody);
        assert!(matches!(err, ServerError::Internal(_)));
    }
}
