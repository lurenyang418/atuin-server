use atuin_server_database::DbError;
use salvo::prelude::StatusCode;
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
            ServerError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn render(&self, res: &mut salvo::Response) {
        tracing::error!(error = %self, "server error");
        res.status_code = Some(self.status());
        let error_response = ErrorResponse::new(self.to_string());
        res.render(
            serde_json::to_string(&error_response)
                .unwrap_or_else(|_| r#"{"reason":"internal error"}"#.to_string()),
        );
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
