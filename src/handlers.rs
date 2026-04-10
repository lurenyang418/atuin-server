use salvo::handler;
use salvo::writing::Json;
use salvo::{Request, Response, http::StatusCode};

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use time::{Month, UtcOffset};

use atuin_common::api::*;
use atuin_server_database::{
    Database, DbError,
    calendar::TimePeriod,
    models::{NewHistory, NewSession, NewUser, User},
};

use crate::error::ServerError;
use crate::server::get_state;
use crate::utils;

// Note: metrics_handler is defined in server.rs and used directly

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ============ Basic Endpoints ============

#[handler]
pub async fn index(res: &mut Response) {
    let homage = r#""Through the fathomless deeps of space swims the star turtle Great A'Tuin, bearing on its back the four giant elephants who carry on their shoulders the mass of the Discworld." -- Sir Terry Pratchett"#;

    let state = get_state();
    let version = state
        .settings
        .fake_version
        .clone()
        .unwrap_or(VERSION.to_string());

    res.render(Json(IndexResponse {
        homage: homage.to_string(),
        version,
    }));
}

#[handler]
pub async fn health_check(res: &mut Response) {
    res.render(Json(serde_json::json!({ "status": "healthy" })));
}

// ============ User Endpoints ============

#[handler]
pub async fn register(req: &mut Request, res: &mut Response) {
    let state = get_state();

    if !state.settings.open_registration {
        ServerError::RegistrationClosed.render(res);
        return;
    }

    let body: RegisterRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ServerError::Internal(format!("Failed to parse request: {}", e)).render(res);
            return;
        }
    };

    for c in body.username.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {}
            _ => {
                ServerError::InvalidUsername(format!("invalid character '{}' in username", c))
                    .render(res);
                return;
            }
        }
    }

    let hashed = hash_password(&body.password);

    let new_user = NewUser {
        email: body.email,
        username: body.username.clone(),
        password: hashed,
    };

    let user_id = match state.db.add_user(&new_user).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "failed to add user");
            ServerError::UserAlreadyExists.render(res);
            return;
        }
    };

    let token = crypto_random_string();
    let new_session = NewSession {
        user_id,
        token: token.clone(),
    };

    if let Some(url) = &state.settings.register_webhook_url {
        let webhook_url = url.clone();
        let webhook_username = state.settings.register_webhook_username.clone();
        let username = body.username.clone();

        tokio::spawn(async move {
            send_register_hook(&webhook_url, webhook_username, username).await;
        });
    }

    if let Err(e) = state.db.add_session(&new_session).await {
        tracing::error!(error = %e, "failed to add session");
        ServerError::Internal("failed to create session".into()).render(res);
        return;
    }

    tracing::info!(username = %body.username, "user registered");

    res.render(Json(RegisterResponse {
        session: token,
        auth: Some("cli".into()),
    }));
}

#[handler]
pub async fn login(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let body: LoginRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ServerError::Internal(format!("Failed to parse request: {}", e)).render(res);
            return;
        }
    };

    let user = match state.db.get_user(&body.username).await {
        Ok(u) => u,
        Err(DbError::NotFound) => {
            ServerError::UserNotFound.render(res);
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to get user");
            ServerError::Internal("database error".into()).render(res);
            return;
        }
    };

    if !verify_password(&user.password, &body.password) {
        ServerError::InvalidCredentials.render(res);
        return;
    }

    let session = match state.db.get_user_session(&user).await {
        Ok(s) => s,
        Err(_) => {
            ServerError::UserNotFound.render(res);
            return;
        }
    };

    tracing::info!(username = %body.username, "user logged in");

    res.render(Json(LoginResponse {
        session: session.token,
        auth: Some("cli".into()),
    }));
}

#[handler]
pub async fn get_user(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let username = req.param::<String>("username").unwrap_or_default();

    let user = match state.db.get_user(&username).await {
        Ok(u) => u,
        Err(DbError::NotFound) => {
            ServerError::UserNotFound.render(res);
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "database error");
            ServerError::Internal("database error".into()).render(res);
            return;
        }
    };

    res.render(Json(UserResponse {
        username: user.username,
    }));
}

#[handler]
pub async fn delete_user(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    if let Err(e) = state.db.delete_user(&user).await {
        tracing::error!(error = %e, "failed to delete user");
        ServerError::Internal("failed to delete user".into()).render(res);
        return;
    }

    tracing::info!(username = %user.username, "user deleted");

    res.render(Json(DeleteUserResponse {}));
}

#[handler]
pub async fn change_password(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    let body: ChangePasswordRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ServerError::Internal(format!("Failed to parse request: {}", e)).render(res);
            return;
        }
    };

    if !verify_password(&user.password, &body.current_password) {
        ServerError::InvalidCredentials.render(res);
        return;
    }

    let updated_user = User {
        id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        password: hash_password(&body.new_password),
    };

    if let Err(e) = state.db.update_user_password(&updated_user).await {
        tracing::error!(error = %e, "failed to change password");
        ServerError::Internal("failed to change password".into()).render(res);
        return;
    }

    tracing::info!(username = %user.username, "password changed");

    res.render(Json(ChangePasswordResponse {}));
}

// ============ Sync Endpoints ============

#[handler]
pub async fn sync_count(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    let count = match state.db.count_history_cached(&user).await {
        Ok(c) => c,
        Err(_) => match state.db.count_history(&user).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to count history");
                ServerError::Internal("failed to count history".into()).render(res);
                return;
            }
        },
    };

    res.render(Json(CountResponse { count }));
}

#[handler]
pub async fn sync_history(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    let query: SyncHistoryRequest = match req.parse_json().await {
        Ok(q) => q,
        Err(e) => {
            ServerError::Internal(format!("Failed to parse request: {}", e)).render(res);
            return;
        }
    };

    let user_agent = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let variable_page_size = utils::client_version_min(user_agent, ">=15.0.0");

    let page_size = if variable_page_size {
        state.settings.page_size
    } else {
        100
    };

    let history = match state
        .db
        .list_history(
            &user,
            query.sync_ts,
            query.history_ts,
            &query.host,
            page_size,
        )
        .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to list history");
            ServerError::Internal("failed to list history".into()).render(res);
            return;
        }
    };

    let history_data: Vec<String> = history.iter().map(|h| h.data.to_string()).collect();

    res.render(Json(SyncHistoryResponse {
        history: history_data,
    }));
}

#[handler]
pub async fn sync_status(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    let deleted = state.db.deleted_history(&user).await.unwrap_or_default();

    let count = match state.db.count_history_cached(&user).await {
        Ok(c) => c,
        Err(_) => match state.db.count_history(&user).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to count history");
                ServerError::Internal("failed to count history".into()).render(res);
                return;
            }
        },
    };

    tracing::debug!(user = %user.username, "requested sync status");

    res.render(Json(StatusResponse {
        count,
        username: user.username,
        deleted,
        page_size: state.settings.page_size,
        version: VERSION.to_string(),
    }));
}

#[derive(serde::Deserialize, Debug)]
pub struct CalendarQuery {
    #[serde(default = "serde_calendar::zero")]
    year: i32,
    #[serde(default = "serde_calendar::one")]
    month: u8,
    #[serde(default = "serde_calendar::utc")]
    tz: UtcOffset,
}

mod serde_calendar {
    use time::UtcOffset;

    pub fn zero() -> i32 {
        0
    }

    pub fn one() -> u8 {
        1
    }

    pub fn utc() -> UtcOffset {
        UtcOffset::UTC
    }
}

#[handler]
pub async fn sync_calendar(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    let focus = req.param::<String>("focus").unwrap_or_default();

    let params: CalendarQuery = req.parse_queries().unwrap_or(CalendarQuery {
        year: 0,
        month: 1,
        tz: UtcOffset::UTC,
    });

    let year = params.year;
    let month = match Month::try_from(params.month) {
        Ok(m) => m,
        Err(_) => {
            ServerError::InvalidCalendarMonth.render(res);
            return;
        }
    };

    let period = match focus.as_str() {
        "year" => TimePeriod::Year,
        "month" => TimePeriod::Month { year },
        "day" => TimePeriod::Day { year, month },
        _ => {
            ServerError::InvalidFocus.render(res);
            return;
        }
    };

    let focus = match state.db.calendar(&user, period, params.tz).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "failed to query calendar");
            ServerError::Internal("failed to query calendar".into()).render(res);
            return;
        }
    };

    res.render(Json(focus));
}

#[handler]
pub async fn delete_history(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    let body: DeleteHistoryRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ServerError::Internal(format!("Failed to parse request: {}", e)).render(res);
            return;
        }
    };

    if let Err(e) = state.db.delete_history(&user, body.client_id).await {
        tracing::error!(error = %e, "failed to delete history");
        ServerError::Internal("failed to delete history".into()).render(res);
        return;
    }

    res.render(Json(MessageResponse {
        message: "deleted OK".to_string(),
    }));
}

#[handler]
pub async fn add_history(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    let body: Vec<AddHistoryRequest> = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ServerError::Internal(format!("Failed to parse request: {}", e)).render(res);
            return;
        }
    };

    let history: Vec<NewHistory> = body
        .into_iter()
        .map(|h| NewHistory {
            client_id: h.id,
            user_id: user.id,
            hostname: h.hostname,
            timestamp: h.timestamp,
            data: h.data,
        })
        .collect();

    if let Err(e) = state.db.add_history(&history).await {
        tracing::error!(error = %e, "failed to add history");
        ServerError::Internal("failed to add history".into()).render(res);
        return;
    }

    res.status_code = Some(StatusCode::OK);
}

// ============ Record Endpoints (Deprecated) ============

#[handler]
pub async fn record_post(req: &mut Request, res: &mut Response) {
    let _user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    ServerError::Internal("record store deprecated; please upgrade".into()).render(res);
}

#[handler]
pub async fn record_index(req: &mut Request, res: &mut Response) {
    let _user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    res.render(Json(serde_json::json!({ "hosts": {} })));
}

#[handler]
pub async fn record_next(req: &mut Request, res: &mut Response) {
    let _user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    res.render(Json(Vec::<serde_json::Value>::new()));
}

// ============ API v0 Endpoints ============

#[handler]
pub async fn me(req: &mut Request, res: &mut Response) {
    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    res.render(Json(MeResponse {
        username: user.username,
    }));
}

#[handler]
pub async fn v0_record_post(req: &mut Request, res: &mut Response) {
    let _state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    // Parse record data - use 100MB limit for sync payloads
    let _body: serde_json::Value = match req.parse_json_with_max_size(100 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            ServerError::Internal(format!("Failed to parse request: {}", e)).render(res);
            return;
        }
    };

    // For now, just acknowledge
    tracing::debug!(user = %user.username, "v0 record post");
    res.status_code = Some(StatusCode::OK);
}

#[handler]
pub async fn v0_record_index(req: &mut Request, res: &mut Response) {
    let _user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    res.render(Json(serde_json::json!({ "hosts": {} })));
}

#[handler]
pub async fn v0_record_next(req: &mut Request, res: &mut Response) {
    let _user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    res.render(Json(Vec::<serde_json::Value>::new()));
}

#[handler]
pub async fn v0_store_delete(req: &mut Request, res: &mut Response) {
    let state = get_state();

    let user = match authenticate(req).await {
        Ok(u) => u,
        Err(e) => {
            e.render(res);
            return;
        }
    };

    if let Err(e) = state.db.delete_store(&user).await {
        tracing::error!(error = %e, "failed to delete store");
        ServerError::Internal("failed to delete store".into()).render(res);
        return;
    }

    res.render(Json(MessageResponse {
        message: "deleted OK".to_string(),
    }));
}

// ============ Helper Functions ============

async fn authenticate(req: &mut Request) -> Result<User, ServerError> {
    let state = get_state();

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ServerError::MissingAuthHeader)?;

    let (typ, token) = auth_header
        .split_once(' ')
        .ok_or(ServerError::InvalidAuthHeader)?;

    if typ != "Token" {
        return Err(ServerError::InvalidAuthHeader);
    }

    state.db.get_session_user(token).await.map_err(|e| e.into())
}

fn hash_password(password: &str) -> String {
    use argon2::password_hash::rand_core::OsRng;
    let arg2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let salt = SaltString::generate(&mut OsRng);
    arg2.hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn verify_password(hash: &str, password: &str) -> bool {
    let arg2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let Ok(hash) = PasswordHash::new(hash) else {
        return false;
    };
    arg2.verify_password(password.as_bytes(), &hash).is_ok()
}

fn crypto_random_string() -> String {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = [0u8; 24];
    OsRng.fill_bytes(&mut rng);
    (0..24)
        .map(|i| {
            let idx = rng[i] as usize % CHARSET.len();
            CHARSET[idx] as char
        })
        .collect()
}

async fn send_register_hook(url: &str, webhook_username: String, username: String) {
    use reqwest::header::CONTENT_TYPE;
    use std::collections::HashMap;
    use std::time::Duration;

    let hook = HashMap::from([
        ("username", webhook_username),
        ("content", format!("{username} has just signed up!")),
    ]);

    let client = reqwest::Client::new();

    let resp = client
        .post(url)
        .timeout(Duration::new(5, 0))
        .header(CONTENT_TYPE, "application/json")
        .json(&hook)
        .send()
        .await;

    match resp {
        Ok(_) => tracing::info!("register webhook sent ok!"),
        Err(e) => tracing::error!("failed to send register webhook: {}", e),
    }
}
