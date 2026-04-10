use once_cell::sync::OnceCell;
use salvo::conn::TcpListener;
use salvo::prelude::*;
use salvo::writing::Text;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use atuin_server_database::{Database, DbSettings};
use atuin_server_sqlite::Sqlite;

use crate::handlers;
use crate::middleware;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Fallback database URI used when no config file is provided.
fn default_db_uri() -> String {
    "sqlite://atuin.db".to_string()
}

fn setup_metrics_recorder() -> PrometheusHandle {
    const EXPONENTIAL_SECONDS: &[f64] = &[
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_requests_duration_seconds".to_string()),
            EXPONENTIAL_SECONDS,
        )
        .unwrap()
        .install_recorder()
        .unwrap()
}

#[handler]
async fn metrics_handler(res: &mut Response) {
    use metrics_exporter_prometheus::PrometheusHandle;
    static HANDLER: std::sync::OnceLock<PrometheusHandle> = std::sync::OnceLock::new();

    let handle = HANDLER.get_or_init(setup_metrics_recorder);

    res.render(Text::Plain(handle.render()));
}

static APP_STATE: OnceCell<AppState> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub open_registration: bool,
    pub max_history_length: usize,
    pub max_record_size: usize,
    pub page_size: i64,
    pub sync_v1_enabled: bool,
    pub fake_version: Option<String>,
    pub register_webhook_url: Option<String>,
    pub register_webhook_username: String,
    #[serde(flatten)]
    pub db_settings: DbSettings,
}

impl Settings {
    pub fn new() -> anyhow::Result<Self> {
        // If ATUIN_CONFIG_DIR is set, only use that directory; otherwise use current directory.
        let config_path = if let Ok(config_dir) = std::env::var("ATUIN_CONFIG_DIR") {
            std::path::Path::new(&config_dir).join("server.toml")
        } else {
            std::path::Path::new("server.toml").to_path_buf()
        };

        if config_path.exists() {
            let contents = std::fs::read_to_string(config_path)?;
            let config: toml::Table = toml::from_str(&contents)?;
            Ok(Self {
                host: config
                    .get("host")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.0.0.0")
                    .to_string(),
                port: config
                    .get("port")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(8888) as u16,
                open_registration: config
                    .get("open_registration")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
                max_history_length: config
                    .get("max_history_length")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(8192) as usize,
                max_record_size: config
                    .get("max_record_size")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(1024 * 1024 * 1024) as usize,
                page_size: config
                    .get("page_size")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(1100),
                sync_v1_enabled: config
                    .get("sync_v1_enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
                fake_version: config
                    .get("fake_version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                register_webhook_url: config
                    .get("register_webhook_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                register_webhook_username: config
                    .get("register_webhook_username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                db_settings: DbSettings {
                    db_uri: config
                        .get("db_uri")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(default_db_uri),
                    read_db_uri: config
                        .get("read_db_uri")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                },
            })
        } else {
            Ok(Self {
                host: "0.0.0.0".to_string(),
                port: 8888,
                open_registration: true,
                max_history_length: 8192,
                max_record_size: 1024 * 1024 * 1024,
                page_size: 1100,
                sync_v1_enabled: true,
                fake_version: None,
                register_webhook_url: None,
                register_webhook_username: String::new(),
                db_settings: DbSettings {
                    db_uri: default_db_uri(),
                    read_db_uri: None,
                },
            })
        }
    }
}

pub struct AppState {
    pub db: Sqlite,
    pub settings: Settings,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db", &"<Sqlite>")
            .field("settings", &self.settings)
            .finish()
    }
}

pub fn get_state() -> &'static AppState {
    APP_STATE.get().expect("AppState not initialized")
}

pub fn init_state(state: AppState) {
    APP_STATE.set(state).expect("AppState already initialized");
}

pub fn create_router(sync_v1_enabled: bool) -> Router {
    let router = Router::new()
        .push(Router::with_path("/").get(handlers::index))
        .push(Router::with_path("/healthz").get(handlers::health_check))
        .push(Router::with_path("/metrics").get(metrics_handler))
        // User endpoints
        .push(Router::with_path("/register").post(handlers::register))
        .push(Router::with_path("/login").post(handlers::login))
        .push(Router::with_path("/user/<username>").get(handlers::get_user))
        .push(Router::with_path("/account").delete(handlers::delete_user))
        .push(Router::with_path("/account/password").patch(handlers::change_password));

    let router = if sync_v1_enabled {
        router
            // Sync v1 endpoints
            .push(Router::with_path("/sync/count").get(handlers::sync_count))
            .push(Router::with_path("/sync/history").get(handlers::sync_history))
            .push(Router::with_path("/sync/status").get(handlers::sync_status))
            .push(Router::with_path("/sync/calendar/<focus>").get(handlers::sync_calendar))
            .push(Router::with_path("/history").post(handlers::add_history))
            .push(Router::with_path("/history").delete(handlers::delete_history))
    } else {
        router
    };

    router
        // Record endpoints (deprecated)
        .push(Router::with_path("/record").post(handlers::record_post))
        .push(Router::with_path("/record").get(handlers::record_index))
        .push(Router::with_path("/record/next").get(handlers::record_next))
        // API v0
        .push(Router::with_path("/api/v0/me").get(handlers::me))
        .push(Router::with_path("/api/v0/record").post(handlers::v0_record_post))
        .push(Router::with_path("/api/v0/record").get(handlers::v0_record_index))
        .push(Router::with_path("/api/v0/record/next").get(handlers::v0_record_next))
        .push(Router::with_path("/api/v0/store").delete(handlers::v0_store_delete))
        // Middleware
        .hoop(middleware::clacks_overhead)
        .hoop(middleware::version_header)
}

#[cfg(target_family = "unix")]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate()).expect("failed to register signal handler");
    let mut interrupt = signal(SignalKind::interrupt()).expect("failed to register signal handler");

    tokio::select! {
        _ = term.recv() => {},
        _ = interrupt.recv() => {},
    }
    eprintln!("Shutting down gracefully...");
}

#[cfg(target_family = "windows")]
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to register signal handler");
    eprintln!("Shutting down gracefully...");
}

pub async fn launch(settings: Settings, addr: SocketAddr) -> anyhow::Result<()> {
    match settings.db_settings.db_type() {
        atuin_server_database::DbType::Postgres => {
            anyhow::bail!(
                "Postgres not supported in this build. Use atuin-server with atuin-server-postgres crate."
            );
        }
        atuin_server_database::DbType::Sqlite => {}
        atuin_server_database::DbType::Unknown => {
            anyhow::bail!("Unknown database type. Please check your db_uri configuration.");
        }
    }

    let db: Sqlite = Sqlite::new(&settings.db_settings).await?;
    let sync_v1_enabled = settings.sync_v1_enabled;

    let state = AppState { db, settings };
    init_state(state);

    let router = create_router(sync_v1_enabled);
    let catcher = middleware::create_catcher();

    tracing::info!(addr = %addr, "Starting Atuin server");

    let acceptor = TcpListener::new(addr).bind().await;
    let server = Server::new(acceptor);
    let handle = server.handle();

    tokio::spawn(async move {
        shutdown_signal().await;
        handle.stop_graceful(None);
    });

    server.serve(Service::new(router).catcher(catcher)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use salvo::test::TestClient;
    use std::sync::Mutex;
    use tempfile::tempdir;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[tokio::test]
    async fn router_disables_sync_v1_routes_when_flag_is_false() {
        let router = create_router(false);

        let res = TestClient::get("http://127.0.0.1/sync/count")
            .send(router)
            .await;
        assert_eq!(res.status_code.unwrap(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn settings_uses_default_db_uri_when_config_file_missing() {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let dir = tempdir().expect("tempdir should be created");

        // SAFETY: guarded by process-wide mutex to avoid concurrent env mutation in tests.
        unsafe { std::env::set_var("ATUIN_CONFIG_DIR", dir.path()) };

        let settings = Settings::new().expect("settings should load with defaults");
        assert_eq!(settings.db_settings.db_uri, "sqlite://atuin.db");

        // SAFETY: guarded by process-wide mutex to avoid concurrent env mutation in tests.
        unsafe { std::env::remove_var("ATUIN_CONFIG_DIR") };
    }

    #[test]
    fn settings_uses_db_uri_from_config_when_provided() {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let dir = tempdir().expect("tempdir should be created");
        let config_path = dir.path().join("server.toml");
        std::fs::write(&config_path, "db_uri = \"sqlite://custom.db\"\n")
            .expect("config should be written");

        // SAFETY: guarded by process-wide mutex to avoid concurrent env mutation in tests.
        unsafe { std::env::set_var("ATUIN_CONFIG_DIR", dir.path()) };

        let settings = Settings::new().expect("settings should load from config");
        assert_eq!(settings.db_settings.db_uri, "sqlite://custom.db");

        // SAFETY: guarded by process-wide mutex to avoid concurrent env mutation in tests.
        unsafe { std::env::remove_var("ATUIN_CONFIG_DIR") };
    }
}
