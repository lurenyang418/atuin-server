mod error;
mod handlers;
mod middleware;
mod server;
mod utils;

use std::net::SocketAddr;

use server::{Settings, launch};

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "atuin-server", about = "Atuin sync server", version)]
enum Cmd {
    /// Start the server
    Start {
        /// The host address to bind
        #[clap(long)]
        host: Option<String>,

        /// The port to bind
        #[clap(long, short)]
        port: Option<u16>,
    },

    /// Print server example configuration
    DefaultConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cmd = Cmd::parse();

    match cmd {
        Cmd::Start { host, port } => {
            let settings = Settings::new()?;
            let host = host.unwrap_or_else(|| settings.host.clone());
            let port = port.unwrap_or(settings.port);
            let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

            launch(settings, addr).await?;
        }
        Cmd::DefaultConfig => {
            eprintln!(
                r#"# Atuin Server Configuration
# host to bind, can also be passed via CLI args
host = "127.0.0.1"

# port to bind, can also be passed via CLI args
port = 8888

# whether to allow anyone to register an account
open_registration = false

# Maximum size for one history entry
max_history_length = 8192

# Maximum size for one record entry (1024 * 1024 * 1024 = 1GB)
max_record_size = 1073741824

# Default page size for requests
page_size = 1100

# Enable legacy sync v1 routes
sync_v1_enabled = true

# Database URI (SQLite or PostgreSQL)
db_uri = "sqlite://atuin.db"
"#
            );
        }
    }

    Ok(())
}
