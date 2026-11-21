//! `pdp`: the policy decision point as a standalone server.
//!
//! - `pdp serve`: serve the router on `PDP_HOST:PDP_PORT`. It never migrates.
//! - `pdp migrate`: apply the `authz` migrations to the database.
//! - `pdp check`: validate the policies, with no database, and list the actions.
//! - `pdp healthcheck`: `GET /health` on the local port (the image's HEALTHCHECK).
//!
//! Every setting comes from the environment ([`olai_pdp::Config::from_env`]).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "pdp", version, about = "A Cedar policy decision point")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the PDP's HTTP API.
    Serve,
    /// Apply the `authz` migrations (over a direct connection).
    Migrate,
    /// Validate the policies and print the schema's actions.
    Check,
    /// Exit 0 when the local server answers `GET /health`.
    Healthcheck,
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "olai_pdp=info,olai_auth=info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let cli = Cli::parse();
    match run(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pdp: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    let config = olai_pdp::Config::from_env()?;
    match command {
        Command::Serve => {
            let service = olai_pdp::embed::start(&config).await?;
            let addr = SocketAddr::new(config.host, config.port);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(%addr, actions = service.actions().len(), "pdp serving");
            axum::serve(listener, service.router())
                .with_graceful_shutdown(shutdown())
                .await?;
        }
        Command::Migrate => {
            let url = config
                .database_url
                .as_deref()
                .ok_or("set PDP_DATABASE_URL or DATABASE_URL")?;
            olai_pdp::embed::migrate(url).await?;
            tracing::info!("authz migrations applied");
        }
        Command::Check => {
            for action in olai_pdp::embed::check(&config)? {
                println!("{}::{:?}", action.entity_type, action.id);
            }
        }
        Command::Healthcheck => healthcheck(config.port).await?,
    }
    Ok(())
}

/// Ctrl-C, or SIGTERM (a container stop).
async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            term.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("pdp shutting down");
}

/// `GET /health` over plain HTTP/1.1, so the distroless image needs no curl.
async fn healthcheck(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let check = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let response = tokio::time::timeout(Duration::from_secs(3), check).await??;
    let status = String::from_utf8_lossy(&response);
    match status.lines().next() {
        Some(line) if line.split_whitespace().nth(1) == Some("200") => Ok(()),
        line => Err(format!("unhealthy: {}", line.unwrap_or("no response")).into()),
    }
}
