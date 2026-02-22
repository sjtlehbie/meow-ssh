mod db;
mod http;
mod pty;
mod ssh;

use anyhow::Result;
use clap::Parser;
use russh::server::Server as _;
use std::sync::Arc;

#[derive(Parser, Clone)]
#[command(name = "meow-ssh", about = "SSH server with browser passkey auth")]
struct Args {
    /// Domain name (e.g., meow.gs)
    #[arg(long)]
    domain: String,

    /// SSH server port
    #[arg(long, default_value = "22")]
    ssh_port: u16,

    /// HTTP/WebSocket server port
    #[arg(long, default_value = "3000")]
    web_port: u16,

    /// Path to SSH host key (auto-generated if missing)
    #[arg(long, default_value = "./meow_host_key")]
    host_key: String,

    /// Path to SQLite database
    #[arg(long, default_value = "./meow.db")]
    db: String,

    /// Shell to spawn
    #[arg(long, default_value = "/bin/bash")]
    shell: String,

    /// Run shell as this user (via sudo)
    #[arg(long)]
    shell_user: Option<String>,

    /// Set HOME for shell sessions
    #[arg(long)]
    shell_home: Option<String>,

    /// Disable new passkey registration
    #[arg(long)]
    no_registration: bool,

    /// Secret required for passkey registration
    #[arg(long, default_value = "test")]
    registration_secret: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let db = Arc::new(db::Db::open(&args.db)?);

    let shell_config = Arc::new(pty::ShellConfig {
        shell: args.shell.clone(),
        shell_user: args.shell_user.clone(),
        shell_home: args.shell_home.clone(),
    });

    // SSH host key
    if !std::path::Path::new(&args.host_key).exists() {
        tracing::info!("Generating SSH host key...");
        std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f", &args.host_key, "-N", ""])
            .output()?;
    }
    let key_data = tokio::fs::read(&args.host_key).await?;
    let host_key = russh::keys::PrivateKey::from_openssh(&key_data)?;

    let ssh_config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        ..Default::default()
    });

    // SSH server
    let ssh_db = db.clone();
    let ssh_shell = shell_config.clone();
    let ssh_domain = args.domain.clone();
    let ssh_port = args.ssh_port;
    let ssh_port_web = args.web_port;
    let ssh_handle = tokio::spawn(async move {
        let mut server = ssh::SshServer {
            db: ssh_db,
            shell_config: ssh_shell,
            domain: ssh_domain,
            web_port: ssh_port_web,
        };
        tracing::info!("SSH server listening on port {}", ssh_port);
        server
            .run_on_address(ssh_config, ("0.0.0.0", ssh_port))
            .await
            .expect("SSH server failed");
    });

    // HTTP/WS server
    let http_state = http::AppState {
        db: db.clone(),
        shell_config: shell_config.clone(),
        domain: args.domain.clone(),
        web_port: args.web_port,
        no_registration: args.no_registration,
        registration_secret: args.registration_secret.clone(),
    };
    let app = http::router(http_state);
    let web_port = args.web_port;
    let http_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", web_port))
            .await
            .expect("Failed to bind HTTP port");
        tracing::info!("HTTP/WS server listening on port {}", web_port);
        axum::serve(listener, app).await.expect("HTTP server failed");
    });

    // Periodic cleanup
    let cleanup_db = db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            cleanup_db.cleanup_expired().ok();
        }
    });

    tracing::info!("meow-ssh ready — https://{}", args.domain);

    tokio::select! {
        r = ssh_handle => { tracing::error!("SSH server exited: {:?}", r); }
        r = http_handle => { tracing::error!("HTTP server exited: {:?}", r); }
    }

    Ok(())
}
