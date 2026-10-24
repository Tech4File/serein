use anyhow::{Context, Result};
use std::{env, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use wtransport::{endpoint::IncomingSession, Endpoint, Identity, ServerConfig};

const MEDIA_PATH: &str = "/media/v1";
const MAX_CONCURRENT_SESSIONS: usize = 128;
const MAX_ECHO_DATAGRAM: usize = 1200;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let port: u16 = env::var("WT_PORT")
        .unwrap_or_else(|_| "4433".into())
        .parse()?;
    let cert_path = env::var("WT_CERT_PEM")
        .context("WT_CERT_PEM must point to a TLS certificate PEM")?;
    let key_path = env::var("WT_KEY_PEM")
        .context("WT_KEY_PEM must point to a TLS private-key PEM")?;
    let allowed_origin = env::var("ALLOWED_ORIGIN")
        .context("ALLOWED_ORIGIN must be set to one exact HTTPS browser origin")?;

    let identity = Identity::load_pemfiles(cert_path, key_path).await?;
    let config = ServerConfig::builder()
        .with_bind_default(port)
        .with_identity(identity)
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .build();
    let server = Endpoint::server(config)?;
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));

    info!(
        port,
        %allowed_origin,
        "WebTransport transport spike listening; echo only, not a call server"
    );
    loop {
        let incoming = server.accept().await;
        let permit = match Arc::clone(&permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("connection limit reached; rejecting WebTransport request");
                tokio::spawn(async move {
                    if let Ok(request) = incoming.await {
                        let _ = request.too_many_requests().await;
                    }
                });
                continue;
            }
        };
        let origin = allowed_origin.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_session(incoming, &origin).await {
                warn!(error = %err, "WebTransport session ended");
            }
        });
    }
}

async fn handle_session(incoming: IncomingSession, allowed_origin: &str) -> Result<()> {
    let request = incoming.await?;
    let origin_ok = request.origin().is_some_and(|origin| origin == allowed_origin);
    if !origin_ok {
        request.forbidden().await;
        anyhow::bail!("rejected missing or unapproved Origin");
    }
    if request.path() != MEDIA_PATH {
        request.not_found().await;
        anyhow::bail!("rejected unknown WebTransport path");
    }

    let connection = request.accept().await?;
    info!("accepted WebTransport spike session");
    loop {
        let datagram = match connection.receive_datagram().await {
            Ok(bytes) => bytes,
            Err(err) => break Err(err.into()),
        };
        // This test endpoint echoes small opaque bytes only. It does not parse, decrypt,
        // relay, persist, or treat these bytes as audio/video frames.
        if datagram.len() > MAX_ECHO_DATAGRAM {
            warn!(size = datagram.len(), "dropped oversized test datagram");
            continue;
        }
        connection.send_datagram(datagram.as_ref())?;
    }
}
