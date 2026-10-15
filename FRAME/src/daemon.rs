//! Daemon lifecycle; the externally reachable peer listener is closed while revoked.
use crate::{
    api::{App, router},
    peer::{peer_router, sync},
    store::Store,
};
use anyhow::{Result, bail};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

pub async fn run(
    store: Store,
    listen: SocketAddr,
    peer_listen: SocketAddr,
    assets: PathBuf,
    sync_seconds: u64,
) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!(
            "management/Git HTTP must bind loopback; public deployment requires a reviewed TLS/auth proxy"
        );
    }
    let app = App::new(store);
    let management = tokio::net::TcpListener::bind(listen).await?;
    let initial = if *app.peer_enabled.borrow() {
        Some(tokio::net::TcpListener::bind(peer_listen).await?)
    } else {
        None
    };
    let peer_app = app.clone();
    let mut changes = app.peer_enabled.subscribe();
    let peer_task = tokio::spawn(async move {
        let mut initial = initial;
        loop {
            while !*changes.borrow() {
                if changes.changed().await.is_err() {
                    return;
                }
            }
            let listener = match initial.take() {
                Some(listener) => listener,
                None => match tokio::net::TcpListener::bind(peer_listen).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        tracing::error!(%error,"peer listener bind failed");
                        return;
                    }
                },
            };
            let mut shutdown = changes.clone();
            let result = axum::serve(listener, peer_router(peer_app.clone()))
                .with_graceful_shutdown(async move {
                    loop {
                        if !*shutdown.borrow() {
                            return;
                        }
                        if shutdown.changed().await.is_err() {
                            return;
                        }
                    }
                })
                .await;
            if let Err(error) = result {
                tracing::error!(%error,"peer server failed");
                return;
            }
        }
    });
    let sync_app = app.clone();
    let sync_task = tokio::spawn(async move {
        if sync_seconds == 0 {
            return;
        }
        loop {
            tokio::time::sleep(Duration::from_secs(sync_seconds.max(5))).await;
            let peers = sync_app
                .execute(|s| {
                    s.ensure_active()?;
                    Ok(s.peers())
                })
                .await
                .unwrap_or_default();
            for peer in peers {
                if let Err(error) = sync(&sync_app, &peer.id).await {
                    tracing::warn!(peer=%peer.id,%error,"peer synchronization failed");
                }
            }
        }
    });
    tracing::info!(%listen,%peer_listen,"FRAME ready; obtain management credential with comb token");
    let result = axum::serve(management, router(app, assets))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    peer_task.abort();
    sync_task.abort();
    result?;
    Ok(())
}
