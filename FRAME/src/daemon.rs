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
    run_with_ssh(store, listen, peer_listen, assets, sync_seconds, None).await
}

/// Explicit SSH bind override; absent means the FRAME's saved SSH configuration.
pub async fn run_with_ssh(
    store: Store,
    listen: SocketAddr,
    peer_listen: SocketAddr,
    assets: PathBuf,
    sync_seconds: u64,
    ssh_listen: Option<SocketAddr>,
) -> Result<()> {
    run_with_web(
        store,
        listen,
        peer_listen,
        assets,
        sync_seconds,
        ssh_listen,
        None,
    )
    .await
}

/// Opt-in remote web administration is isolated from the local convenience API.
pub async fn run_with_web(
    store: Store,
    listen: SocketAddr,
    peer_listen: SocketAddr,
    assets: PathBuf,
    sync_seconds: u64,
    ssh_listen: Option<SocketAddr>,
    web: Option<crate::web_host::Config>,
) -> Result<()> {
    run_until(
        store,
        Listeners {
            http: listen,
            peer: peer_listen,
            ssh: ssh_listen,
            web,
        },
        assets,
        sync_seconds,
        shutdown_signal(),
        None,
    )
    .await
}

pub(crate) struct Listeners {
    pub http: SocketAddr,
    pub peer: SocketAddr,
    pub ssh: Option<SocketAddr>,
    pub web: Option<crate::web_host::Config>,
}

/// Run an unlocked FRAME with service-owned shutdown and an explicit bind receipt.
pub(crate) async fn run_until(
    mut store: Store,
    listeners: Listeners,
    assets: PathBuf,
    sync_seconds: u64,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ready: Option<tokio::sync::oneshot::Sender<App>>,
) -> Result<()> {
    let Listeners {
        http: listen,
        peer: peer_listen,
        ssh,
        web,
    } = listeners;
    if !listen.ip().is_loopback() {
        bail!(
            "management/Git HTTP must bind loopback; public deployment requires a reviewed TLS/auth proxy"
        );
    }
    let remote = match web {
        Some(config) => {
            let origin = config.origin.trim_end_matches('/').to_owned();
            Some((crate::web_host::Prepared::bind(config).await?, origin))
        }
        None => None,
    };
    let ssh = crate::ssh_service::Prepared::bind(&mut store, ssh).await?;
    let app = App::new(store);
    let management = tokio::net::TcpListener::bind(listen).await?;
    let initial = if *app.peer_enabled.borrow() {
        Some(tokio::net::TcpListener::bind(peer_listen).await?)
    } else {
        None
    };
    let ssh = ssh.map(|prepared| prepared.spawn(app.clone()));
    let (web_stop, mut web_stopped) = tokio::sync::watch::channel(false);
    let remote = remote
        .map(|(prepared, origin)| {
            crate::api::remote_router(app.clone(), assets.clone(), &origin)
                .map(|router| (prepared, router))
        })
        .transpose()?;
    let remote_enabled = remote.is_some();
    // Keep the serving future owned here, not in a detached task. Cancellation
    // drops the transport's JoinSet and all of its retained connections.
    let remote = async move {
        match remote {
            Some((prepared, router)) => {
                prepared
                    .serve(router, async move {
                        while !*web_stopped.borrow() {
                            if web_stopped.changed().await.is_err() {
                                break;
                            }
                        }
                    })
                    .await
            }
            None => std::future::pending().await,
        }
    };
    tokio::pin!(remote);
    if let Some(ready) = ready {
        let _ = ready.send(app.clone());
    }
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
            let result =
                crate::server::serve(listener, peer_router(peer_app.clone()), async move {
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
    let peer_abort = peer_task.abort_handle();
    let sync_abort = sync_task.abort_handle();
    let ssh_stop = ssh.as_ref().map(|service| service.stop_handle());
    let stop_web = web_stop.clone();
    let management = crate::server::serve(management, router(app, assets), async move {
        shutdown.await;
        stop_web.send_replace(true);
        if let Some(stop) = ssh_stop {
            stop.send_replace(true);
        }
        // Abort peer serving/sync at shutdown onset, not after HTTP drain.
        peer_abort.abort();
        sync_abort.abort();
    });
    tokio::pin!(management);
    let (result, web_finished) = tokio::select! {
        result = &mut management => (result, false),
        result = &mut remote => {
            let result = if *web_stop.borrow() {
                result.and(management.await)
            } else {
                result.and(Err(anyhow::anyhow!("remote web listener stopped unexpectedly")))
            };
            (result, true)
        }
    };
    web_stop.send_replace(true);
    if remote_enabled && !web_finished {
        let _ = tokio::time::timeout(Duration::from_secs(3), &mut remote).await;
    }
    peer_task.abort();
    sync_task.abort();
    let _ = peer_task.await;
    let _ = sync_task.await;
    if let Some(service) = ssh {
        service.finish().await?;
    }
    result?;
    Ok(())
}

/// Both terminal interrupts and user service-manager stops release listeners/state.
pub(crate) async fn shutdown_signal() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "could not install termination handler");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate => {} }
}
