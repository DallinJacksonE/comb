//! HTTP connection ownership and bounded service shutdown, shared by both listeners.
use axum::Router;
use hyper::server::conn::http1::Builder;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use std::{future::Future, time::Duration};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// The web transport retains TLS handshakes and HTTP connections in one owner.
pub(crate) async fn serve_web(
    listener: TcpListener,
    app: Router,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let (stop, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let app = app.clone();
                let tls = tls.clone();
                let stopped = stop.subscribe();
                connections.spawn(async move {
                    if let Some(tls) = tls {
                        if let Ok(stream) = tls.accept(stream).await {
                            web_connection(stream, app, stopped).await;
                        }
                    } else {
                        web_connection(stream, app, stopped).await;
                    }
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    drop(listener);
    let _ = stop.send(true);
    if tokio::time::timeout(DRAIN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

async fn web_connection<I>(stream: I, app: Router, mut stopped: watch::Receiver<bool>)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(app);
    let connection = Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::pin!(connection);
    let result = tokio::select! {
        result = &mut connection => result,
        _ = stopped.changed() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(error) = result {
        tracing::debug!(%error, "web HTTP connection closed");
    }
}

/// Stop accepting immediately; drain briefly, then cancel every retained connection.
/// Dropping this future also drops the JoinSet and aborts its connection tasks.
pub(crate) async fn serve(
    listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let (stop, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let service = TowerToHyperService::new(app.clone());
                let mut stopped = stop.subscribe();
                connections.spawn(async move {
                    let connection = Builder::new().serve_connection(TokioIo::new(stream), service).with_upgrades();
                    tokio::pin!(connection);
                    let result = tokio::select! {
                        result = &mut connection => result,
                        _ = stopped.changed() => {
                            connection.as_mut().graceful_shutdown();
                            connection.await
                        }
                    };
                    if let Err(error) = result { tracing::debug!(%error, "HTTP connection closed"); }
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    drop(listener);
    let _ = stop.send(true);
    if tokio::time::timeout(DRAIN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}
