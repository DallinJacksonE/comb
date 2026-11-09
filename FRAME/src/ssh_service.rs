//! Bind SSH before readiness and own its listener across revocation and shutdown.
//! The daemon prepares once, spawns after constructing `App`, and finishes on
//! shutdown. A disabled FRAME retains its address/key but must not keep listening.
use crate::{api::App, ssh_keys::ServerIdentity, store::Store};
use anyhow::Result;
use russh::keys::PrivateKey;
use std::{net::SocketAddr, time::Duration};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

/// Host key and address reserved before reporting daemon readiness.
pub(crate) struct Prepared {
    /// Initial bound listener, absent when prepared while the FRAME is inactive.
    listener: Option<TcpListener>,
    /// Actual bound address (including an allocated ephemeral port) for later rebinds.
    address: SocketAddr,
    /// Decrypted host identity cloned from the unlocked store, never a client key.
    key: PrivateKey,
}
impl Prepared {
    /// Prepare configured SSH, binding only if the store is currently active.
    /// Returns `None` if SSH is not configured. An override takes precedence over
    /// settings; the effective address updates in-memory settings only. Bind and
    /// local-address failures abort preparation before daemon readiness.
    pub(crate) async fn bind(
        store: &mut Store,
        address: Option<SocketAddr>,
    ) -> Result<Option<Self>> {
        let active = store.is_active();
        let Some(ServerIdentity { settings, host_key }) = store.ssh_identity.as_mut() else {
            return Ok(None);
        };
        let address = address.unwrap_or(settings.listen);
        let listener = if active {
            Some(TcpListener::bind(address).await?)
        } else {
            None
        };
        let address = match &listener {
            Some(listener) => listener.local_addr()?,
            None => address,
        };
        settings.listen = address;
        Ok(Some(Self {
            listener,
            address,
            key: host_key.clone(),
        }))
    }
    /// Spawn lifecycle supervision; later bind/transport errors surface via `finish`.
    pub(crate) fn spawn(self, app: App) -> Service {
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(self.run(app, stopped));
        Service {
            stop,
            task: Some(task),
        }
    }
    /// Wait while inactive, serve while enabled, and rebind after reactivation.
    /// Stop/channel closure exits; bind or transport errors end supervision.
    async fn run(mut self, app: App, mut stopped: watch::Receiver<bool>) -> Result<()> {
        let mut lifecycle = app.peer_enabled.subscribe();
        loop {
            if *stopped.borrow() {
                return Ok(());
            }
            while !*lifecycle.borrow() {
                tokio::select! {
                    _ = stopped.changed() => return Ok(()),
                    changed = lifecycle.changed() => { if changed.is_err() { return Ok(()); } }
                }
            }
            let listener = match self.listener.take() {
                Some(listener) => listener,
                None => TcpListener::bind(self.address).await?,
            };
            let mut revoked = lifecycle.clone();
            let mut shutdown = stopped.clone();
            crate::ssh::run(listener, app.clone(), self.key.clone(), async move {
                loop {
                    if *shutdown.borrow() || !*revoked.borrow() {
                        return;
                    }
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        changed = revoked.changed() => { if changed.is_err() { return; } }
                    }
                }
            })
            .await?;
        }
    }
}

/// Owning shutdown handle; dropping it signals stop and aborts supervision.
pub(crate) struct Service {
    /// Shared explicit stop signal consumed by lifecycle supervision.
    stop: watch::Sender<bool>,
    /// Taken during finish so Drop cannot abort a task being joined.
    task: Option<JoinHandle<Result<()>>>,
}
impl Service {
    /// Clone the stop sender; set it to true to request shutdown, then call `finish`.
    pub(crate) fn stop_handle(&self) -> watch::Sender<bool> {
        self.stop.clone()
    }
    /// Signal shutdown and wait up to three seconds for graceful cleanup.
    /// Propagates completed task/join errors; on timeout aborts and joins the
    /// supervisor, returning success without guaranteeing all child tasks joined.
    pub(crate) async fn finish(mut self) -> Result<()> {
        self.stop.send_replace(true);
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(3), &mut task).await {
            Ok(result) => result??,
            Err(_) => {
                task.abort();
                let _ = task.await;
            }
        }
        Ok(())
    }
}
impl Drop for Service {
    /// Request stop and abort any unjoined supervisor without blocking for cleanup.
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
