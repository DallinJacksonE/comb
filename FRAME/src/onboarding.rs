//! First-use guidance for the installed locked user service.
use crate::{
    cli::Command,
    entry::{password, prompt},
};
use anyhow::{Result, bail, ensure};
use comb_frame::{
    identity,
    managed::{self, State},
};
use std::{
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct Options {
    pub name: Option<String>,
    pub email: Option<String>,
    pub recovery: Option<PathBuf>,
    pub username: Option<String>,
    pub ssh_config: Option<PathBuf>,
    pub ssh_listen: Option<std::net::SocketAddr>,
}

impl Options {
    fn from_command(command: &Command) -> Self {
        match command {
            Command::User {
                name,
                email,
                recovery,
                username,
                ssh_config,
                ssh_listen,
            } => Self {
                name: name.clone(),
                email: email.clone(),
                recovery: recovery.clone(),
                username: username.clone(),
                ssh_config: ssh_config.clone(),
                ssh_listen: *ssh_listen,
            },
            _ => Self::default(),
        }
    }
}

fn require_terminal() -> Result<()> {
    // Explicit fixture/automation opt-in; normal piped commands never create an identity.
    ensure!(
        std::env::var_os("COMB_PASSWORD").is_some() || io::stdin().is_terminal(),
        "FRAME needs setup/unlock. Run comb in an interactive terminal first; automated use may explicitly set COMB_PASSWORD"
    );
    Ok(())
}

/// Return the password once so the originating command need not prompt twice.
pub async fn prepare(data: &Path, command: &Command) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if matches!(
        command,
        Command::ServiceStatus
            | Command::Serve { .. }
            | Command::Enroll { .. }
            | Command::Recover { .. }
            | Command::Ice { .. }
            | Command::Ssh { .. }
    ) {
        return Ok(None);
    }
    let service_state = managed::status(data).await?;
    let state = match service_state {
        Some(state) => state,
        None if data.join("node.vault").exists() => return Ok(None),
        None => State::Uninitialized,
    };
    if state == State::Ready {
        return Ok(None);
    }
    require_terminal()?;
    let secret = if state == State::Uninitialized {
        initialize(data, Options::from_command(command))?
    } else {
        eprintln!(
            "FRAME is locked after service start/restart. Unlocking keeps keys in this user's daemon memory; no password is saved in the service. Git/peer listeners stay closed until unlock."
        );
        loop {
            let secret = password("Unlock FRAME: ")?;
            match managed::unlock(data, &secret).await {
                Ok(()) => break secret,
                Err(error) => retry_password(error)?,
            }
        }
    };
    if service_state.is_some() && state == State::Uninitialized {
        managed::unlock(data, &secret).await?;
    }
    if service_state.is_some() {
        eprintln!(
            "FRAME is unlocked and serving locally. After a service restart or reboot, run a management command to unlock it."
        );
    }
    Ok(Some(secret))
}

/// Create first-device identity and explain the independent offline recovery capability.
pub(crate) fn initialize(data: &Path, options: Options) -> Result<Zeroizing<Vec<u8>>> {
    require_terminal()?;
    if data.join("pending.vault").exists() {
        bail!("Pending enrollment exists; complete enrollment instead of creating a new identity");
    }
    for file in ["node.vault", "profile.json", "root.vault"] {
        ensure!(
            !data.join(file).exists(),
            "Identity or partial setup already exists; do not overwrite it: {file}"
        );
    }
    eprintln!(
        "Welcome to COMB. We will create your self-custodied contributor identity and a distinct key for this device's FRAME. Name/email are profile metadata, not proof of identity."
    );
    eprintln!(
        "Your password encrypts local key vaults and the recovery file. A managed FRAME starts locked: no Git/peer listeners open and no repository keys are decrypted until you unlock it. The service does not save your password."
    );
    eprintln!(
        "IMPORTANT: the encrypted recovery file plus its password can restore your identity authority and historical decryption capability after device loss. It is NOT a repository backup: keep encrypted CELL backups too. COMB has no provider reset or replacement recovery key."
    );
    let name = match options.name {
        Some(name) => name,
        None => prompt("Name: ")?,
    };
    let email = match options.email {
        Some(email) => email,
        None => prompt("Email: ")?,
    };
    ensure!(
        !name.is_empty() && !email.is_empty(),
        "Name and email must not be empty"
    );
    ensure!(
        name.len() <= 120,
        "Name must be at most 120 UTF-8 bytes; nothing was initialized"
    );
    ensure!(
        email.len() <= 320,
        "Email must be at most 320 UTF-8 bytes; nothing was initialized"
    );
    let username = crate::cli_ssh::username(options.username)?;
    let ssh_listen = crate::cli_ssh::listen(options.ssh_listen)?;
    let ssh_config = crate::cli_ssh::config_target(options.ssh_config)?;
    let secret = password("Choose FRAME/recovery-file password: ")?;
    validate_new_password(&secret)?;
    if std::env::var_os("COMB_PASSWORD").is_none() {
        let confirmation = password("Confirm password: ")?;
        ensure!(
            *confirmation == *secret,
            "Passwords did not match; nothing was initialized"
        );
    }
    let ssh_passphrase = crate::cli_ssh::key_passphrase()?;
    let recovery = options
        .recovery
        .unwrap_or_else(|| data.join("identity.recovery"));
    identity::initialize(data, &name, &email, &secret, &recovery)?;
    let ssh = comb_frame::ssh_keys::setup(
        data,
        &secret,
        &username,
        ssh_passphrase.as_bytes(),
        ssh_config.as_deref(),
        ssh_listen,
    )?;
    crate::cli_ssh::explain(&ssh, ssh_config.is_some());
    eprintln!("Encrypted recovery file created at: {}", recovery.display());
    eprintln!(
        "Copy it to protected offline storage (for example, a secured USB drive), verify that copy, and retain its original password separately. Keep encrypted repository backups as well. Losing every authorized device and the last usable recovery copy can permanently lose this recovery path. A stolen recovery file AND its password expose identity authority: protect both. Do not delete the only verified copy. This prototype also retains an encrypted root.vault on the first device; installation does not change that trust boundary."
    );
    Ok(secret)
}

/// Apply the same new-key password contract to setup, enrollment and recovery.
pub fn validate_new_password(secret: &[u8]) -> Result<()> {
    ensure!(
        !secret.is_empty() && secret.len() <= managed::MAX_PASSWORD_BYTES,
        "New FRAME passwords must contain 1..4096 UTF-8 bytes for managed unlock; no identity/enrollment files were written"
    );
    Ok(())
}

pub fn take_password(
    cached: &mut Option<Zeroizing<Vec<u8>>>,
    message: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    match cached.take() {
        Some(secret) => Ok(secret),
        None => password(message),
    }
}

/// Retry only rejected secrets, never startup/I/O errors or a fixed automation value.
pub(crate) fn retry_password(error: anyhow::Error) -> Result<()> {
    if !error.is::<identity::IncorrectPassword>() || std::env::var_os("COMB_PASSWORD").is_some() {
        return Err(error);
    }
    eprintln!("Incorrect password");
    Ok(())
}

/// Unlock local state, retaining the successful secret for commands that need it later.
pub(crate) fn unlock_local<T>(
    cached: &mut Option<Zeroizing<Vec<u8>>>,
    message: &str,
    mut open: impl FnMut(&[u8]) -> Result<T>,
) -> Result<(Zeroizing<Vec<u8>>, T)> {
    loop {
        let secret = take_password(cached, message)?;
        match open(&secret) {
            Ok(value) => return Ok((secret, value)),
            Err(error) => retry_password(error)?,
        }
    }
}
