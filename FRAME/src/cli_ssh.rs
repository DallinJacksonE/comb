//! SSH setup prompts and explicit migration/configuration commands.
use crate::{
    cli::SshCommand,
    entry::{password, prompt},
};
use anyhow::{Context, Result, ensure};
use comb_frame::ssh_keys::{self, Settings};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(crate) fn username(value: Option<String>) -> Result<String> {
    let username = match value.or_else(|| std::env::var("COMB_USERNAME").ok()) {
        Some(value) => value,
        None if std::env::var_os("COMB_PASSWORD").is_some() => "comb".to_owned(),
        None => prompt("Username (SSH login): ")?,
    };
    ssh_keys::validate_username(&username)?;
    Ok(username)
}

/// Automation must opt into an isolated config target rather than touching HOME.
pub(crate) fn config_target(value: Option<PathBuf>) -> Result<Option<PathBuf>> {
    if let Some(path) = value.or_else(|| std::env::var_os("COMB_SSH_CONFIG").map(PathBuf::from)) {
        return Ok(Some(path));
    }
    if std::env::var_os("COMB_PASSWORD").is_some() {
        return Ok(None);
    }
    Ok(Some(
        PathBuf::from(std::env::var_os("HOME").context("HOME is required for SSH configuration")?)
            .join(".ssh/config"),
    ))
}

pub(crate) fn listen(value: Option<SocketAddr>) -> Result<SocketAddr> {
    match value {
        Some(value) => Ok(value),
        None => std::env::var("COMB_SSH_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:7333".into())
            .parse()
            .context("invalid SSH listen address"),
    }
}

/// An SSH key passphrase is local to OpenSSH, not an SSH server login password.
pub(crate) fn key_passphrase() -> Result<Zeroizing<String>> {
    let configured = std::env::var("COMB_SSH_KEY_PASSPHRASE").ok();
    let interactive = configured.is_none() && std::env::var_os("COMB_PASSWORD").is_none();
    let value = Zeroizing::new(match configured {
        Some(value) => value,
        None if !interactive => String::new(),
        None => rpassword::prompt_password("SSH key passphrase (Enter for none): ")?,
    });
    ensure!(
        value.len() <= 4096,
        "SSH key passphrase must be at most 4096 bytes"
    );
    if interactive && !value.is_empty() {
        let confirmation =
            Zeroizing::new(rpassword::prompt_password("Confirm SSH key passphrase: ")?);
        ensure!(
            *confirmation == *value,
            "SSH key passphrases did not match; SSH keys were not created"
        );
    }
    if value.is_empty() {
        eprintln!(
            "SSH client key will have no passphrase; protect its private local file. FRAME vaults and recovery material remain password-encrypted."
        );
    }
    Ok(value)
}

pub(crate) fn explain(settings: &Settings, configured: bool) {
    eprintln!("FRAME SSH client key: {}", settings.client_key.display());
    eprintln!(
        "SSH login: {}. SSH listener: {} (available only after FRAME unlock).",
        settings.username, settings.listen
    );
    if configured {
        eprintln!(
            "Git SSH remote: {}:REPOSITORY-SLUG.git. The dedicated alias automatically selects this FRAME key.",
            settings.alias
        );
    } else {
        eprintln!(
            "No user SSH configuration changed. Run comb ssh configure with an explicit --ssh-config destination to install the {} alias.",
            settings.alias
        );
    }
    eprintln!(
        "The optional SSH key passphrase protects the client key locally. OpenSSH prompts when needed; ssh-agent can cache the unlocked key. Keep this key separate from your FRAME/recovery password and never share the private key."
    );
}

pub(crate) fn run(data: &Path, command: SshCommand) -> Result<()> {
    match command {
        SshCommand::Status => {
            println!(
                "{}",
                serde_json::to_string_pretty(&ssh_keys::settings(data)?)?
            );
        }
        SshCommand::Configure { ssh_config } => {
            let target = config_target(ssh_config)?
                .context("automated SSH configuration requires --ssh-config or COMB_SSH_CONFIG")?;
            let settings = ssh_keys::configure_client(data, &target)?;
            explain(&settings, true);
        }
        SshCommand::Setup {
            username: value,
            ssh_config,
            listen: address,
        } => {
            ensure!(
                data.join("node.vault").is_file(),
                "initialize a FRAME before configuring SSH"
            );
            let username = username(value)?;
            let address = listen(address)?;
            let target = config_target(ssh_config)?;
            let passphrase = key_passphrase()?;
            let secret = password("FRAME password to configure SSH: ")?;
            let settings = ssh_keys::setup(
                data,
                &secret,
                &username,
                passphrase.as_bytes(),
                target.as_deref(),
                address,
            )?;
            explain(&settings, target.is_some());
            eprintln!(
                "If this FRAME daemon is already running, restart it and run comb cell list to unlock again and load SSH. Existing identity, repositories and recovery files were preserved."
            );
        }
    }
    Ok(())
}
