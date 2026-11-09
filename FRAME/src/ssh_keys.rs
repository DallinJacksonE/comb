//! Separate standard OpenSSH client keys and password-sealed server host keys.
use crate::identity;
use anyhow::{Context, Result, ensure};
use comb_cell::{PasswordEnvelope, open_secret, seal_secret};
use russh::keys::{Algorithm, PrivateKey};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

/// Validate a public username before committing identity/setup state.
pub fn validate_username(username: &str) -> Result<()> {
    identity::validate_ssh_username(username)
}

const HOST_CONTEXT: &[u8] = b"COMB-FRAME-ssh-host-v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub username: String,
    pub public_key: String,
    pub client_key: PathBuf,
    pub host_public_key: String,
    pub listen: SocketAddr,
    pub alias: String,
}
pub struct ServerIdentity {
    pub settings: Settings,
    pub host_key: PrivateKey,
}
fn safe(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        ensure!(
            !matches!(component, Component::ParentDir),
            "parent traversal refused"
        );
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) => ensure!(!meta.file_type().is_symlink(), "symlink refused"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>> {
    safe(path)?;
    ensure!(
        fs::metadata(path)?.is_file() && fs::metadata(path)?.len() <= 1024 * 1024,
        "invalid SSH metadata file"
    );
    Ok(fs::read(path)?)
}
fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    safe(path)?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
pub fn settings(data: &Path) -> Result<Option<Settings>> {
    let path = data.join("ssh/settings.json");
    safe(&path)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let settings: Settings = serde_json::from_slice(&read(&path)?)?;
    identity::validate_ssh_username(&settings.username)?;
    identity::validate_ssh_public_key(&settings.public_key)?;
    identity::validate_ssh_public_key(&settings.host_public_key)?;
    ensure!(
        settings.alias.len() == 21
            && settings.alias.starts_with("comb-")
            && settings.alias[5..].bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid SSH alias"
    );
    Ok(Some(settings))
}
pub fn load_server(data: &Path, password: &[u8]) -> Result<Option<ServerIdentity>> {
    let Some(settings) = settings(data)? else {
        return Ok(None);
    };
    let envelope: PasswordEnvelope = serde_json::from_slice(&read(&data.join("ssh/host.vault"))?)?;
    let plain = open_secret(&envelope, password, HOST_CONTEXT)?;
    let host_key = PrivateKey::from_openssh(&plain)?;
    ensure!(
        host_key.public_key().to_openssh()? == settings.host_public_key,
        "host key mismatch"
    );
    let local = identity::load(data, password)?;
    ensure!(
        local.profile.username.as_ref() == Some(&settings.username)
            && local.profile.ssh_public_key.as_ref() == Some(&settings.public_key),
        "SSH settings/profile mismatch"
    );
    ensure!(
        settings.alias == format!("comb-{}", &local.profile.frame_id()[..16]),
        "SSH alias/frame mismatch"
    );
    Ok(Some(ServerIdentity { settings, host_key }))
}
pub fn set_listen(data: &Path, listen: SocketAddr) -> Result<()> {
    let mut settings = settings(data)?.context("SSH is not configured")?;
    settings.listen = listen;
    identity::atomic_write(
        &data.join("ssh/settings.json"),
        &serde_json::to_vec(&settings)?,
    )
}
pub fn setup(
    data: &Path,
    password: &[u8],
    username: &str,
    key_passphrase: &[u8],
    ssh_config: Option<&Path>,
    listen: SocketAddr,
) -> Result<Settings> {
    identity::validate_ssh_username(username)?;
    let local = identity::load(data, password)?;
    let directory = data.join("ssh");
    identity::private_directory(&directory)?;
    for name in ["id_ed25519", "host.vault", "known_hosts", "settings.json"] {
        let path = directory.join(name);
        safe(&path)?;
        ensure!(
            !path.try_exists()?,
            "SSH key/settings already exist; refusing overwrite"
        );
    }
    let _lock = SetupLock::acquire(&directory)?;
    let mut client = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519)?;
    let host = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519)?;
    let settings = Settings {
        username: username.into(),
        public_key: client.public_key().to_openssh()?,
        client_key: fs::canonicalize(&directory)?.join("id_ed25519"),
        host_public_key: host.public_key().to_openssh()?,
        listen,
        alias: format!("comb-{}", &local.profile.frame_id()[..16]),
    };
    // Validate target and collision before any key/profile publication.
    let config = ssh_config
        .map(|path| client_config(&settings, data, path))
        .transpose()?;
    if !key_passphrase.is_empty() {
        client = client.encrypt(&mut rand10::rng(), key_passphrase)?;
    }
    let private = client.to_openssh(russh::keys::ssh_key::LineEnding::LF)?;
    let host_plain = host.to_openssh(russh::keys::ssh_key::LineEnding::LF)?;
    let host_vault = seal_secret(host_plain.as_bytes(), password, HOST_CONTEXT)?;
    create(&settings.client_key, private.as_bytes())?;
    create(
        &directory.join("host.vault"),
        &serde_json::to_vec(&host_vault)?,
    )?;
    create(
        &directory.join("known_hosts"),
        format!("{} {}\n", settings.alias, settings.host_public_key).as_bytes(),
    )?;
    identity::configure_ssh_profile(data, password, username, &settings.public_key)?;
    if let (Some(target), Some(bytes)) = (ssh_config, config) {
        write_config(target, &bytes)?;
    }
    create(
        &directory.join("settings.json"),
        &serde_json::to_vec(&settings)?,
    )?;
    Ok(settings)
}
struct SetupLock(PathBuf);
impl SetupLock {
    fn acquire(directory: &Path) -> Result<Self> {
        let path = directory.join(".setup-lock");
        create(&path, b"")?;
        Ok(Self(path))
    }
}
impl Drop for SetupLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn quote(path: &Path) -> Result<String> {
    let text = path.to_str().context("SSH path must be UTF-8")?;
    ensure!(
        !text.chars().any(|c| c.is_control()),
        "control character in SSH path"
    );
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
fn client_config(settings: &Settings, data: &Path, target: &Path) -> Result<Vec<u8>> {
    safe(target)?;
    let original = if target.try_exists()? {
        read(target)?
    } else {
        Vec::new()
    };
    let text = std::str::from_utf8(&original).context("SSH config must be UTF-8")?;
    let begin = format!("# BEGIN COMB {}\n", settings.alias);
    let end = format!("# END COMB {}\n", settings.alias);
    let mut remaining = text.to_owned();
    if let Some(start) = remaining.find(&begin) {
        ensure!(
            start == 0 || remaining.as_bytes()[start - 1] == b'\n',
            "invalid managed block"
        );
        let stop = remaining[start..]
            .find(&end)
            .context("unterminated COMB block")?
            + start
            + end.len();
        remaining.replace_range(start..stop, "");
    }
    ensure!(
        !remaining.contains(&begin) && !remaining.contains(&end),
        "duplicate/invalid managed block"
    );
    for line in remaining.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut words = line
            .split(|c: char| c.is_ascii_whitespace() || c == '=')
            .filter(|s| !s.is_empty());
        if words
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("host"))
        {
            ensure!(
                !words.any(|word| word.trim_matches('"').eq_ignore_ascii_case(&settings.alias)),
                "foreign SSH alias collision"
            );
        }
    }
    let known_hosts = fs::canonicalize(data.join("ssh"))?.join("known_hosts");
    let host = if settings.listen.ip().is_unspecified() {
        "127.0.0.1".into()
    } else {
        settings.listen.ip().to_string()
    };
    let block = format!(
        "{begin}Host {}\n  HostName {host}\n  Port {}\n  User {}\n  IdentityFile {}\n  IdentitiesOnly yes\n  AddKeysToAgent yes\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  HostKeyAlias {}\n  StrictHostKeyChecking yes\nHost *\n{end}",
        settings.alias,
        settings.listen.port(),
        settings.username,
        quote(&settings.client_key)?,
        quote(&known_hosts)?,
        settings.alias
    );
    // Prepend so generic Host patterns cannot override first-value-wins options.
    Ok([block.as_bytes(), remaining.as_bytes()].concat())
}
fn write_config(target: &Path, bytes: &[u8]) -> Result<()> {
    safe(target)?;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.try_exists()? {
        identity::private_directory(parent)?;
    }
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    safe(target)?;
    temp.persist(target).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn configure_client(data: &Path, target: &Path) -> Result<Settings> {
    let settings = settings(data)?.context("SSH is not configured")?;
    let bytes = client_config(&settings, data, target)?;
    write_config(target, &bytes)?;
    Ok(settings)
}
