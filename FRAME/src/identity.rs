//! Password-sealed local FRAME persistence; root authority is loaded only explicitly.
use anyhow::{Context, Result, ensure};
use comb_cell::{
    FrameCertificate, FramePublic, FrameSecrets, IdentityPublic, IdentitySecrets, PasswordEnvelope,
    Signature, open_secret, seal_secret,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const PROFILE_DOMAIN: &[u8] = b"COMB-FRAME-profile-v1";
const NODE_CONTEXT: &[u8] = b"COMB-FRAME-node-vault-v1";
const PENDING_CONTEXT: &[u8] = b"COMB-FRAME-pending-vault-v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub identity: IdentityPublic,
    pub certificate: FrameCertificate,
    pub name: String,
    pub email: String,
    pub noise_public: [u8; 32],
    pub nonce: String,
    pub signature: Signature,
}
impl Profile {
    pub fn id(&self) -> String {
        hex::encode(self.identity.signing_key)
    }
    pub fn frame_id(&self) -> String {
        hex::encode(self.certificate.frame.signing_key)
    }
}

/// Deliberately has no Debug, Clone or Serialize implementation, and no root secret.
pub struct LocalIdentity {
    pub profile: Profile,
    pub frame: FrameSecrets,
    pub noise_private: Zeroizing<[u8; 32]>,
    pub token: String,
}
impl Drop for LocalIdentity {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub frame: FramePublic,
    pub noise_public: [u8; 32],
    pub nonce: String,
}
/// A grant is the complete public, root-signed profile, including its FRAME certificate.
pub type EnrollmentGrant = Profile;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeVault {
    frame: PasswordEnvelope,
    noise_private: [u8; 32],
    token: String,
    nonce: String,
    profile: Option<Profile>,
}
impl Drop for NodeVault {
    fn drop(&mut self) {
        self.noise_private.zeroize();
        self.token.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootVault {
    root: PasswordEnvelope,
    profile: Profile,
}

fn random() -> Zeroizing<[u8; 32]> {
    let mut value = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(value.as_mut());
    value
}
fn random_hex() -> String {
    hex::encode(*random())
}
fn signed_bytes(profile: &Profile) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(
        1_u32,
        &profile.identity,
        &profile.certificate,
        &profile.name,
        &profile.email,
        &profile.noise_public,
        &profile.nonce,
    ))?)
}
pub fn validate_profile(profile: &Profile, expected_identity: &IdentityPublic) -> Result<()> {
    ensure!(
        &profile.identity == expected_identity,
        "unexpected identity"
    );
    profile.certificate.verify(expected_identity)?;
    ensure!(
        profile.nonce.len() == 64 && hex::decode(&profile.nonce)?.len() == 32,
        "invalid enrollment nonce"
    );
    // Reject low-order transport keys using GUARD's own contributory-key validation.
    comb_guard::client_start(&[1; 32], &profile.noise_public)?;
    let signing_key = profile
        .certificate
        .delegation
        .as_deref()
        .map(|issuer| issuer.frame.signing_key)
        .unwrap_or(expected_identity.signing_key);
    profile
        .signature
        .verify(&signing_key, PROFILE_DOMAIN, &signed_bytes(profile)?)?;
    Ok(())
}
fn certify(
    root: &IdentitySecrets,
    name: &str,
    email: &str,
    request: &EnrollmentRequest,
) -> Result<Profile> {
    let mut profile = Profile {
        identity: root.public(),
        certificate: root.certify_frame(&request.frame)?,
        name: name.into(),
        email: email.into(),
        noise_public: request.noise_public,
        nonce: request.nonce.clone(),
        signature: Signature { bytes: Vec::new() },
    };
    profile.signature = root.sign(PROFILE_DOMAIN, &signed_bytes(&profile)?);
    validate_profile(&profile, &root.public())?;
    Ok(profile)
}

// Reject symlinks in every existing path component. Private directories prevent
// unprivileged local races; these helpers do not defend against a hostile same UID.
fn reject_symlinks(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        ensure!(
            !matches!(component, Component::ParentDir),
            "parent traversal refused"
        );
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) => ensure!(
                !meta.file_type().is_symlink(),
                "symlink refused: {}",
                current.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
/// Create a private directory (0700), refusing symlinks in its entire path.
/// Existing ancestor permissions are not changed.
pub fn private_directory(path: &Path) -> Result<()> {
    reject_symlinks(path)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)?;
    reject_symlinks(path)?;
    ensure!(fs::metadata(path)?.is_dir(), "not a directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn write_file(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    reject_symlinks(path)?;
    private_directory(parent(path))?;
    let mut file = tempfile::NamedTempFile::new_in(parent(path))?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    reject_symlinks(path)?;
    if replace {
        file.persist(path).map_err(|e| e.error)?;
    } else {
        file.persist_noclobber(path).map_err(|e| e.error)?;
    }
    File::open(parent(path))?.sync_all()?;
    Ok(())
}
/// Atomically replace a file with mode 0600, fsyncing its contents and directory.
/// Intended for encrypted state or public metadata, not plaintext private keys.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    write_file(path, bytes, true)
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    reject_symlinks(path)?;
    let meta = fs::metadata(path)?;
    ensure!(
        meta.is_file() && meta.len() <= 1024 * 1024,
        "invalid or oversized identity file"
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn seal_vault(vault: &NodeVault, password: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let plain = Zeroizing::new(serde_json::to_vec(vault)?);
    Ok(serde_json::to_vec(&seal_secret(
        &plain, password, context,
    )?)?)
}
fn open_vault(path: &Path, password: &[u8], context: &[u8]) -> Result<NodeVault> {
    let envelope: PasswordEnvelope = read_json(path)?;
    let plain = open_secret(&envelope, password, context)?;
    Ok(serde_json::from_slice(&plain)?)
}
struct Lock(PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn lock(data: &Path) -> Result<Lock> {
    private_directory(data)?;
    let path = data.join(".identity-lock");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .context("identity operation already in progress (or stale lock)")?
        .sync_all()?;
    Ok(Lock(path))
}
fn ensure_empty(data: &Path, pending_allowed: bool) -> Result<()> {
    for name in ["profile.json", "node.vault", "root.vault"] {
        ensure!(
            !data.join(name).try_exists()?,
            "identity already exists or partial initialization: {name}"
        );
        reject_symlinks(&data.join(name))?;
    }
    if !pending_allowed {
        reject_symlinks(&data.join("pending.vault"))?;
        ensure!(
            !data.join("pending.vault").try_exists()?,
            "pending enrollment exists"
        );
    }
    Ok(())
}
fn fresh(password: &[u8]) -> Result<(FrameSecrets, NodeVault)> {
    let frame = FrameSecrets::generate();
    let vault = NodeVault {
        frame: frame.export_encrypted(password)?,
        noise_private: *random(),
        token: random_hex(),
        nonce: random_hex(),
        profile: None,
    };
    Ok((frame, vault))
}
fn request(frame: &FrameSecrets, vault: &NodeVault) -> EnrollmentRequest {
    EnrollmentRequest {
        frame: frame.public(),
        noise_public: comb_guard::static_public(&vault.noise_private),
        nonce: vault.nonce.clone(),
    }
}
fn local(vault: &NodeVault, password: &[u8], profile: Profile) -> Result<LocalIdentity> {
    validate_profile(&profile, &profile.identity)?;
    let frame = FrameSecrets::import_encrypted(&vault.frame, password)?;
    ensure!(
        frame.public() == profile.certificate.frame
            && comb_guard::static_public(&vault.noise_private) == profile.noise_public
            && vault.nonce == profile.nonce,
        "local keys do not match profile"
    );
    ensure!(
        vault.token.len() == 64 && hex::decode(&vault.token)?.len() == 32,
        "invalid local token"
    );
    Ok(LocalIdentity {
        profile,
        frame,
        noise_private: Zeroizing::new(vault.noise_private),
        token: vault.token.clone(),
    })
}
fn commit(
    data: &Path,
    password: &[u8],
    vault: &mut NodeVault,
    profile: &Profile,
) -> Result<LocalIdentity> {
    vault.profile = Some(profile.clone());
    let local = local(vault, password, profile.clone())?;
    write_file(
        &data.join("node.vault"),
        &seal_vault(vault, password, NODE_CONTEXT)?,
        false,
    )?;
    write_file(
        &data.join("profile.json"),
        &serde_json::to_vec(profile)?,
        false,
    )?;
    Ok(local)
}

pub fn initialize(
    data: &Path,
    name: &str,
    email: &str,
    password: &[u8],
    recovery_path: &Path,
) -> Result<LocalIdentity> {
    let _lock = lock(data)?;
    ensure_empty(data, false)?;
    reject_symlinks(recovery_path)?;
    ensure!(!recovery_path.try_exists()?, "recovery file already exists");
    let root = IdentitySecrets::generate();
    let (frame, mut vault) = fresh(password)?;
    let profile = certify(&root, name, email, &request(&frame, &vault))?;
    let root_bytes = serde_json::to_vec(&RootVault {
        root: root.export_encrypted(password)?,
        profile: profile.clone(),
    })?;
    write_file(recovery_path, &root_bytes, false)?;
    write_file(&data.join("root.vault"), &root_bytes, false)?;
    commit(data, password, &mut vault, &profile)
}
/// Load routine keys only. Does not read or decrypt root.vault.
pub fn load(data: &Path, password: &[u8]) -> Result<LocalIdentity> {
    let profile: Profile = read_json(&data.join("profile.json"))?;
    let vault = open_vault(&data.join("node.vault"), password, NODE_CONTEXT)?;
    let bound = vault
        .profile
        .as_ref()
        .context("node vault has no profile")?;
    ensure!(
        serde_json::to_vec(bound)? == serde_json::to_vec(&profile)?,
        "public profile differs from authenticated vault"
    );
    local(&vault, password, profile)
}
fn open_root(path: &Path, password: &[u8]) -> Result<(IdentitySecrets, Profile)> {
    let vault: RootVault = read_json(path)?;
    let root = IdentitySecrets::import_encrypted(&vault.root, password)?;
    validate_profile(&vault.profile, &root.public())?;
    Ok((root, vault.profile))
}
/// Explicit offline authority access; never call from the running daemon.
pub fn load_root(data: &Path, password: &[u8]) -> Result<IdentitySecrets> {
    let (root, _) = open_root(&data.join("root.vault"), password)?;
    let local = load(data, password)?;
    ensure!(
        root.public() == local.profile.identity,
        "root does not match local identity"
    );
    Ok(root)
}
pub fn prepare_enrollment(data: &Path, password: &[u8]) -> Result<EnrollmentRequest> {
    let _lock = lock(data)?;
    ensure_empty(data, false)?;
    let (frame, vault) = fresh(password)?;
    let request = request(&frame, &vault);
    write_file(
        &data.join("pending.vault"),
        &seal_vault(&vault, password, PENDING_CONTEXT)?,
        false,
    )?;
    Ok(request)
}
pub fn authorize(
    data: &Path,
    password: &[u8],
    request: &EnrollmentRequest,
) -> Result<EnrollmentGrant> {
    let local = load(data, password)?;
    // Root-bearing first/recovered devices retain direct certification compatibility.
    // Enrolled devices delegate with their own FRAME key, not copied recovery authority.
    if data.join("root.vault").exists() {
        let root = load_root(data, password)?;
        return certify(&root, &local.profile.name, &local.profile.email, request);
    }
    authorize_from_frame(&local, request)
}

/// Delegate from an existing FRAME without loading identity recovery/root secrets.
pub fn authorize_from_frame(
    local: &LocalIdentity,
    request: &EnrollmentRequest,
) -> Result<EnrollmentGrant> {
    let mut profile = Profile {
        identity: local.profile.identity.clone(),
        certificate: local
            .frame
            .certify_frame(&local.profile.certificate, &request.frame)?,
        name: local.profile.name.clone(),
        email: local.profile.email.clone(),
        noise_public: request.noise_public,
        nonce: request.nonce.clone(),
        signature: Signature { bytes: Vec::new() },
    };
    profile.signature = local.frame.sign(PROFILE_DOMAIN, &signed_bytes(&profile)?);
    validate_profile(&profile, &local.profile.identity)?;
    Ok(profile)
}
/// Validate bindings and load pending keys without consuming or committing the request.
pub fn preview_enrollment(
    data: &Path,
    password: &[u8],
    grant: &EnrollmentGrant,
    expected_identity: &IdentityPublic,
) -> Result<LocalIdentity> {
    validate_profile(grant, expected_identity)?;
    let vault = open_vault(&data.join("pending.vault"), password, PENDING_CONTEXT)?;
    local(&vault, password, grant.clone())
}

pub fn complete_enrollment(
    data: &Path,
    password: &[u8],
    grant: &EnrollmentGrant,
    expected_identity: &IdentityPublic,
) -> Result<LocalIdentity> {
    validate_profile(grant, expected_identity)?;
    let _lock = lock(data)?;
    ensure_empty(data, true)?;
    let mut vault = open_vault(&data.join("pending.vault"), password, PENDING_CONTEXT)?;
    // Validate all pending bindings before writing anything permanent.
    let _checked = local(&vault, password, grant.clone())?;
    let local = commit(data, password, &mut vault, grant)?;
    fs::remove_file(data.join("pending.vault"))?;
    File::open(data)?.sync_all()?;
    Ok(local)
}
/// Restore offline authority and certify entirely fresh device/transport keys.
/// Historical decryption requires explicit load_root(...).recovery_secret().
pub fn recover(
    data: &Path,
    password: &[u8],
    recovery_path: &Path,
    recovery_password: &[u8],
) -> Result<LocalIdentity> {
    // Authenticate the recovery material before creating destination files.
    let (root, previous) = open_root(recovery_path, recovery_password)?;
    let _lock = lock(data)?;
    ensure_empty(data, false)?;
    let (frame, mut vault) = fresh(password)?;
    let profile = certify(
        &root,
        &previous.name,
        &previous.email,
        &request(&frame, &vault),
    )?;
    let root_bytes = serde_json::to_vec(&RootVault {
        root: root.export_encrypted(password)?,
        profile: profile.clone(),
    })?;
    write_file(&data.join("root.vault"), &root_bytes, false)?;
    commit(data, password, &mut vault, &profile)
}
