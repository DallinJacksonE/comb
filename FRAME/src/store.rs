//! Application repository service. Domain authority stays in CELL; crypto stays in shared adapters.
use crate::{
    archive::{pack_directory, unpack_directory},
    git::GitRepository,
    identity::{self, LocalIdentity, Profile},
    lifecycle::{Lifecycle, RestoreOutcome},
    snapshot::{Snapshot, SnapshotContext},
};
use anyhow::{Context, Result, bail};
use comb_cell::domain::{Cell, Issue, Operation, Role, identity_id};
use comb_cell::{
    EncryptedSnapshot, FrameCertificate, IdentityPublic, IdentitySecrets, open_snapshot,
    seal_snapshot,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const CONTROL_AAD: &[u8] = b"comb.frame.control.v1";
mod restore;

#[derive(Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub url: String,
    pub public_key: String,
    pub profile: Profile,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    current: BTreeMap<String, String>,
    pins: BTreeMap<String, IdentityPublic>,
    peers: BTreeMap<String, Peer>,
    lifecycle: Lifecycle,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CellPayload {
    cell: Cell,
    git: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CellSummary {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub version: String,
    pub refs: BTreeMap<String, String>,
    pub members: BTreeMap<String, String>,
}

/// Only encrypted snapshots/control survive shutdown; Git storage is a private runtime cache.
pub struct Store {
    pub local: LocalIdentity,
    _directory_lock: std::fs::File,
    data: PathBuf,
    runtime: tempfile::TempDir,
    cells: BTreeMap<String, Cell>,
    control: Control,
}

impl Store {
    pub fn open(data: &Path, password: &[u8]) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        identity::private_directory(data)?;
        let lock_path = data.join("daemon.lock");
        if lock_path.is_symlink() {
            bail!("refusing daemon lock symlink");
        }
        let directory_lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(lock_path)?;
        directory_lock
            .try_lock()
            .context("another FRAME already owns this data directory")?;
        let local = identity::load(data, password)?;
        let control_path = data.join("control.enc");
        let control = if control_path.exists() {
            let encrypted: EncryptedSnapshot =
                serde_json::from_slice(&std::fs::read(&control_path)?)?;
            let plain = open_snapshot(&encrypted, &local.frame.recipient_secret(), CONTROL_AAD)?;
            serde_json::from_slice(&plain)?
        } else {
            Control::default()
        };
        let runtime = tempfile::Builder::new()
            .prefix("comb-frame-runtime-")
            .tempdir()?;
        identity::private_directory(runtime.path())?;
        identity::private_directory(&data.join("snapshots"))?;
        let mut store = Self {
            local,
            _directory_lock: directory_lock,
            data: data.to_owned(),
            runtime,
            cells: BTreeMap::new(),
            control,
        };
        let entries = store.control.current.clone();
        for (id, digest) in entries {
            let snapshot = store.read_snapshot(&digest)?;
            let owner = store
                .control
                .pins
                .get(&id)
                .context("missing pinned CELL owner")?;
            let plain = snapshot.open(owner, &store.local.frame.recipient_secret())?;
            let payload: CellPayload = serde_json::from_slice(&plain)?;
            store.verify_payload(&snapshot, &payload, owner)?;
            store.materialize(&payload)?;
            store.cells.insert(id, payload.cell);
        }
        store.save_control()?;
        Ok(store)
    }
    pub fn profile(&self) -> &Profile {
        &self.local.profile
    }
    pub fn is_active(&self) -> bool {
        self.control.lifecycle.is_active()
    }
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.control.lifecycle
    }
    pub fn ensure_active(&self) -> Result<()> {
        if !self.is_active() {
            bail!("FRAME permission revoked; restore from another authorized FRAME");
        }
        Ok(())
    }
    pub fn count(&self) -> usize {
        self.cells.len()
    }
    pub fn peers(&self) -> Vec<Peer> {
        self.control.peers.values().cloned().collect()
    }
    pub fn peer(&self, id: &str) -> Result<Peer> {
        self.control
            .peers
            .get(id)
            .cloned()
            .context("unknown pinned peer")
    }
    pub fn add_peer(&mut self, peer: Peer) -> Result<()> {
        self.ensure_active()?;
        identity::validate_profile(&peer.profile, &peer.profile.identity)?;
        if peer.id != peer.profile.frame_id()
            || peer.public_key != hex::encode(peer.profile.noise_public)
        {
            bail!("peer profile does not match explicit FRAME/Noise pin");
        }
        if let Some(previous) = self.control.peers.get(&peer.id)
            && (previous.public_key != peer.public_key
                || previous.profile.identity != peer.profile.identity)
        {
            bail!("cannot replace an existing peer identity pin");
        }
        self.control.peers.insert(peer.id.clone(), peer);
        self.save_control()
    }
    pub fn list_cells(&self) -> Result<Vec<CellSummary>> {
        Ok(self.cells.values().map(summary).collect())
    }
    pub fn cell(&self, id: &str) -> Result<&Cell> {
        self.cells.get(id).context("unknown CELL")
    }
    pub fn cell_summary(&self, id: &str) -> Result<CellSummary> {
        Ok(summary(self.cell(id)?))
    }
    pub fn create_cell(&mut self, name: String) -> Result<CellSummary> {
        self.ensure_active()?;
        let name = name.trim().to_owned();
        if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
            bail!("CELL name must contain 1..120 printable bytes");
        }
        if self.cells.values().any(|c| c.name == name) {
            bail!("CELL name already exists");
        }
        let cell = Cell::create(name, &self.local.frame, &self.local.profile.certificate)?;
        GitRepository::create(self.runtime.path(), &cell.id)?;
        let id = cell.id.clone();
        self.control.pins.insert(id.clone(), cell.owner.clone());
        self.cells.insert(id.clone(), cell);
        self.persist_cell(&id)?;
        self.cell_summary(&id)
    }
    pub fn operate(&mut self, id: &str, operation: Operation) -> Result<CellSummary> {
        self.ensure_active()?;
        self.cells.get_mut(id).context("unknown CELL")?.apply(
            operation,
            &self.local.frame,
            &self.local.profile.certificate,
        )?;
        GitRepository::open(self.runtime.path(), id)?.install_refs(&self.cell(id)?.refs())?;
        self.persist_cell(id)?;
        self.cell_summary(id)
    }
    pub fn grant(&mut self, id: &str, profile: &Profile, role: Role) -> Result<CellSummary> {
        identity::validate_profile(profile, &profile.identity)?;
        self.operate(
            id,
            Operation::Grant {
                identity: profile.identity.clone(),
                role,
            },
        )?;
        self.operate(
            id,
            Operation::RegisterFrame {
                certificate: profile.certificate.clone(),
            },
        )
    }
    pub fn issues(&self, id: &str) -> Result<Vec<Issue>> {
        Ok(self.cell(id)?.issues())
    }
    pub fn add_issue(&mut self, id: &str, title: String, body: String) -> Result<Issue> {
        let title = title.trim().to_owned();
        if title.is_empty() || title.len() > 200 || body.len() > 32_768 {
            bail!("invalid issue size");
        }
        let issue = Issue {
            id: uuid::Uuid::new_v4().to_string(),
            title,
            body,
            closed: false,
        };
        self.operate(
            id,
            Operation::AddIssue {
                issue: issue.clone(),
            },
        )?;
        Ok(issue)
    }
    pub fn git_http(
        &mut self,
        id: &str,
        method: &str,
        suffix: &str,
        query: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<crate::git::GitResponse> {
        self.ensure_active()?;
        let write = suffix == "git-receive-pack" || query.contains("git-receive-pack");
        if !self
            .cell(id)?
            .is_frame_authorized(&self.local.profile.certificate, write)
        {
            bail!("FRAME lacks repository permission");
        }
        let repo = GitRepository::open(self.runtime.path(), id)?;
        let response = repo.http(method, suffix, query, content_type, body)?;
        if method == "POST" && suffix == "git-receive-pack" && response.status == 200 {
            let refs = repo
                .refs()?
                .into_iter()
                .filter(|(name, _)| !name.starts_with("refs/comb/"))
                .collect();
            self.operate(id, Operation::Publish { refs })?;
        }
        Ok(response)
    }
    pub fn export_snapshot(&self, id: &str) -> Result<Snapshot> {
        self.ensure_active()?;
        self.read_snapshot(
            self.control
                .current
                .get(id)
                .context("unknown CELL snapshot")?,
        )
    }
    pub fn snapshots_for(&self, certificate: &FrameCertificate) -> Result<Vec<Snapshot>> {
        self.ensure_active()?;
        self.cells
            .values()
            .filter(|c| c.is_frame_authorized(certificate, false))
            .map(|c| self.export_snapshot(&c.id))
            .collect()
    }
    /// Import requires an explicit owner pin for a previously unknown CELL.
    pub fn import_snapshot(
        &mut self,
        snapshot: &Snapshot,
        expected_owner: &IdentityPublic,
        recovery: Option<&IdentitySecrets>,
    ) -> Result<CellSummary> {
        self.ensure_active()?;
        let context = snapshot.context()?;
        crate::git::validate_id(&context.cell_id)?;
        let owner = self
            .control
            .pins
            .get(&context.cell_id)
            .unwrap_or(expected_owner);
        if owner != expected_owner {
            bail!("CELL owner differs from pinned identity");
        }
        let plain = match snapshot.open(owner, &self.local.frame.recipient_secret()) {
            Ok(plain) => plain,
            Err(error) => match recovery {
                Some(root) => snapshot.open(owner, &root.recovery_secret())?,
                None => return Err(error),
            },
        };
        let payload: CellPayload = serde_json::from_slice(&plain)?;
        self.verify_payload(snapshot, &payload, owner)?;
        if !payload
            .cell
            .identities()
            .contains_key(&self.local.profile.id())
        {
            bail!("local identity has no CELL access");
        }
        if let Some(current) = self.cells.get(&context.cell_id)
            && current.version_id() == context.version
        {
            return self.cell_summary(&context.cell_id);
        }
        // All untrusted Git and domain work is staged before changing accepted state.
        let stage = tempfile::Builder::new()
            .prefix("import-")
            .tempdir_in(self.runtime.path())?;
        let incoming_root = stage.path().join("incoming");
        std::fs::create_dir(&incoming_root)?;
        let incoming_path = incoming_root.join(format!("{}.git", context.cell_id));
        unpack_directory(&payload.git, &incoming_path)?;
        let incoming = GitRepository::open(&incoming_root, &context.cell_id)?;
        if incoming.refs()? != payload.cell.refs() {
            bail!("archive refs differ from signed CELL metadata");
        }
        let mut candidate = if let Some(current) = self.cells.get(&context.cell_id) {
            let mut candidate = current.clone();
            candidate.merge(&payload.cell)?;
            let local = GitRepository::open(self.runtime.path(), &context.cell_id)?;
            let path = stage.path().join(format!("{}.git", context.cell_id));
            unpack_directory(&pack_directory(local.path())?, &path)?;
            let staged = GitRepository::open(stage.path(), &context.cell_id)?;
            staged.merge_archive(&payload.git, &snapshot.id()?[..16])?;
            staged.install_refs(&candidate.refs())?;
            candidate
        } else {
            std::fs::rename(
                incoming.path(),
                stage.path().join(format!("{}.git", context.cell_id)),
            )?;
            payload.cell
        };
        if !candidate.is_frame_authorized(&self.local.profile.certificate, false) {
            candidate.apply(
                Operation::RegisterFrame {
                    certificate: self.local.profile.certificate.clone(),
                },
                &self.local.frame,
                &self.local.profile.certificate,
            )?;
        }

        let id = &context.cell_id;
        let final_path = self.runtime.path().join(format!("{id}.git"));
        let previous_path = stage.path().join("previous.git");
        let old_cell = self.cells.get(id).cloned();
        let old_control = self.control.clone();
        if final_path.exists() {
            std::fs::rename(&final_path, &previous_path)?;
        }
        if let Err(error) = std::fs::rename(stage.path().join(format!("{id}.git")), &final_path) {
            if previous_path.exists() {
                std::fs::rename(&previous_path, &final_path)?;
            }
            return Err(error.into());
        }
        self.cells.insert(id.clone(), candidate);
        self.control.pins.insert(id.clone(), expected_owner.clone());
        // Snapshot re-encryption/replication is not a code write: every code/policy
        // operation inside the DAG was independently authorized during validation.
        let saved = self.persist_cell(id);
        if let Err(error) = saved {
            self.control = old_control;
            if let Some(old) = old_cell {
                self.cells.insert(id.clone(), old);
            } else {
                self.cells.remove(id);
            }
            std::fs::remove_dir_all(&final_path)?;
            if previous_path.exists() {
                std::fs::rename(&previous_path, &final_path)?;
            }
            return Err(error);
        }
        self.cell_summary(id)
    }
    fn verify_payload(
        &self,
        snapshot: &Snapshot,
        payload: &CellPayload,
        owner: &IdentityPublic,
    ) -> Result<()> {
        let context = snapshot.context()?;
        payload.cell.validate()?;
        if &payload.cell.owner != owner
            || payload.cell.id != context.cell_id
            || payload.cell.version_id() != context.version
        {
            bail!("snapshot context does not match signed CELL history");
        }
        if !payload
            .cell
            .is_frame_authorized(&snapshot.record.certificate, false)
        {
            bail!("snapshot publisher is not an authorized CELL recipient");
        }
        Ok(())
    }
    fn materialize(&self, payload: &CellPayload) -> Result<()> {
        crate::git::validate_id(&payload.cell.id)?;
        let root = self.runtime.path().join(format!("{}.git", payload.cell.id));
        unpack_directory(&payload.git, &root)?;
        let repo = GitRepository::open(self.runtime.path(), &payload.cell.id)?;
        if repo.refs()? != payload.cell.refs() {
            bail!("Git snapshot refs do not match the complete accepted projection");
        }
        repo.install_refs(&payload.cell.refs())?;
        Ok(())
    }
    pub fn persist_cell(&mut self, id: &str) -> Result<()> {
        let cell = self.cell(id)?;
        let repo = GitRepository::open(self.runtime.path(), id)?;
        let payload = Zeroizing::new(serde_json::to_vec(&CellPayload {
            cell: cell.clone(),
            git: pack_directory(repo.path())?,
        })?);
        let mut recipients = Vec::new();
        for certificate in cell.frames().values() {
            if cell.is_frame_authorized(certificate, false) {
                recipients.push(certificate.frame.encryption_key);
            }
        }
        let members = cell.members();
        for (id, identity) in cell.identities() {
            if members.contains_key(&id) {
                recipients.push(identity.recovery_key);
            }
        }
        recipients.sort();
        recipients.dedup();
        let snapshot = Snapshot::seal(
            SnapshotContext {
                cell_id: id.to_owned(),
                version: cell.version_id(),
                owner: cell.owner.clone(),
            },
            &payload,
            &recipients,
            &self.local.frame,
            &self.local.profile.certificate,
        )?;
        self.write_snapshot(&snapshot)?;
        self.control.current.insert(id.to_owned(), snapshot.id()?);
        self.save_control()
    }
    fn write_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let id = snapshot.id()?;
        identity::atomic_write(
            &self.data.join("snapshots").join(format!("{id}.cell")),
            &serde_json::to_vec(snapshot)?,
        )
    }
    fn read_snapshot(&self, digest: &str) -> Result<Snapshot> {
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid snapshot identifier");
        }
        let snapshot: Snapshot = serde_json::from_slice(&std::fs::read(
            self.data.join("snapshots").join(format!("{digest}.cell")),
        )?)?;
        if snapshot.id()? != digest {
            bail!("snapshot content hash mismatch");
        }
        Ok(snapshot)
    }
    fn save_control(&self) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&self.control)?);
        let encrypted = seal_snapshot(
            &bytes,
            &[self.local.frame.public().encryption_key],
            CONTROL_AAD,
        )?;
        identity::atomic_write(
            &self.data.join("control.enc"),
            &serde_json::to_vec(&encrypted)?,
        )
    }
    /// Caller must authenticate notice against a pinned, non-revoked same-identity FRAME.
    pub fn lock(&mut self, notice_id: String) -> Result<()> {
        self.control.lifecycle.revoke(notice_id);
        self.save_control()
    }
    pub fn restore_attempt(&mut self, valid: bool) -> Result<RestoreOutcome> {
        let result = self.control.lifecycle.try_restore(valid);
        self.save_control()?;
        if result == RestoreOutcome::ResetRequired {
            // Delete only private, encrypted application CELL state. Never arbitrary clone paths.
            let snapshots = self.data.join("snapshots");
            if snapshots.is_symlink() {
                bail!("refusing reset through symlink");
            }
            std::fs::remove_dir_all(&snapshots)?;
            identity::private_directory(&snapshots)?;
            self.cells.clear();
            self.control.current.clear();
            self.control.pins.clear();
            self.control.peers.clear();
            self.save_control()?;
        }
        Ok(result)
    }
}
fn summary(cell: &Cell) -> CellSummary {
    CellSummary {
        id: cell.id.clone(),
        name: cell.name.clone(),
        owner: identity_id(&cell.owner),
        version: cell.version_id(),
        refs: cell.refs(),
        members: cell
            .members()
            .into_iter()
            .map(|(id, role)| {
                (
                    id,
                    match role {
                        Role::Read => "read".into(),
                        Role::Write => "write".into(),
                    },
                )
            })
            .collect(),
    }
}
