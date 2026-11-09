//! SSH policy/transaction boundary. Call through App::execute: its Store mutex
//! MUST remain held from authorization through transfer, signed publication and
//! encrypted persistence. Revocations serialize with transfers, as with HTTP.
use super::*;

impl Store {
    /// Only a locally validated profile or explicitly pinned peer profile is an
    /// SSH principal. Never accept a certificate supplied by the SSH client.
    pub(crate) fn ssh_authenticate(
        &self,
        username: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<FrameCertificate> {
        self.ensure_active()?;
        let mut matched = None;
        for profile in std::iter::once(&self.local.profile)
            .chain(self.control.peers.values().map(|peer| &peer.profile))
        {
            if profile.username.as_deref() != Some(username) {
                continue;
            }
            identity::validate_profile(profile, &profile.identity)?;
            let Some(public) = profile.ssh_public_key.as_deref() else {
                continue;
            };
            let public = russh::keys::PublicKey::from_openssh(public)?;
            if public.key_data() == key.key_data() {
                if let Some(previous) = &matched {
                    ensure!(previous == &profile.certificate, "ambiguous SSH principal");
                }
                matched = Some(profile.certificate.clone());
            }
        }
        matched.context("unrecognized SSH username/public key")
    }

    /// Run native Git against a private stage for writes. Failed/cancelled Git
    /// never mutates the accepted repository. The caller supplies only a fixed
    /// upload-pack/receive-pack child and must cancel/reap it before returning.
    /// Successful receive is published by the local authorized FRAME, retaining
    /// the matched client's certificate as the independent authorization gate.
    pub(crate) fn ssh_transfer(
        &mut self,
        certificate: &FrameCertificate,
        repository: &str,
        write: bool,
        transfer: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<()> {
        self.ensure_active()?;
        let id = self.resolve_git_cell(repository)?;
        let cell = self.cell(&id)?;
        ensure!(
            cell.is_frame_authorized(certificate, write),
            "SSH principal lacks CELL permission"
        );
        ensure!(
            cell.is_frame_authorized(&self.local.profile.certificate, write),
            "serving FRAME lacks CELL permission"
        );
        let repo = GitRepository::open(self.runtime.path(), &id)?;
        if !write {
            return transfer(repo.path());
        }
        let stage = tempfile::Builder::new()
            .prefix("ssh-receive-")
            .tempdir_in(self.runtime.path())?;
        let candidate_path = stage.path().join(format!("{id}.git"));
        unpack_directory(&pack_directory(repo.path())?, &candidate_path)?;
        let candidate = GitRepository::open(stage.path(), &id)?;
        transfer(candidate.path())?;
        // receive-pack exits zero even when every requested update is rejected
        // (the rejection lives in its report-status stream). Discard that stage
        // instead of creating a signed no-op publication/snapshot.
        if candidate.refs()? == repo.refs()? {
            return Ok(());
        }
        candidate.validate_objects()?;
        let refs = candidate
            .refs()?
            .into_iter()
            .filter(|(name, _)| !name.starts_with("refs/comb/"))
            .collect();
        let previous_cell = self.cell(&id)?.clone();
        let previous_control = self.control.clone();
        let previous_path = stage.path().join("previous.git");
        std::fs::rename(repo.path(), &previous_path)?;
        if let Err(error) = std::fs::rename(candidate.path(), repo.path()) {
            std::fs::rename(&previous_path, repo.path())?;
            return Err(error.into());
        }
        if let Err(error) = self.operate(&id, Operation::Publish { refs }) {
            self.cells.insert(id, previous_cell);
            self.control = previous_control;
            std::fs::remove_dir_all(repo.path())?;
            std::fs::rename(previous_path, repo.path())?;
            self.save_control()?;
            return Err(error);
        }
        Ok(())
    }
}

use anyhow::ensure;
