//! Revoked-FRAME recovery. Validation is read-only until every policy transition passes.
use super::*;
use crate::{
    identity::EnrollmentGrant,
    restore::{RESTORE_DOMAIN, RestoreAuthorization, RestoreRequest},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use comb_cell::SignedRecord;

impl Store {
    pub fn prepare_restore(&self, password: &[u8]) -> Result<RestoreRequest> {
        let Lifecycle::Revoked { revocation, .. } = &self.control.lifecycle else {
            bail!("FRAME is not awaiting restoration");
        };
        let pending = self.data.join("restore-pending");
        let path = pending.join("request.json");
        if path.is_file() {
            return Ok(serde_json::from_slice(&std::fs::read(path)?)?);
        }
        let request = RestoreRequest {
            enrollment: identity::prepare_enrollment(&pending, password)?,
            identity: self.profile().identity.clone(),
            target_frame: self.profile().frame_id(),
            revocation: revocation.clone(),
        };
        identity::atomic_write(&path, &serde_json::to_vec(&request)?)?;
        Ok(request)
    }
    /// A live, separately authorized FRAME signs a restore-specific challenge response.
    pub fn issue_restore(&self, request: &RestoreRequest) -> Result<SignedRecord> {
        self.ensure_active()?;
        if request.identity != self.profile().identity
            || request.target_frame == self.profile().frame_id()
            || request.revocation.is_empty()
            || request.revocation.len() > 128
        {
            bail!("invalid restore target or identity");
        }
        let known = self
            .control
            .peers
            .get(&request.target_frame)
            .is_some_and(|p| p.profile.identity == request.identity)
            || self.cells.values().any(|c| {
                c.frames()
                    .get(&request.target_frame)
                    .is_some_and(|f| f.identity == request.identity)
            });
        if !known {
            bail!("restore target is not a known FRAME of this identity");
        }
        let grant = identity::authorize_from_frame(&self.local, &request.enrollment)?;
        let authorization = RestoreAuthorization {
            grant,
            target_frame: request.target_frame.clone(),
            revocation: request.revocation.clone(),
        };
        Ok(SignedRecord::new(
            &self.local.frame,
            &self.profile().certificate,
            RESTORE_DOMAIN,
            &serde_json::to_vec(&authorization)?,
        )?)
    }
    pub fn restore_credential(
        &mut self,
        credential: &str,
        password: &[u8],
    ) -> Result<RestoreOutcome> {
        if self.is_active() {
            bail!("FRAME is not revoked");
        }
        let validated = self
            .validate_restore(credential, password)
            .and_then(|replacement| {
                let mut cells = self.cells.clone();
                for cell in cells.values_mut() {
                    cell.apply(
                        Operation::RegisterFrame {
                            certificate: replacement.profile.certificate.clone(),
                        },
                        &replacement.frame,
                        &replacement.profile.certificate,
                    )?;
                    cell.apply(
                        Operation::RevokeFrame {
                            frame_id: self.profile().frame_id(),
                        },
                        &replacement.frame,
                        &replacement.profile.certificate,
                    )?;
                }
                Ok((replacement, cells))
            });
        let (preview, cells) = match validated {
            Ok(value) => value,
            Err(_) => {
                let result = self.restore_attempt(false)?;
                if result == RestoreOutcome::ResetRequired {
                    self.reinitialize(password)?;
                }
                return Ok(result);
            }
        };
        // Only now consume pending keys. Rejected grants leave the original request usable.
        let pending = self.data.join("restore-pending");
        let replacement = identity::complete_enrollment(
            &pending,
            password,
            &preview.profile,
            &self.profile().identity,
        )?;
        drop(preview);
        for name in ["node.vault", "profile.json"] {
            identity::atomic_write(&self.data.join(name), &std::fs::read(pending.join(name))?)?;
        }
        self.local = replacement;
        self.cells = cells;
        self.control.lifecycle = Lifecycle::Active;
        for id in self.cells.keys().cloned().collect::<Vec<_>>() {
            self.persist_cell(&id)?;
        }
        self.save_control()?;
        if pending.is_symlink() {
            bail!("refusing cleanup through symlink");
        }
        std::fs::remove_dir_all(pending)?;
        Ok(RestoreOutcome::Restored)
    }
    fn validate_restore(&self, credential: &str, password: &[u8]) -> Result<LocalIdentity> {
        if credential.len() > 65_536 {
            bail!("oversized restore credential");
        }
        let record: SignedRecord = serde_json::from_slice(&STANDARD.decode(credential.trim())?)?;
        let issuer = &record.certificate;
        let issuer_id = comb_cell::domain::frame_id(&issuer.frame);
        let trusted = self
            .control
            .peers
            .get(&issuer_id)
            .is_some_and(|p| p.profile.certificate == *issuer)
            || self
                .cells
                .values()
                .any(|c| c.frames().get(&issuer_id) == Some(issuer));
        if issuer_id == self.profile().frame_id()
            || !trusted
            || self
                .cells
                .values()
                .any(|c| c.revoked_frames().contains(&issuer_id))
        {
            bail!("restore requires another trusted, nonrevoked FRAME");
        }
        let bytes = record.verify(&self.profile().identity, &issuer.frame, RESTORE_DOMAIN)?;
        let authorization: RestoreAuthorization = serde_json::from_slice(bytes)?;
        let Lifecycle::Revoked { revocation, .. } = &self.control.lifecycle else {
            bail!("no active revocation challenge");
        };
        if authorization.target_frame != self.profile().frame_id()
            || &authorization.revocation != revocation
        {
            bail!("restore credential targets a different FRAME or revocation");
        }
        let grant: EnrollmentGrant = authorization.grant;
        if grant.certificate.delegation.as_deref() != Some(issuer) {
            bail!("restore enrollment issuer differs from challenge signer");
        }
        identity::preview_enrollment(
            &self.data.join("restore-pending"),
            password,
            &grant,
            &self.profile().identity,
        )
    }
    fn reinitialize(&mut self, password: &[u8]) -> Result<()> {
        let name = self.profile().name.clone();
        let email = self.profile().email.clone();
        for entry in ["node.vault", "profile.json", "root.vault", "control.enc"] {
            let path = self.data.join(entry);
            if path.is_symlink() {
                bail!("refusing reset through symlink");
            }
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        let pending = self.data.join("restore-pending");
        if pending.is_symlink() {
            bail!("refusing reset through symlink");
        }
        if pending.exists() {
            std::fs::remove_dir_all(pending)?;
        }
        let recovery = self
            .data
            .join(format!("reset-{}.recovery", uuid::Uuid::new_v4()));
        self.local = identity::initialize(&self.data, &name, &email, password, &recovery)?;
        self.runtime = tempfile::Builder::new()
            .prefix("comb-frame-runtime-")
            .tempdir()?;
        self.cells.clear();
        self.control = Control::default();
        self.save_control()
    }
}
