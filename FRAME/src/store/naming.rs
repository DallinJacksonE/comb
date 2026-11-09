use super::*;

/// Stable URL segment: lowercase ASCII alphanumeric runs separated by hyphens.
pub(super) fn slug(name: &str) -> String {
    let mut result = String::new();
    let mut separator = false;
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() {
            if separator && !result.is_empty() {
                result.push('-');
            }
            result.push(byte.to_ascii_lowercase() as char);
            separator = false;
        } else {
            separator = true;
        }
    }
    result
}

impl Store {
    /// Peer transfers omit locally removed CELLs without stopping unrelated sync.
    pub(crate) fn is_cell_deleted(&self, id: &str) -> bool {
        self.control.tombstones.contains(id)
    }

    pub(super) fn validate_cell_name(&self, name: &str, except: Option<&str>) -> Result<String> {
        let name = name.trim();
        if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
            bail!("CELL name must contain 1..120 printable bytes");
        }
        let candidate = slug(name);
        if candidate.is_empty()
            || (candidate.len() == 64 && candidate.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            bail!("CELL name must have a nonempty, non-ID-shaped URL slug");
        }
        if self.cells.values().any(|cell| {
            Some(cell.id.as_str()) != except && slug(&cell.effective_name()) == candidate
        }) {
            bail!("CELL URL slug already exists");
        }
        Ok(name.to_owned())
    }

    pub(super) fn ensure_cell_owner(&self, id: &str) -> Result<()> {
        self.ensure_active()?;
        let cell = self.cell(id)?;
        if cell.owner != self.local.profile.identity
            || !cell.is_frame_authorized(&self.local.profile.certificate, true)
        {
            bail!("only an authorized owner FRAME may rename or delete a CELL");
        }
        Ok(())
    }

    pub fn rename_cell(&mut self, id: &str, name: String) -> Result<CellSummary> {
        self.ensure_cell_owner(id)?;
        let name = self.validate_cell_name(&name, Some(id))?;
        self.operate(id, Operation::Rename { name })
    }

    /// Remove only this FRAME's private state, with a durable reimport barrier.
    pub fn delete_cell(&mut self, id: &str, confirmation: &str) -> Result<()> {
        self.ensure_cell_owner(id)?;
        if confirmation != self.cell(id)?.effective_name() {
            bail!("confirmation must exactly match the current CELL name");
        }
        let snapshots = self.data.join("snapshots");
        let repository = self.runtime.path().join(format!("{id}.git"));
        if snapshots.is_symlink() || repository.is_symlink() {
            bail!("refusing deletion through symlink");
        }
        // Include historical private snapshots, not independent exported backups.
        let mut remove = Vec::new();
        for entry in std::fs::read_dir(&snapshots)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "cell") {
                if entry.file_type()?.is_symlink() {
                    bail!("refusing snapshot deletion through symlink");
                }
                let snapshot: Snapshot = serde_json::from_slice(&std::fs::read(&path)?)?;
                if snapshot.context()?.cell_id == id {
                    remove.push(path);
                }
            }
        }
        let previous = self.control.clone();
        self.control.tombstones.insert(id.to_owned());
        self.control.current.remove(id);
        if let Err(error) = self.save_control() {
            self.control = previous;
            return Err(error);
        }
        // The tombstone commits first: interruption cannot resurrect this repository.
        self.cells.remove(id);
        if repository.exists() {
            std::fs::remove_dir_all(repository)?;
        }
        for path in remove {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Immutable IDs take priority; ambiguous imported/legacy slugs fail closed.
    pub fn resolve_git_cell(&self, name_or_id: &str) -> Result<String> {
        if self.cells.contains_key(name_or_id) {
            return Ok(name_or_id.to_owned());
        }
        if name_or_id.is_empty() || slug(name_or_id) != name_or_id {
            bail!("unknown CELL URL slug");
        }
        let mut matches = self
            .cells
            .values()
            .filter(|cell| slug(&cell.effective_name()) == name_or_id);
        let cell = matches.next().context("unknown CELL URL slug")?;
        if matches.next().is_some() {
            bail!("ambiguous CELL URL slug; use the immutable ID");
        }
        Ok(cell.id.clone())
    }
}
