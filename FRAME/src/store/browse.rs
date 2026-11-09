//! Read-only repository browsing shares the Git permission boundary.
use super::Store;
use crate::git::{GitRepository, RepositoryBlob, RepositoryHistory, RepositoryTree};
use anyhow::{Context, Result, bail};

impl Store {
    /// Fixed-size history pages share the tree/blob authorization and revision seam.
    pub fn repository_history(
        &self,
        id: &str,
        revision: Option<&str>,
        offset: usize,
    ) -> Result<RepositoryHistory> {
        let repo = self.browsable_repository(id)?;
        anyhow::ensure!(offset <= 10000, "history offset exceeds 10000");
        let revision = self.browse_revision(id, revision, &repo)?;
        if let Some(revision) = revision {
            return repo.browse_history(&revision, offset);
        }
        Ok(RepositoryHistory {
            revision,
            commits: vec![],
            has_more: false,
            next_offset: None,
        })
    }

    /// Read a committed directory; empty repositories have an empty root view.
    pub fn repository_tree(
        &self,
        id: &str,
        revision: Option<&str>,
        path: &str,
    ) -> Result<RepositoryTree> {
        let repo = self.browsable_repository(id)?;
        let revision = self.browse_revision(id, revision, &repo)?;
        match revision {
            Some(revision) => repo.browse_tree(&revision, path),
            None if path.is_empty() => Ok(RepositoryTree {
                revision: None,
                path: String::new(),
                entries: vec![],
            }),
            None => bail!("repository is empty"),
        }
    }

    /// Read a bounded Git blob, never a runtime filesystem path.
    pub fn repository_blob(
        &self,
        id: &str,
        revision: Option<&str>,
        path: &str,
    ) -> Result<RepositoryBlob> {
        let repo = self.browsable_repository(id)?;
        let revision = self
            .browse_revision(id, revision, &repo)?
            .context("repository is empty")?;
        repo.browse_blob(&revision, path)
    }

    fn browsable_repository(&self, id: &str) -> Result<GitRepository> {
        self.ensure_active()?;
        if !self
            .cell(id)?
            .is_frame_authorized(&self.local.profile.certificate, false)
        {
            bail!("FRAME lacks repository permission");
        }
        GitRepository::open(self.runtime.path(), id)
    }

    fn browse_revision(
        &self,
        id: &str,
        requested: Option<&str>,
        repo: &GitRepository,
    ) -> Result<Option<String>> {
        let refs = self.cell(id)?.refs();
        let visible: Vec<_> = refs
            .iter()
            .filter(|(name, _)| name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
            .collect();
        let Some(requested) = requested.filter(|value| !value.is_empty()) else {
            let default = refs
                .get("refs/heads/main")
                .or_else(|| visible.first().map(|(_, hash)| *hash));
            return default.map(|hash| repo.browse_commit(hash)).transpose();
        };
        // The GUI's default selector names main even before the first push.
        if visible.is_empty() && requested == "refs/heads/main" {
            return Ok(None);
        }
        if let Some((_, hash)) = visible.iter().find(|(name, _)| name.as_str() == requested) {
            return Ok(Some(repo.browse_commit(hash)?));
        }
        // Only commits reachable from accepted visible branches/tags are browsable.
        if matches!(requested.len(), 40 | 64)
            && requested.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            let commit = repo.browse_commit(requested)?;
            for (_, tip) in visible {
                if repo.browse_is_ancestor(&commit, &repo.browse_commit(tip)?)? {
                    return Ok(Some(commit));
                }
            }
        }
        bail!("unknown or unadvertised repository revision")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use comb_cell::domain::Operation;
    use std::{collections::BTreeMap, path::Path, process::Command};

    fn git(work: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(work)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "History Fixture")
            .env("GIT_AUTHOR_EMAIL", "history@test")
            .env("GIT_COMMITTER_NAME", "History Fixture")
            .env("GIT_COMMITTER_EMAIL", "history@test")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().into()
    }

    #[test]
    fn history_only_reads_commits_reachable_from_published_visible_refs() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("frame");
        identity::initialize(
            &data,
            "Fixture",
            "history@test",
            b"password",
            &directory.path().join("recovery"),
        )
        .unwrap();
        let mut store = Store::open(&data, b"password").unwrap();
        let cell = store.create_cell("History permissions".into()).unwrap();
        let repo = GitRepository::open(store.runtime.path(), &cell.id).unwrap();
        let work = directory.path().join("work");
        std::fs::create_dir(&work).unwrap();
        git(&work, &["init", "--initial-branch=main"]);
        git(&work, &["commit", "--allow-empty", "-m", "visible root"]);
        let root = git(&work, &["rev-parse", "HEAD"]);
        git(&work, &["commit", "--allow-empty", "-m", "visible tip"]);
        let tip = git(&work, &["rev-parse", "HEAD"]);
        git(&work, &["push", repo.path().to_str().unwrap(), "main"]);
        git(&work, &["checkout", "--orphan", "secret"]);
        git(&work, &["commit", "--allow-empty", "-m", "private history"]);
        let secret = git(&work, &["rev-parse", "HEAD"]);
        git(
            &work,
            &[
                "push",
                repo.path().to_str().unwrap(),
                "HEAD:refs/heads/unpublished",
            ],
        );
        // The object really exists; rejecting it must be an authorization decision.
        assert_eq!(repo.browse_commit(&secret).unwrap(), secret);
        let mut refs = BTreeMap::new();
        refs.insert("refs/heads/main".into(), tip.clone());
        refs.insert("refs/tags/release".into(), root.clone());
        store
            .operate(&cell.id, Operation::Publish { refs })
            .unwrap();
        git(
            &work,
            &[
                "--git-dir",
                repo.path().to_str().unwrap(),
                "update-ref",
                "refs/comb/private",
                &secret,
            ],
        );
        assert!(repo.refs().unwrap().contains_key("refs/comb/private"));
        for revision in [None, Some("refs/heads/main"), Some(tip.as_str())] {
            let history = store.repository_history(&cell.id, revision, 0).unwrap();
            assert_eq!(history.revision.as_deref(), Some(tip.as_str()));
            assert_eq!(
                history
                    .commits
                    .iter()
                    .map(|c| c.id.as_str())
                    .collect::<Vec<_>>(),
                vec![tip.as_str(), root.as_str()]
            );
        }
        for revision in [root.as_str(), "refs/tags/release"] {
            let history = store
                .repository_history(&cell.id, Some(revision), 0)
                .unwrap();
            assert_eq!(history.commits.len(), 1);
            assert_eq!(history.commits[0].id, root);
        }
        for revision in [
            secret.as_str(),
            "refs/comb/private",
            "refs/heads/unpublished",
            "HEAD",
            "refs/heads/main~1",
            "refs/heads/main^{commit}",
            "--all",
        ] {
            assert!(
                store
                    .repository_history(&cell.id, Some(revision), 0)
                    .is_err(),
                "{revision}"
            );
        }
    }
}
