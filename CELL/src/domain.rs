//! Signed, replayable CELL metadata. See `CELL/DOMAIN.md` for protocol limits.
use crate::{
    Error, FrameCertificate, FramePublic, FrameSecrets, IdentityPublic, Result, SignedRecord,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const GENESIS: &[u8] = b"comb.cell.genesis.v1";
const EVENT: &[u8] = b"comb.cell.event.v1";

/// Identity-level read or write membership in a CELL.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// May read and perform the permitted own-device enrollment operations.
    Read,
    /// May additionally publish data and reconcile pending data contributions.
    Write,
}

/// Minimal issue register value; repeated IDs replace values during replay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    /// Application-selected issue identifier.
    pub id: String,
    /// Issue title.
    pub title: String,
    /// Issue body.
    pub body: String,
    /// Whether the issue is closed.
    pub closed: bool,
}

/// Signed metadata change, authorized against policy at its causal parents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Operation {
    /// Owner-only name change.
    Rename {
        /// New name: nonblank, at most 120 UTF-8 bytes, with no control characters.
        name: String,
    },
    /// Owner-only membership grant or role update.
    Grant {
        /// Full public identity binding to grant membership.
        identity: IdentityPublic,
        /// New membership role.
        role: Role,
    },
    /// Owner-only removal of an identity’s CELL rights.
    Revoke {
        /// Signing-key identifier of the member to remove.
        identity_id: String,
    },
    /// Register a member’s certified device under the causal enrollment policy.
    RegisterFrame {
        /// Complete certificate of the device to register.
        certificate: FrameCertificate,
    },
    /// Permanently deny a device within this CELL.
    RevokeFrame {
        /// Signing-key identifier of the device to revoke.
        frame_id: String,
    },
    /// Apply partial opaque Git ref updates; `refs/comb/` is reserved.
    Publish {
        /// Partial map of ref names to opaque object identifiers.
        refs: BTreeMap<String, String>,
    },
    /// Insert or replace an issue by its identifier.
    AddIssue {
        /// Complete issue value to insert or replace.
        issue: Issue,
    },
    /// Accept an exact list of causally visible pending data versions.
    Adopt {
        /// Exact, nonempty, duplicate-free list of pending data versions.
        version_ids: Vec<String>,
    },
    /// Exclude an exact list of causally visible pending data versions.
    Exclude {
        /// Exact, nonempty, duplicate-free list of pending data versions.
        version_ids: Vec<String>,
    },
}

/// Serializable signed metadata history. Deserialization does not validate trust.
/// Call `validate` before consuming public fields; projections replay signed history.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    /// Genesis signed-record content identifier.
    pub id: String,
    /// Original genesis name; use `effective_name` for accepted renames.
    pub name: String,
    /// Immutable public identity that owns this CELL.
    pub owner: IdentityPublic,
    genesis: SignedRecord,
    versions: BTreeMap<String, SignedRecord>,
}

/// Result of a validated union of two histories sharing the same genesis.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MergeReport {
    /// Newly received records that are neither pending nor excluded.
    pub accepted: usize,
    /// All currently quarantined version IDs in sorted order.
    pub pending: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Genesis {
    name: String,
    owner: IdentityPublic,
    nonce: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    cell_id: String,
    parents: BTreeSet<String>,
    operation: Operation,
}

#[derive(Default)]
struct Graph {
    order: Vec<String>,
    events: BTreeMap<String, Event>,
    ancestors: BTreeMap<String, BTreeSet<String>>,
}
/// Reject changes to an already pinned identity or device binding.
fn bind<T: PartialEq>(map: &mut BTreeMap<String, T>, id: String, value: T) -> Result<()> {
    if map.get(&id).is_some_and(|old| old != &value) {
        return Err(Error::Authentication);
    }
    map.insert(id, value);
    Ok(())
}

#[derive(Default)]
struct Classification {
    pending: BTreeSet<String>,
    excluded: BTreeSet<String>,
}

#[derive(Default)]
struct View {
    name: String,
    members: BTreeMap<String, Role>,
    identities: BTreeMap<String, IdentityPublic>,
    frames: BTreeMap<String, FrameCertificate>,
    revoked: BTreeSet<String>,
    refs: BTreeMap<String, String>,
    issues: BTreeMap<String, Issue>,
    pending: BTreeSet<String>,
    excluded: BTreeSet<String>,
}

/// Lowercase hex Ed25519 identity key; does not include the recovery key.
pub fn identity_id(identity: &IdentityPublic) -> String {
    hex::encode(identity.signing_key)
}
/// Lowercase hex Ed25519 device key; does not include the recipient key.
pub fn frame_id(frame: &FramePublic) -> String {
    hex::encode(frame.signing_key)
}
/// Serialize through a JSON value to obtain this workspace configuration’s sorted keys.
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(value)?)?)
}
/// Encode the signed record content hash as lowercase hexadecimal.
fn record_id(record: &SignedRecord) -> Result<String> {
    Ok(hex::encode(record.id()?))
}

impl Cell {
    /// Create a randomly distinguished signed genesis owned by the certificate identity.
    /// Caller supplies the trusted owner certificate; creation does not externally pin it.
    pub fn create(name: String, frame: &FrameSecrets, cert: &FrameCertificate) -> Result<Self> {
        let genesis = SignedRecord::new(
            frame,
            cert,
            GENESIS,
            &canonical(&Genesis {
                name: name.clone(),
                owner: cert.identity.clone(),
                nonce: crate::random(),
            })?,
        )?;
        Ok(Self {
            id: record_id(&genesis)?,
            name,
            owner: cert.identity.clone(),
            genesis,
            versions: BTreeMap::new(),
        })
    }
    /// Collect DAG records not referenced as parents, including genesis for an empty history.
    fn tips(&self) -> BTreeSet<String> {
        let mut tips: BTreeSet<_> = self.versions.keys().cloned().collect();
        tips.insert(self.id.clone());
        for record in self.versions.values() {
            if let Ok(event) = serde_json::from_slice::<Event>(&record.payload) {
                for parent in event.parents {
                    tips.remove(&parent);
                }
            }
        }
        tips
    }
    /// Hash the sorted current DAG tips; this identifier alone does not validate history.
    pub fn version_id(&self) -> String {
        hex::encode(Sha256::digest(
            canonical(&self.tips()).expect("string serialization"),
        ))
    }
    /// Sign an operation descending from all current tips and validate the candidate.
    /// Returns the new record ID; leaves this CELL unchanged on failure.
    pub fn apply(
        &mut self,
        op: Operation,
        frame: &FrameSecrets,
        cert: &FrameCertificate,
    ) -> Result<String> {
        self.validate()?;
        let record = SignedRecord::new(
            frame,
            cert,
            EVENT,
            &canonical(&Event {
                cell_id: self.id.clone(),
                parents: self.tips(),
                operation: op,
            })?,
        )?;
        let id = record_id(&record)?;
        let mut candidate = self.clone();
        candidate.versions.insert(id.clone(), record);
        candidate.validate()?;
        *self = candidate;
        Ok(id)
    }
    /// Validate and union a peer history with the same exact genesis.
    /// Commits only a valid candidate; pending contributions remain in history.
    pub fn merge(&mut self, other: &Cell) -> Result<MergeReport> {
        self.validate()?;
        if self.id != other.id
            || self.name != other.name
            || self.owner != other.owner
            || self.genesis != other.genesis
        {
            return Err(Error::Authentication);
        }
        other.validate()?;
        let mut candidate = self.clone();
        let mut incoming = BTreeSet::new();
        for (id, record) in &other.versions {
            if let Some(existing) = candidate.versions.get(id) {
                if existing != record {
                    return Err(Error::Authentication);
                }
            } else {
                candidate.versions.insert(id.clone(), record.clone());
                incoming.insert(id.clone());
            }
        }
        let view = candidate.view()?;
        let report = MergeReport {
            accepted: incoming
                .iter()
                .filter(|id| !view.pending.contains(*id) && !view.excluded.contains(*id))
                .count(),
            pending: view.pending.into_iter().collect(),
        };
        *self = candidate;
        Ok(report)
    }
    /// Validate genesis, record encodings, graph structure, signatures, and causal policy.
    /// Does not prove freshness, persistence completeness, or validity of opaque Git objects.
    pub fn validate(&self) -> Result<()> {
        self.view().map(|_| ())
    }
    /// Validate canonical records and build causal order before checking each operation.
    fn graph(&self) -> Result<Graph> {
        let genesis: Genesis = serde_json::from_slice(self.genesis.verify(
            &self.owner,
            &self.genesis.certificate.frame,
            GENESIS,
        )?)?;
        if record_id(&self.genesis)? != self.id
            || genesis.name != self.name
            || genesis.owner != self.owner
            || canonical(&genesis)? != self.genesis.payload
        {
            return Err(Error::Authentication);
        }
        let mut graph = Graph::default();
        for (id, record) in &self.versions {
            let event: Event = serde_json::from_slice(&record.payload)?;
            if record_id(record)? != *id
                || event.cell_id != self.id
                || canonical(&event)? != record.payload
                || event.parents.is_empty()
                || id == &self.id
            {
                return Err(Error::Authentication);
            }
            graph.events.insert(id.clone(), event);
        }
        let mut remaining: BTreeSet<_> = graph.events.keys().cloned().collect();
        while !remaining.is_empty() {
            let ready: Vec<_> = remaining
                .iter()
                .filter(|id| {
                    graph.events[*id]
                        .parents
                        .iter()
                        .all(|p| p == &self.id || graph.ancestors.contains_key(p))
                })
                .cloned()
                .collect();
            if ready.is_empty() {
                return Err(Error::Format);
            }
            for id in ready {
                let mut ancestors = BTreeSet::new();
                for parent in &graph.events[&id].parents {
                    if parent != &self.id {
                        ancestors.insert(parent.clone());
                        ancestors.extend(graph.ancestors[parent].iter().cloned());
                    }
                }
                graph.ancestors.insert(id.clone(), ancestors);
                graph.order.push(id.clone());
                remaining.remove(&id);
            }
        }
        // Check key bindings across the entire signed history, not just current membership.
        let mut identities = BTreeMap::from([(identity_id(&self.owner), self.owner.clone())]);
        let mut frames = BTreeMap::from([(
            frame_id(&self.genesis.certificate.frame),
            self.genesis.certificate.clone(),
        )]);
        for id in &graph.order {
            let record = &self.versions[id];
            let event = &graph.events[id];
            let policy = self.policy(&graph, &graph.ancestors[id]);
            let author = identity_id(&record.certificate.identity);
            let signer = frame_id(&record.certificate.frame);
            let identity = policy
                .identities
                .get(&author)
                .ok_or(Error::Authentication)?;
            record.verify(identity, &record.certificate.frame, EVENT)?;
            bind(&mut identities, author.clone(), identity.clone())?;
            bind(&mut frames, signer.clone(), record.certificate.clone())?;
            let owner = identity == &self.owner;
            let member = policy.members.get(&author).ok_or(Error::Authentication)?;
            let self_enroll = matches!(&event.operation, Operation::RegisterFrame { certificate } if certificate == &record.certificate);
            if policy.revoked.contains(&signer)
                || (!self_enroll && policy.frames.get(&signer) != Some(&record.certificate))
            {
                return Err(Error::Authentication);
            }
            match &event.operation {
                Operation::Rename { name } => {
                    if !owner {
                        return Err(Error::Authentication);
                    }
                    if name.trim().is_empty()
                        || name.len() > 120
                        || name.chars().any(char::is_control)
                    {
                        return Err(Error::Format);
                    }
                }
                Operation::Grant { identity, .. } => {
                    if !owner || identity_id(identity) == identity_id(&self.owner) {
                        return Err(Error::Authentication);
                    }
                    bind(&mut identities, identity_id(identity), identity.clone())?;
                }
                Operation::Revoke {
                    identity_id: target,
                } => {
                    if !owner
                        || target == &identity_id(&self.owner)
                        || !policy.identities.contains_key(target)
                    {
                        return Err(Error::Authentication);
                    }
                }
                Operation::RegisterFrame { certificate } => {
                    let target = identity_id(&certificate.identity);
                    let expected = policy
                        .identities
                        .get(&target)
                        .ok_or(Error::Authentication)?;
                    certificate.verify(expected)?;
                    if let Some(issuer) = certificate.delegation.as_deref() {
                        let issuer_id = frame_id(&issuer.frame);
                        if policy.revoked.contains(&issuer_id)
                            || ((self_enroll || !owner)
                                && policy.frames.get(&issuer_id) != Some(issuer))
                        {
                            return Err(Error::Authentication);
                        }
                    }
                    if (!owner && target != author)
                        || !policy.members.contains_key(&target)
                        || policy.revoked.contains(&frame_id(&certificate.frame))
                    {
                        return Err(Error::Authentication);
                    }
                    bind(
                        &mut frames,
                        frame_id(&certificate.frame),
                        certificate.clone(),
                    )?;
                }
                Operation::RevokeFrame { frame_id: target } => {
                    let certificate = policy.frames.get(target).ok_or(Error::Authentication)?;
                    if !owner && certificate.identity != *identity {
                        return Err(Error::Authentication);
                    }
                }
                Operation::Publish { refs } => {
                    if *member != Role::Write
                        || refs.keys().any(|name| name.starts_with("refs/comb/"))
                    {
                        return Err(Error::Authentication);
                    }
                }
                _ => {
                    if *member != Role::Write {
                        return Err(Error::Authentication);
                    }
                }
            }
        }
        Ok(graph)
    }
    /// Replay selected policy events; concurrent revocation or read grants win.
    fn policy(&self, graph: &Graph, selected: &BTreeSet<String>) -> View {
        let mut view = View::default();
        view.members.insert(identity_id(&self.owner), Role::Write);
        view.identities
            .insert(identity_id(&self.owner), self.owner.clone());
        view.frames.insert(
            frame_id(&self.genesis.certificate.frame),
            self.genesis.certificate.clone(),
        );
        let mut changes: BTreeMap<String, Vec<(String, Option<Role>)>> = BTreeMap::new();
        for id in graph.order.iter().filter(|id| selected.contains(*id)) {
            match &graph.events[id].operation {
                Operation::Grant { identity, role } => {
                    view.identities
                        .insert(identity_id(identity), identity.clone());
                    changes
                        .entry(identity_id(identity))
                        .or_default()
                        .push((id.clone(), Some(*role)));
                }
                Operation::Revoke { identity_id } => {
                    changes
                        .entry(identity_id.clone())
                        .or_default()
                        .push((id.clone(), None));
                }
                Operation::RegisterFrame { certificate } => {
                    view.frames
                        .insert(frame_id(&certificate.frame), certificate.clone());
                }
                Operation::RevokeFrame { frame_id } => {
                    view.revoked.insert(frame_id.clone());
                }
                _ => {}
            }
        }
        for (target, updates) in changes {
            let latest: Vec<_> = updates
                .iter()
                .filter(|(id, _)| {
                    !updates
                        .iter()
                        .any(|(newer, _)| graph.ancestors[newer].contains(id))
                })
                .collect();
            if latest.iter().all(|(_, role)| role.is_some()) {
                view.members.insert(
                    target,
                    if latest.iter().any(|(_, role)| *role == Some(Role::Read)) {
                        Role::Read
                    } else {
                        Role::Write
                    },
                );
            }
        }
        view
    }
    /// Quarantine stale concurrent work and apply causally valid reconciliation decisions.
    fn classify(&self, graph: &Graph, selected: &BTreeSet<String>) -> Classification {
        let mut result = Classification::default();
        let mut decisions: Vec<(String, String, bool)> = Vec::new();
        for id in graph.order.iter().filter(|id| selected.contains(*id)) {
            let cert = &self.versions[id].certificate;
            let operation = &graph.events[id].operation;
            let stale = selected.iter().any(|revocation| {
                if revocation == id
                    || graph.ancestors[revocation].contains(id)
                    || graph.ancestors[id].contains(revocation)
                {
                    return false;
                }
                match &graph.events[revocation].operation {
                    Operation::Revoke {
                        identity_id: target,
                    } => *target == identity_id(&cert.identity),
                    Operation::RevokeFrame { frame_id: target } => {
                        *target == frame_id(&cert.frame) || matches!(operation,
                            Operation::RegisterFrame{certificate} if certificate.delegation.as_deref().is_some_and(|issuer|frame_id(&issuer.frame)==*target))
                    },
                    Operation::Grant {
                        identity,
                        role: Role::Read,
                    } => {
                        identity == &cert.identity
                            && matches!(
                                operation,
                                Operation::Publish { .. }
                                    | Operation::AddIssue { .. }
                                    | Operation::Adopt { .. }
                                    | Operation::Exclude { .. }
                            )
                    }
                    _ => false,
                }
            });
            // Metadata policy does not incorporate Git/issue effects merely by acknowledging
            // their DAG parents. Data descendants, however, need explicit reconciliation.
            let data = matches!(
                operation,
                Operation::Publish { .. } | Operation::AddIssue { .. }
            );
            let dependent = graph.ancestors[id].iter().any(|parent| {
                let policy_dependency = !matches!(
                    graph.events[parent].operation,
                    Operation::Publish { .. }
                        | Operation::AddIssue { .. }
                        | Operation::Adopt { .. }
                        | Operation::Exclude { .. }
                );
                (data || policy_dependency)
                    && result.pending.contains(parent)
                    && !decisions.iter().any(|(decision, target, _)| {
                        target == parent && graph.ancestors[id].contains(decision)
                    })
            });
            if stale || dependent {
                result.pending.insert(id.clone());
                continue;
            }
            match operation {
                Operation::Adopt { version_ids } | Operation::Exclude { version_ids } => {
                    for target in version_ids {
                        decisions.push((
                            id.clone(),
                            target.clone(),
                            matches!(operation, Operation::Exclude { .. }),
                        ));
                    }
                }
                _ => {}
            }
        }
        // Concurrent exclude wins; a later causal decision can supersede an older one.
        for (_, target, _) in &decisions {
            let latest: Vec<_> = decisions
                .iter()
                .filter(|(id, t, _)| {
                    t == target
                        && !decisions.iter().any(|(newer, other, _)| {
                            other == target && graph.ancestors[newer].contains(id)
                        })
                })
                .collect();
            result.pending.remove(target);
            if latest.iter().any(|(_, _, exclude)| *exclude) {
                result.excluded.insert(target.clone());
            }
        }
        result
    }
    /// Reconstruct validated policy and accepted data projections from signed history.
    fn view(&self) -> Result<View> {
        let graph = self.graph()?;
        // A decision must have been valid with exactly the causal evidence it signed.
        for id in &graph.order {
            let operation = &graph.events[id].operation;
            if let Operation::Adopt { version_ids } | Operation::Exclude { version_ids } = operation
            {
                let prior = self.classify(&graph, &graph.ancestors[id]);
                let unique: BTreeSet<_> = version_ids.iter().collect();
                if unique.is_empty()
                    || unique.len() != version_ids.len()
                    || version_ids.iter().any(|target| {
                        !prior.pending.contains(target)
                            || !matches!(
                                graph.events[target].operation,
                                Operation::Publish { .. } | Operation::AddIssue { .. }
                            )
                    })
                {
                    return Err(Error::Authentication);
                }
            }
        }
        let classification = self.classify(&graph, &graph.events.keys().cloned().collect());
        let accepted: BTreeSet<_> = graph
            .events
            .keys()
            .filter(|id| {
                !classification.pending.contains(*id) && !classification.excluded.contains(*id)
            })
            .cloned()
            .collect();
        let mut view = self.policy(&graph, &accepted);
        view.name = self.name.clone();
        view.pending = classification.pending;
        view.excluded = classification.excluded;
        let mut ref_updates: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for id in graph.order.iter().filter(|id| accepted.contains(*id)) {
            match &graph.events[id].operation {
                // Causal order wins; concurrent owner renames use deterministic DAG order.
                Operation::Rename { name } => view.name = name.clone(),
                Operation::Publish { refs } => {
                    for (name, value) in refs {
                        ref_updates
                            .entry(name.clone())
                            .or_default()
                            .push((id.clone(), value.clone()));
                    }
                }
                Operation::AddIssue { issue } => {
                    view.issues.insert(issue.id.clone(), issue.clone());
                }
                _ => {}
            }
        }
        for (name, updates) in ref_updates {
            let latest: Vec<_> = updates
                .iter()
                .filter(|(id, _)| {
                    !updates
                        .iter()
                        .any(|(newer, _)| graph.ancestors[newer].contains(id))
                })
                .collect();
            let distinct: BTreeSet<_> = latest.iter().map(|(_, value)| value).collect();
            if distinct.len() == 1 {
                view.refs.insert(name, latest[0].1.clone());
            } else {
                for (id, value) in latest {
                    view.refs.insert(
                        format!("refs/comb/divergent/{}/{id}", hex::encode(name.as_bytes())),
                        value.clone(),
                    );
                }
            }
        }
        Ok(view)
    }
    /// Replay accepted renames; falls back to the genesis name if validation fails.
    pub fn effective_name(&self) -> String {
        self.view()
            .map(|v| v.name)
            .unwrap_or_else(|_| self.name.clone())
    }
    /// Return current accepted membership, or an empty map on invalid history.
    pub fn members(&self) -> BTreeMap<String, Role> {
        self.view().map(|v| v.members).unwrap_or_default()
    }
    /// Return historical identity bindings, or an empty map on invalid history.
    /// Includes former members; this map alone is not an encryption recipient policy.
    pub fn identities(&self) -> BTreeMap<String, IdentityPublic> {
        self.view().map(|v| v.identities).unwrap_or_default()
    }
    /// Return historical certificates, including revoked devices, or an empty map on error.
    pub fn frames(&self) -> BTreeMap<String, FrameCertificate> {
        self.view().map(|v| v.frames).unwrap_or_default()
    }
    /// Project accepted partial ref updates, preserving divergence under `refs/comb/`.
    /// Returns an empty map if history is invalid; values are opaque to CELL.
    pub fn refs(&self) -> BTreeMap<String, String> {
        self.view().map(|v| v.refs).unwrap_or_default()
    }
    /// Return accepted issues sorted by ID, or an empty list on invalid history.
    pub fn issues(&self) -> Vec<Issue> {
        self.view()
            .map(|v| v.issues.into_values().collect())
            .unwrap_or_default()
    }
    /// Return permanently revoked device IDs, or an empty set on invalid history.
    pub fn revoked_frames(&self) -> BTreeSet<String> {
        self.view().map(|v| v.revoked).unwrap_or_default()
    }
    /// Return sorted quarantined version IDs, or an empty list on invalid history.
    pub fn pending(&self) -> Vec<String> {
        self.view()
            .map(|v| v.pending.into_iter().collect())
            .unwrap_or_default()
    }
    /// Check exact registered certificate, membership, and device revocation.
    /// With `write`, additionally require write membership. Invalid history returns false.
    /// This is CELL-local policy, not global lifecycle or enrollment authorization.
    pub fn is_frame_authorized(&self, cert: &FrameCertificate, write: bool) -> bool {
        self.view().is_ok_and(|v| {
            v.frames.get(&frame_id(&cert.frame)) == Some(cert)
                && cert.verify(&cert.identity).is_ok()
                && !v.revoked.contains(&frame_id(&cert.frame))
                && v.members
                    .get(&identity_id(&cert.identity))
                    .is_some_and(|r| !write || *r == Role::Write)
        })
    }
}
