# Signed CELL domain model

`comb_cell::domain` is a reusable in-memory, serializable metadata model. It uses
the existing `SignedRecord`, certificate verification, Ed25519 signatures, and
SHA-256 primitives; it does not implement networking, storage, encryption, or Git.
Unaudited prototype, not a production security protocol.

## Public contract

```rust
use comb_cell::{FrameCertificate, FramePublic, FrameSecrets, IdentityPublic, Result};
use comb_cell::domain::{Cell, Issue, MergeReport, Operation, Role, identity_id, frame_id};
use std::collections::{BTreeMap, BTreeSet};
// Role::Read / Role::Write serialize as "read" / "write".
// Issue { id: String, title: String, body: String, closed: bool }
// Operation variants:
// Grant { identity: IdentityPublic, role: Role }
// Revoke { identity_id: String }
// RegisterFrame { certificate: FrameCertificate }
// RevokeFrame { frame_id: String }
// Publish { refs: BTreeMap<String, String> }
// AddIssue { issue: Issue }
// Adopt { version_ids: Vec<String> }
// Exclude { version_ids: Vec<String> }
```

`Cell` derives `Clone`, `Serialize`, and `Deserialize`. Public fields are
`id: String`, `name: String`, and `owner: IdentityPublic`. The signed genesis and
version-record map are serialized but private. Deserialization is **not** trust
validation. Call `validate()` on persisted state before using its public fields.

Methods (all public):

- `Cell::create(name: String, frame: &FrameSecrets, cert: &FrameCertificate) -> Result<Cell>`
- `apply(&mut self, op: Operation, frame: &FrameSecrets, cert: &FrameCertificate) -> Result<String>`
- `merge(&mut self, other: &Cell) -> Result<MergeReport>`
- `validate(&self) -> Result<()>`
- `version_id(&self) -> String`
- `members(&self) -> BTreeMap<String, Role>`
- `identities(&self) -> BTreeMap<String, IdentityPublic>`
- `frames(&self) -> BTreeMap<String, FrameCertificate>`
- `is_frame_authorized(&self, cert: &FrameCertificate, write: bool) -> bool`
- `refs(&self) -> BTreeMap<String, String>`
- `issues(&self) -> Vec<Issue>`
- `revoked_frames(&self) -> BTreeSet<String>`
- `pending(&self) -> Vec<String>`

`identity_id(&IdentityPublic) -> String` and `frame_id(&FramePublic) -> String`
return lowercase hex signing keys. `MergeReport` derives serialization and has
`accepted: usize` (newly received versions that are neither pending nor excluded)
and `pending: Vec<String>` (all currently pending IDs, sorted). Duplicate incoming
records produce no version, no new acceptance count, and no key-rotation loop.
Errors reuse `comb_cell::Error`: authentication, format, or JSON serialization.

## Authority and enrollment

The initial certificate's identity is the single immutable owner and initial
write member. Creation checks that the signing secret matches the certificate.
Only the owner may grant, downgrade, or revoke identity rights; the owner cannot
be removed or downgraded. Grants pin the **whole** public identity, including its
recovery key. A signing-key identifier cannot substitute a different recovery key.

Ordinary writes require a registered, nonrevoked certificate for a write member.
A read member cannot publish, add issues, adopt, or exclude. Registration is the
narrow exception: a member may sign `RegisterFrame` using that exact new,
identity-certified FRAME to enroll itself. Existing registered members may also
register their own additional FRAMEs. The owner may register any current member's
certificate (for immediate recipient-envelope creation). Registration never
restores an already-revoked FRAME key, even with a new root-signed certificate.

A registered member may revoke a FRAME of its own identity; the owner may revoke
any enrolled FRAME **for this CELL**. Neither operation changes identity rights.
This module never requests global device destruction: a FRAME lifecycle layer
must distinguish own-identity revocation from another CELL owner's local denial.
FRAME bindings include signing and encryption public keys and the full certificate.
Key substitution is rejected across the entire history, including old records.

`identities()` and `frames()` retain historical enrolled bindings, including
revoked/nonmember identities and FRAMEs. **Never use these maps alone as recipient
policy.** Use `members()`, `revoked_frames()`, and `is_frame_authorized()` to select
active recipients. Projection getters return empty maps/lists, and authorization
returns false, if validation fails; use `validate()` to obtain the actual error.

## Signed graph and merge trust

Genesis includes a random 32-byte nonce, name, and owner and is signed under
`comb.cell.genesis.v1`. Each event payload contains `cell_id`, sorted unique
`parents`, and `operation`, signed under `comb.cell.event.v1`. Event JSON is
canonicalized through `serde_json::Value` (sorted object keys with this workspace's
serde_json configuration); BTree collections give sorted map/set contents.
Noncanonical payload encodings are rejected. Version IDs use the existing
`SignedRecord::id()` SHA-256 content identifier, including signature and certificate.
The CELL ID is its genesis-record ID. `version_id()` hashes canonical JSON of the
sorted current tip set; it is a state identifier, not a separately signed record.

Every successful `apply`, even a metadata-only or semantically redundant change,
signs a version with **all** current tips as parents. Merging only unions existing
records; an explicit application change creates the next signed version.

Merge validates the local state, requires the exact pinned local genesis, owner,
name, and CELL ID, validates the complete incoming DAG independently, and validates
the candidate union again. Record IDs, canonical payloads, signatures, enrolled
key bindings, domains, membership, and authority at causal parents are checked.
Missing parents and cycles fail via iterative topological traversal (no recursive
DAG traversal). A malicious peer cannot make unsigned cached membership trusted:
all projections are derived from signed history. Apply and merge are transactional.
A malformed or unauthorized descendant fails the operation without mutating local
state. Locally persisted rollback/completeness still needs external checkpoints.

Concurrent identity policies use causally maximal changes: concurrent revoke wins,
and concurrent Read/Write grants resolve to Read. A later causal owner grant may
restore identity rights. FRAME revocation is permanent. There are no wall clocks
or globally meaningful timestamps.

## Revocation and exact reconciliation

A contribution that is an ancestor of a relevant revocation remains accepted:
the revocation causally acknowledges that work. Descendants must satisfy the new
policy or are rejected outright. Concurrent contributions relying on the old
policy are retained as **pending**, not silently integrated. A Write-to-Read
downgrade similarly quarantines concurrent writes. Data descendants of unresolved
pending work are also pending, conservatively treating DAG ancestry as dependence.
Policy-only changes do not absorb Git/issue effects merely by acknowledging their
parents, so pending data cannot suppress an otherwise valid owner revocation.
Policy descendants of quarantined policy are themselves quarantined.

Any authorized writer, not just the owner, may adopt or exclude a nonempty,
duplicate-free **exact list** of pending Publish/AddIssue IDs visible in that
decision's causal history. No implicit ancestor/descendant adoption occurs.
Decisions cannot reference unknown, already-resolved, or not-yet-pending versions.
Original signed authorship is never rewritten. Concurrent exclusion wins over
adoption. Excluded and pending records remain in serialized history but not in
accepted refs/issues. After exclusion, subsequent data versions can proceed;
this does not prove that opaque Git contents are free of excluded code.

Stale-policy records themselves are quarantined, not adoptable/excludable through
these data-reconciliation operations. Resolving complex concurrent owner-device
policy forks requires a future policy-recovery protocol; this conservative
prototype does not silently turn data adoption into authority escalation.

## Ref and issue projections

Publish is a **partial ref update**, not an entire-repository replacement.
For each ref, a causal newer publication supersedes the older one. Concurrent
identical values coalesce. Divergent values survive as:

`refs/comb/divergent/<hex UTF-8 original ref name>/<full version ID>`

The ambiguous ordinary ref is omitted. `refs/comb/` is reserved and cannot be
published directly. A later publication descending from all tips explicitly
resolves the divergence. Git ancestry/fast-forward checks and object validation
belong to FRAME: this model treats ref values as opaque strings.

Issues are returned sorted by issue ID. Repeated IDs deterministically replace
previous values by topological replay, ties by signed version ID. This minimal
issue register is not a field-level issue CRDT; full concurrent issue editing is
not implemented. Signed records retain overwritten history for inspection.

## Boundary requirements and limitations

The caller must limit serialized byte size, record count, graph depth, parent
fan-out, strings, ref counts, and reconciliation lists **before** deserializing or
validating untrusted inputs. Replay repeatedly reconstructs causal policy and is
intentionally not optimized for large DAGs. Input limits are not hidden constants
inside this reusable model.

FRAME must separately implement Git validity, encrypted snapshots and fresh
per-version keys/envelopes, durable atomic persistence, transport authentication,
recipient selection, authenticated acceptance/checkpoint exchange, cleanup preview,
and lifecycle handling. This model cannot infer real-time ordering of disconnected
work, inspect whether opaque Git changes depend on excluded commits, retract old
keys, prove backup completeness, or prevent copied code. Pending versions must not
execute workflows or be served as accepted branch/issue state.

Run `cargo test -p comb-cell --test domain` and
`cargo clippy -p comb-cell --all-targets -- -D warnings`.
