# COMB Design Discussion

This document records confirmed design decisions alongside recommendations and open questions. Only items explicitly marked as confirmed are accepted decisions. The feature set and command reference are maintained in [readme.md](readme.md).

The README is now the consolidated baseline containing agreed decisions and approved recommendations only. This discussion retains protocol questions and unapproved alternatives. In earlier passages, "device key" means **FRAME key**: there is one user FRAME per device, with its own key. Identity keys are separate and also held within user FRAMEs; the exact distribution and protection of identity/recovery private capabilities still requires a protocol.

## 1. Standard Git Repositories; FRAME as Remote Manager

**Confirmed decision:** Working copies remain ordinary Git repositories using `.git`. There is no `.comb` file or directory and no separate COMB repository format. Users access FRAME to create a managed remote repository, then configure their Git repository to point at that remote. Existing Git commands and IDE integrations continue to work normally.

**Confirmed decision:** FRAME treats repositories created within it as CELLs and tracks their ownership and permission metadata. FRAME owns remote repository management, collaboration metadata, and peer-to-peer replication; working copies remain ordinary Git repositories.

**Confirmed decision:** The `comb` CLI is exclusively for interacting with FRAME and managing ICE services. It exposes no Git-wrapper commands or aliases. Repository initialization, remote configuration, staging, commits, branches, resets, cloning, pushing, fetching, and pulling all use standard Git. FRAME identity, keys, device setup, GUI access, service administration, and ICE management remain in scope for `comb`.

Git already has pack-transfer protocols and negotiation for sending the objects needed to update a peer.[1] **Recommendation:** Reuse Git implementations and protocols rather than inventing a second code-history format.

Remaining design questions:

- Which standard Git transport does FRAME expose, and what remote URL and authentication does it provide?
- How does FRAME store managed Git repositories and collaboration metadata? A bare Git repository per CELL is an option, not yet a decision.
- How does an authenticated Git connection map to COMB identity and CELL permissions?
- What FRAME management interface creates remote repositories and exposes their URLs? Keep this separate from local Git initialization and remote configuration.
- How can users export or back up FRAME-managed collaboration metadata independently of their standard Git repositories?

**Consequence:** Ordinary Git edits are legitimate inputs, not corruption. Sealing and validation must protect FRAME-managed metadata and remote state without blocking standard local Git activity.

## 2. Separate Replication, Checkout, and Integration

**Confirmed decision:** Developers interact with FRAME through standard Git remotes. FRAME-to-FRAME replication is separate from the user's local Git workflow; it is not a replacement for Git push, fetch, or pull semantics.

The workflow is:

1. The user creates a remote repository through FRAME and adds its URL to a standard Git repository, or clones it from FRAME. The remote name is user-selected.
2. Local edits, staging, commits, and branches use ordinary Git and require no FRAME involvement.
3. `git push` sends updates to the configured FRAME remote. FRAME manages remote-side acceptance and replication to peers.
4. Collaborators use `git fetch` or `git pull` against their own configured FRAME remote to obtain replicated updates. Integration follows their normal Git configuration and commands.


**Recommendation:** FRAME replication must not silently modify a developer's working tree. Keep any replication publication records internal to FRAME rather than requiring custom client commands or client-side signing hooks. The precise remote-update authentication and signing mechanism remains open.


**Confirmed decision:** Preserve concurrent branch tips, automatically fast-forward when one includes the other, and surface divergent tips for explicit Git integration. Do not choose a winner by counter or wall-clock timestamp. The representation and user-facing Git refs for divergence remain open.

Define success separately for:

- Saved locally and queued.
- Acknowledged by at least one authorized replica.
- Replicated to a configured durability target.
- Integrated into a particular branch.

**Confirmed decision:** A successful Git push acknowledges durable acceptance by the target FRAME, with peer replication health reported separately. An unavailable target remote is different from an available FRAME whose peers are offline; a normal Git push cannot succeed when its target cannot be reached. Specify crash-safe persistence and replication-status reporting in the protocol.

## 3. Authorized Tree, Revocation, and Adoption

**Confirmed decision:** FRAME maintains an authorized tree for each CELL. Known revocations propagate between replicas and are enforced when learned. Disconnected users can continue local work, but sharing through FRAME requires connectivity and is subject to the authorization knowledge available to the participating FRAMEs.

### CELL version and revocation boundary

**Confirmed decision:** Every valid CELL metadata change creates a new CELL version containing metadata and the Git tree/repository state, even when no code changes. A revocation is therefore a version transition with a fresh data-key/envelope update; it does not wait for an unrelated later merge or commit. Authorized FRAMEs validate the new state and obtain their envelopes as they request subsequent updates. Version/key creation and delivery to an offline peer are separate events.

Bob retains older code and keys legitimately obtained before revocation. Versions following the revocation policy omit him from new recipient envelopes and reject his normal contribution attempts. The unchanged Git tree in a metadata-only version does not restore his permission or make old keys valid for new encrypted state.

**Confirmed scope:** No remote deletion, DRM, or promise to prevent a former collaborator from retaining or intentionally leaking previously accessible code. NDA and contractual enforcement are outside the protocol. Enforcing future-version permissions remains in scope. This resolves retained-copy concerns; do not reopen them as a requirement to erase Bob's machine.

The precise version record, deduplication of CRDT merges, concurrent-version reconciliation, and physical encryption/storage layout remain open. A CELL version is not necessarily a new Git commit or a globally ordered version counter.

### Alice, Bob, and Steve

Alice owns the repository and revokes Bob's rights while Bob is offline.

| Situation | Intended behavior |
| --- | --- |
| Bob remains offline. | He can make local Git changes but cannot share them with Steve through FRAME until reconnecting. |
| Steve knows Alice's revocation before meeting Bob. | The revocation propagates to Bob's FRAME, his local authorized tree removes his access, and his changes are rejected for normal authorized sharing. |
| Bob and Steve connect after Alice goes offline, without having learned the revocation. | Steve may receive Bob's changes under stale authorization. Their acceptance is subject to later reconciliation. |
| Alice reconnects and her authorization history reaches Steve. | FRAME identifies affected commits and warns Steve that they came from Bob after his repository rights were revoked. |
| Steve affirms adoption. | Steve explicitly accepts responsibility for the affected code, and his CELL can merge with Alice's through the adoption flow. |
| Steve declines adoption. | `comb clean` removes the affected Bob commits from Steve's FRAME-managed CELL state. |
| A persistent, network-accessible FRAME hosts the CELL and knows the revocation. | It distributes the policy update to Steve and rejects Bob's changes. |

**Confirmed decision:** `comb clean` is a FRAME-side authorization-reconciliation command, not a Git wrapper. It does not restore the removed Git convenience commands or mean the same thing as `git clean`.

**Confirmed decision:** Any collaborator with current write access can adopt flagged contributions without additional owner approval. Write access already delegates the responsibility to fix and integrate contributions. Adoption preserves the original author's attribution and does not transfer CELL ownership.

**Confirmed design direction:** Classify authorization using authorized-tree history and authenticated FRAME acceptance records, not Git commit timestamps. Previously accepted authorized history remains valid after revocation. New contributions from a revoked identity without recognized prior acceptance are flagged, and work accepted by stale peers enters adoption-or-cleanup reconciliation. Legitimate unpublished offline work may need adoption. Exact evidence rules, trusted acceptance records, and concurrent-policy handling remain open.

**Confirmed direction:** Track received, validated, accepted, pending-reconciliation, adopted, and excluded contribution states. Pending work remains inspectable but cannot automatically integrate or execute workflows. Adoption binds an exact contribution set rather than granting blanket approval to future work. Specify precise transitions, authorization, and inspection visibility before implementation.

**Confirmed direction:** Use authenticated, signed FRAME records binding submission, acceptance, and adoption actions to exact commits and policy history. Distinguish Git author, authenticated submitter, accepting FRAME, and adopter. This enforces recorded provenance, not detection of every copied or rewritten contribution's original source.

**Confirmed cleanup safeguards:** Account for dependent work, preserve original history for recovery, preview affected commits and the proposed accepted result, and require confirmation before changing FRAME state. Existing clones reconcile through normal Git. These safeguards do not yet select a revert, ref-rewrite, or history-reconstruction algorithm.

### Boundaries of the decision

- Revocation removes managed access, not Bob's ability to edit his own local files or retain previously received code.
- An offline or partitioned FRAME may accept contributions under stale policy. Learning the revocation triggers reconciliation; it cannot retroactively prevent the earlier transfer.
- A persistent FRAME can only enforce revocations it has received. It is not automatically an authority above Alice, nor a globally current source during a partition.
- Adoption means responsibility for integrating a contribution, not transfer of Alice's repository ownership or reassignment of Bob's original authorship.

### Remaining protocol questions

1. **Acceptance evidence:** Which authenticated prior-acceptance records qualify to preserve authorization, and how are stale, forged, or self-issued records handled? The accepted direction flags unpublished work without recognized prior acceptance rather than trusting author timestamps.
2. **Record protocol:** Define signature scope, canonical serialization, key validation, and provenance verification for the accepted signed FRAME record approach without introducing custom Git client commands.
3. **Adoption validation:** Write access is sufficient; no owner approval is needed. How is the adopter's current authorization checked when an adoption arrives from a stale or subsequently revoked peer, and which exact contribution set does the decision cover?
4. **Adoption representation:** Does FRAME record an authorization override over the existing commits, or require a new authorized integration? Preserve attribution and record the adopting identity, policy context, and exact affected commits.
5. **Cleanup semantics:** Does `comb clean` remove refs, revert changes, or reconstruct an accepted history? Dependent-work analysis, recoverable original history, preview, and confirmation are required. Define merge commits, Steve's dependent commits, already-shared history, and clone reconciliation without assuming a destructive reset.
6. **Command targeting:** How does `comb clean` select the CELL and reconciliation case? Specify the required preview/confirmation format, recovery retention, and behavior if new updates arrive between preview and confirmation.
7. **Policy conflicts:** How are concurrent permission changes, later re-grants, ownership transfers, and stale grants handled? Receiving a different tree must not by itself authorize arbitrary policy changes.
8. **Reconciliation transitions:** Inspection is allowed and automatic integration/workflow execution is blocked while unresolved. Define how accepted refs, inspection access, adoption, exclusion, and concurrent decisions converge across peers.

### Supporting recommendations

**Recommendation:** Use mergeable structures for collaboration content, but specify security-sensitive policy independently.

Candidate data categories:

| Category | Suggested treatment |
| --- | --- |
| Code | Git commits, refs, and explicit integration. |
| Issues, comments, milestones, and collaborative documentation | CRDTs or immutable events with field-specific conflict rules. |
| Membership, roles, ownership, device authorization, and revocation | Authorized-tree history, with signed policy operations and explicit authority/conflict rules recommended. |
| Presence, transfer progress, and caches | Ephemeral or rebuildable state; not durable repository authority. |

Do not use "last timestamp wins" as the default rule for ownership or permission changes. Define who can issue each operation, what policy history authorizes it, and how every replica reaches the same accepted state.

The owner-issued revocation and later adoption/cleanup flow above is confirmed. Whether additional administrators may independently issue policy changes is still open. **Recommendation:** Authenticate policy history and adoption decisions; do not use an untrusted author timestamp as proof that a change preceded revocation.

## 4. Replace "Sealed" with a Precise Integrity Model

**Recommendation:** Retain sealing as a user-facing concept, but define it as authenticated state, not an assertion that local files cannot be edited.

A candidate publication record would bind:

- CELL identifier.
- Publisher/device identifier.
- Parent publication identifiers.
- Git commit/ref information and metadata content identifiers.
- Applicable policy revision.
- Record format version and a signature over the canonical record.

Use separate checks for separate failures:

- Content hashes: do the bytes match their identifiers?
- Signatures: did the corresponding key sign this record?
- Authorization: was that key allowed to make this change under the applicable policy?
- Ancestry and retained checkpoints: does the update extend a known history, or attempt an unexpected rollback/fork?

A hash stored next to editable data does not establish who authorized that data. Filesystem permissions are useful defense in depth, not the complete trust model.

Preserve the proposed recovery feature, but define recovery as restoring a known valid metadata state while retaining code changes for inspection. Distinguish ordinary edits, incomplete writes, invalid signatures, missing dependencies, and corrupted objects rather than calling every failure "corruption."

**Open question:** Are you defending against accidental edits, malicious peers, stolen devices, local same-user processes, or a compromised administrator? These are different threat models. A fully compromised endpoint can access plaintext and keys while they are in use; avoid promising that FRAME permissions prevent this.

## 5. Self-Custodied FRAME Identity, Deployment, and Recovery

**Confirmed decision:** Identity is self-custodied through the user's FRAMEs and cryptographic keys. There is no provider authentication or key-recovery authority that can impersonate contributors, restore a lost identity, or decrypt their repositories. Users are responsible for retaining devices, keys, and recoverable backups.

**Confirmed decision:** Users can securely copy and deploy additional FRAMEs on their laptop, desktop, and backup infrastructure. Backups may be self-hosted or use capacity rented from COMB. Multiple FRAMEs must represent the same contributor without requiring a provider identity server.

**Confirmed decision:** The first installation initializes FRAME and walks the user through identity creation. It generates a stable identity key and a separate first-device key. Each additional installation generates its own device key and is authenticated by the first trusted FRAME under the same contributor identity. No provider authentication authority participates. Routine enrollment does not reuse another device's private device key.

### Enrollment and device authority: remaining details

- Specify a verified pairing exchange that binds approval to the intended new device key and resists substituted pairing requests and replay.
- Define the identity-to-FRAME authorization record and protection of the separate identity keys held within FRAMEs. Specify which private capabilities are present on each FRAME and how that placement preserves revocation and recovery.
- Decide whether an enrolled FRAME can authorize further devices, and how the recovery path works if the original device is unavailable.
- Separate revocation of one device from revocation of the contributor's CELL rights. Identity recovery must not silently restore revoked rights or authorize old lost-device keys.
- Update remote deployment and archive import around fresh device-key enrollment; copying stored state must not accidentally duplicate a device identity.

**Confirmed key-hierarchy direction:** Separate identity/enrollment authority, recoverable recipient-encryption capability, and individual device credentials. Do not automatically replicate a permanent identity/recovery decryption secret to every enrolled device. Preserve independent offline recovery without giving each device unrestricted future recovery authority. Exact key placement, delegation, and envelope layers remain to be selected.

### FRAME-key revocation and self-destruction

**Confirmed decision:** One user FRAME runs per device, and device credentials are called FRAME keys. Identity keys remain separate and are also placed in user FRAMEs. Other authorized FRAMEs of the same user can invalidate a FRAME key. That revocation updates affected CELL metadata and creates new versions with fresh keys/envelopes; later protected versions are neither sent to nor decryptable by the invalidated FRAME under the revocation policy, while the user's remaining FRAMEs retain access.

**Updated confirmed behavior:** On learning a valid revocation, FRAME closes its peer listener and stops peer/code-update activity. On user interaction it explains the lock and requests a restore credential with bounded allowed attempts. Another authorized FRAME issues the credential through `comb restore -lost-frame`; valid restoration resumes authorized operation. Exhausted attempts delete managed encrypted CELL metadata/state and reinitialize the FRAME, not independent working copies or external backups. This replaces immediate destruction on receipt of revocation. Cooperative locking/reset is not the security boundary against a malicious endpoint; peers and new-version encryption must still exclude it.

**Remaining protocol work:** Define restore-credential binding, delivery, expiration, issuer revocation, offline notice propagation, exact allowed attempts, crash-safe reset, and re-enrollment. The prototype uses three attempts and a long signed fresh-key/nonce-bound grant; these are documented implementation choices, not a completed lost-device protocol. Distinguish whole-FRAME invalidation from CELL-scoped rights loss; a repository owner must not gain authority to reset another user's unrelated FRAME state.

**Cryptographic implementation requirement:** If Bob's laptop is revoked but his desktop remains authorized, old laptop-held secrets must not unwrap future envelopes merely because Bob remains a collaborator. FRAME-key revocation and self-destruction settle the required behavior, not its wrapping/rotation algorithm. In particular, ordinary identity material present in the revoked FRAME must not let it bypass revocation or mint an accepted replacement without the required authority. This must be tested against a non-cooperating endpoint.

### Decryption keys per valid CRDT merge

**Confirmed intended direction:** Generate a fresh data-decryption key for each valid CRDT metadata merge and encrypt a copy for every collaborator authorized to decrypt under that merge's authorization state. Encrypt to each recipient's public encryption key; its matching private key unwraps the data key. Identity signing/authorization, device credentials, recipient encryption, and CELL data encryption are separate cryptographic roles; exact algorithms and key separation remain to be specified.

**Confirmed backup model:** Replicate encrypted CELL data together with recipient-encrypted key envelopes. A backup can retain the full envelope list without possessing plaintext data keys or recipient private keys. Provider-unreadable backups can therefore support whole-team device-loss recovery using user-held recovery material, without a surviving online collaborator holding plaintext keys.

Bind recipient selection to validated authorization at the merge, not current online presence. Known revoked recipients receive no new envelopes. A stale FRAME may nevertheless encrypt to a recipient whose revocation it has not learned; late reconciliation cannot undo that disclosure. This is the confidentiality consequence of eventual authorization, separate from later adoption or cleanup of code contributions.

This is a requirement direction, not yet a complete key-agreement protocol. Resolve:

1. **Version/merge identity:** Every valid metadata change creates a version; define its authenticated identifier and how multiple replicas deduplicate the same accepted change/merge. Replaying an existing version or exchanging its envelopes must not recursively trigger endless versions and key rotation. Specify when concurrent states require a distinct reconciled version.
2. **Concurrent generation:** Two disconnected FRAMEs may produce different valid merge states and keys. Preserve decryptability of both histories and define the key/authorization state after reconciliation; do not assume independently random keys converge like CRDT content.
3. **Envelope protocol:** Define the generating FRAME's authority and bind each authenticated envelope to CELL, merge/epoch, policy history, recipient identity/key version, algorithm, and data-key identifier. Specify recipient public-key authenticity, key separation, authorized device delivery, and rejection of substituted envelopes. Do not derive a supposedly secret key only from public state.
4. **Revocation propagation:** The revocation itself creates a new version/key update, excluding known revoked recipients. Specify validation before key delivery, reconnection catch-up, stale-policy/concurrent-version reconciliation, and selective device revocation without assuming globally instantaneous policy knowledge.
5. **History and storage:** Does rotation protect future objects, rewrap stored object keys, or re-encrypt existing data? Specify offline-device catch-up, retained history keys, object/key references, backup storage, and the absence of retroactive secrecy for data already learned.

**Recommendation:** Represent encryption epochs explicitly and use an established, reviewed key-management construction. Bind the new-version/fresh-key requirement to authenticated version history; do not silently replace it with a code-change-only rotation schedule. Version deduplication and concurrent-epoch rules still need agreement.

### Identity recovery flow

**Confirmed decision:** Setup provides an identity recovery file capable of authorizing a new FRAME with a fresh device key under the original identity. The user may delete the file or retain it securely offline, such as on a USB drive stored in a safe. The UI must explain that deleting the last usable recovery copy sacrifices that path; the provider has no replacement copy or override.

**Recommendation:** Encourage verified offline storage, with deletion of exposed working/download copies after backup verification, rather than encouraging deletion of every copy. Protect the file with authenticated encryption and an appropriately protected user-held secret. The exact file format, authority scope, passphrase requirements, and recovery-secret replacement remain open.

**Confirmed recovery direction:** Restore the user's identity and private unwrapping capability from user-held recovery material, enroll a fresh device key, and retrieve encrypted CELL data plus its key envelopes from backups or peers. Unwrap the available authorized historical data keys locally, restore the local FRAME repositories, and use standard Git clone/pull against that FRAME. A ciphertext-only backup need not learn any plaintext or possess a collaborator's private key during this process.

This can restore a team after loss of all trusted devices when the needed backup objects/envelopes and sufficient legitimate recovery material survive. Each user retaining their own recovery material supports restoring their own identity; restoring one identity does not recreate other teammates' private keys. The precise rules for a recovered authorized user to reshare restored code with other identities remain open.

**Required but not yet selected mechanism:** The recovery material must restore the private decryption capability matching stored envelopes, or an equivalent protected recovery path. A signing-only identity key or authorization for a new unrelated device encryption key does not decrypt old envelopes. Specify whether this uses a separate recoverable identity-encryption key, protected historical keys, or another reviewed construction. No provider escrow is introduced.

### Consequences and remaining recovery questions

- Preserve the envelopes needed for historical objects and define backup completeness. Rotating or deleting recipient keys must not silently invalidate a user's only recovery file.
- Decide whether one initial recovery bundle can recover later recipient-key generations, or whether rotation requires refreshed recovery material. Avoid silently deriving every future secret from an old compromised recovery secret without stating the compromise consequences.
- Implement the accepted separation of enrollment authority, recoverable recipient-encryption capability, and device credentials. Specify how a revoked device is excluded from future access while its identity's remaining devices stay authorized, without trying to erase old keys.
- Past authorization leaves usable historical envelopes. Revocation cannot prevent an old private-key holder from decrypting ciphertext already obtainable with those envelopes; new epochs must exclude known revoked recipients.
- Bind backup snapshots to authenticated manifests and retained history/checkpoints. Encryption alone does not prove a backup is complete or the newest available state.
- Test restore with no trusted device or live collaborator available, using only the offline recovery file and ciphertext/envelope backup. This is the acceptance scenario for independent backup recovery.

The file's enrollment authority also needs a compromise story: how are a stolen recovery file, conflicting recoveries, lost-device revocation, and identity-key rotation handled? Avoid promising a one-time file unless distributed enforcement of its reuse is actually specified.

### Recovery boundaries

- Losing one device does not imply losing identity if another authorized FRAME or usable identity backup survives.
- Losing identity keys is different from losing repository data. Other replicas may retain the code, and a surviving authorized collaborator may grant a replacement identity access where policy permits. This does not recreate the original identity or automatically recover owner authority.
- Losing every usable decryption key and recovery copy can make encrypted data unreadable even if ciphertext survives. There is no provider override.
- Restoring an identity backup does not by itself restore all CELL contents, and restoring ciphertext does not by itself restore identity or decryption access. Specify backup contents and test restoration explicitly.

### Hosted trust boundary

**Confirmed direction:** Separate trusted full FRAME replicas from storage-only peers retaining ciphertext and recipient-encrypted key envelopes without plaintext CELL keys, recipient private keys, or contributor signing authority. Provider-rented encrypted backup capacity must not silently become an unlocked copy of the user's trusted endpoint.

**Recommendation:** For the provider-unreadable backup service, encrypt and authenticate backups on trusted user endpoints and keep recovery secrets under user control. A full FRAME running unlocked on ordinary provider-controlled infrastructure is a different trust model: serving code, decrypting repositories, and running workflows may expose plaintext/keys to that host. Disk encryption alone does not establish that the infrastructure operator cannot access a running endpoint.

The no-provider-access goal must name exactly which deployment modes satisfy it. Do not claim suitability for companies, militaries, or a security certification solely from the absence of a central authentication server; threat modeling, implementation review, operational controls, and independent assurance are separate work.

Specify:

- How invitations bind a public key to a trusted collaborator; name/email alone should not be the authority.
- Which keys sign publications, authenticate connections, and decrypt CELL data.
- The precise pairing, signed enrollment, selective device revocation, and recovery-file verification protocol without provider authority.
- Per-CELL key scope, per-valid-merge rotation, key distribution, concurrency, and membership-change handling.
- Whether new members can read historical repository data.
- Whether password protection of a transfer archive means authenticated encryption rather than a password prompt alone.

"Everything is encrypted" needs separate promises for network traffic, replicated storage, local FRAME storage, backups, and working trees. A developer's checked-out files normally need to be available as plaintext to their tools. Decide whether COMB's encrypted-at-rest promise excludes an unlocked working tree or requires a separate encrypted filesystem/storage design.

Revocation should be described as limiting future authorized access, not deleting knowledge: a collaborator can retain plaintext and keys already received. Future confidentiality requires an explicit key-update policy and cannot protect future content deliberately leaked by an authorized member.

MLS is an authoritative reference for asynchronous group key establishment with forward secrecy and post-compromise security.[3] Evaluate a maintained implementation if those properties are requirements; do not assume MLS automatically solves repository authorization, object retention, or concurrent policy changes.

Retain the archive-cleanup feature, but do not promise guaranteed physical erasure across every storage medium or backup system. Specify best-effort deletion and make encrypted export, key handling, and temporary-file avoidance the primary safeguards.

## 6. Give Discovery, Signaling, Relay, and Storage Separate Roles

ICE uses STUN and TURN for NAT traversal, but assumes a separate signaling connection for exchanging candidate information.[2]

**Recommendation:** Add explicit interfaces for:

- Discovery: finding a collaborator or known device.
- Signaling/rendezvous: exchanging connection setup information.
- Connectivity: direct connections with relay fallback.
- Authentication: verifying the peer and its CELL access.
- Durable replication: retaining publications until recipients can obtain them.

**Confirmed decision:** Global infrastructure is limited to a user-finding tool and TURN relay; neither is an identity, repository-permission, or recovery authority. Optional rented backup/storage capacity is separate from these global coordination services. Discovery must not be trusted to substitute a contributor's identity or authorize a device.

**Open question:** Can the user-finding tool carry signed connection/rendezvous information, or does signaling use another user-controlled channel? Resolve this without silently adding a mandatory global signaling or authentication service. Define self-hosting, private/air-gapped discovery, directory privacy, and public-key verification separately.

A candidate policy is LAN discovery when enabled, direct connection attempts, and an authenticated relay fallback. Make bootstrap/signaling services self-hostable as well if full self-hosting is a requirement.

A TURN relay is not the durable offline mailbox in this proposed design. Optional persistent FRAME replicas and separate storage-only peers retain state while collaborators are offline. Trusted full replicas may process and serve code; storage-only peers retain ciphertext without decrypting repository contents. Define which policy-validation, status, and serving capabilities each role has; do not assume a ciphertext-only backup can perform all full-FRAME operations.

Also decide what infrastructure operators can observe: endpoint addresses, traffic timing, membership hints, and transfer sizes should be considered separately from code confidentiality.

## 7. Treat Workflows as Untrusted Execution

**Recommendation:** Replicating a workflow definition must not automatically authorize it to run on another collaborator's machine.

Define:

- Opt-in execution and trust/approval rules.
- Sandboxing, filesystem access, network access, and resource limits.
- Secret availability and which publications may receive secrets.
- Which FRAMEs are eligible runners and how duplicate triggers are handled.
- Whether workflow results are signed and replicated.

For an initial implementation, keep workflows in the roadmap but require explicit local approval before execution. Run the normal FRAME daemon as the user's service rather than granting broad system privileges solely to protect metadata.

The local GUI also needs an authentication/session and origin policy; "local" should not mean every browser page or local process can freely invoke sensitive daemon operations.

## 8. Specify Availability and Recovery Before Optimizing

Define behavior for:

- Interrupted transfers and retry after reconnection.
- Duplicate and out-of-order messages.
- A crash between writing Git objects and publishing metadata that refers to them.
- Peers missing policy history or CRDT dependencies.
- Disk quotas, repository size limits, replication preferences, and retention.
- Garbage collection when another device may remain offline for months.
- Loss of every online replica, owner-key loss, and restoring from backup.

Keep incomplete objects and records out of accepted state until their dependencies and authorization are validated. A candidate durability rule is to store validated objects first and atomically advance the accepted publication frontier second.

## Suggested Design Sequence

The standard Git working-copy and FRAME-remote model, with `comb` limited to FRAME and ICE management, is confirmed. So are FRAME-owned CELL metadata, authorized-tree revocation propagation, late adoption/cleanup, and optional persistent FRAME replicas. Exact protocols remain to be designed. The following sequence is recommended for the remaining work:

1. Define FRAME's Git transport, remote authentication, and threat model within the confirmed standard Git workflow.
2. Define FRAME-side CELL storage, identity, device enrollment, and policy authority.
3. Specify authorized-tree proofs, affected-commit classification, adoption authority, `comb clean`, and concurrent policy handling for the confirmed revocation flow.
4. Specify push/pull acknowledgments, replication, discovery, signaling, and relay behavior.
5. Select metadata structures and encryption/key-management implementations against those requirements.
6. Build a minimal two-device path: initialize, invite, publish, disconnect, reconnect, fetch, integrate, and recover from an interrupted transfer.
7. Exercise concurrent publication, both stale and current Steve/Bob encounters, late revocation, adoption, cleanup with dependent commits, persistent-FRAME rejection, invalid signatures, metadata recovery, unresolved merges, and workflow approval.
8. Expand into the full GUI, multi-machine onboarding, workflow execution, and operational management without dropping the existing planned features.

## First Decisions to Discuss

- Which Git transport and authentication should FRAME expose to ordinary Git clients?
- What exact authorized-tree/acceptance rule identifies affected commits, and how are adoption decisions validated under concurrent revocation?
- What exact FRAME-side changes does `comb clean` make, especially when later commits depend on Bob's work?
- How are concurrent branch tips exposed to ordinary Git clients and later reconciled?
- Which recoverable recipient-encryption key model restores old envelopes after losing all trusted devices while retaining selective device revocation and safe key rotation?
- What uniquely identifies a valid CRDT merge for key rotation, and how do concurrent keys, revocation, and offline catch-up reconcile?
- What exactly can a provider-rented ciphertext backup do, and which roles require a trusted full FRAME?
- How does discovery carry connection information without becoming an identity authority or introducing another mandatory global service?

## Sources

[1] https://git-scm.com/docs/gitprotocol-pack
[2] https://www.rfc-editor.org/rfc/rfc8445
[3] https://www.rfc-editor.org/rfc/rfc9420
