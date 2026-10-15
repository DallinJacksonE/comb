# COMB System Design

COMB is an open-source, local-first collaboration platform for software teams that want standard Git workflows while retaining control of their code, infrastructure, and identities.

Users work in ordinary Git repositories and configure Git remotes pointing to their FRAMEs. FRAME manages remote repositories, collaboration metadata, authorization, encryption, and peer-to-peer replication. The `comb` CLI manages FRAME and ICE services; it does not wrap or replace Git.

## Document Scope

This README consolidates the agreed design and approved requirements. It describes intended behavior, not implemented functionality or a completed security protocol. It is the baseline for implementation; it does not select a programming language, storage engine, wire format, Git transport, or cryptographic suite.

Unapproved recommendations, protocol alternatives, and remaining design questions belong in [Design discussion](design-discussion.md), not in the requirements below.

The current executable prototype, run instructions, verified behavior, and explicit implementation gaps are documented separately in [the implementation README](../README.md).

## 1. Architecture and Boundaries

| Component | Responsibility |
| --- | --- |
| **CELL** | A repository created within FRAME, including Git repository state, collaboration metadata, ownership, permissions, and authorization history. |
| **FRAME** | One user FRAME per device: a daemon, Git remote repository manager, and peer-to-peer node associated with a contributor identity and identified by a distinct FRAME key. |
| **`comb` CLI** | FRAME identity, enrollment, recovery, reconciliation, GUI, service administration, and ICE management. |
| **Local web GUI** | A FRAME-hosted, GitHub- or Bitbucket-like interface for repositories, code, issues, milestones, and project history. |
| **User-finding service** | Global discovery of users and connection information, without authority over identity, enrollment, repository permissions, or recovery. |
| **Connectivity infrastructure** | Direct peer connectivity supported by ICE/STUN and TURN relay fallback, including self-hosted services and a global TURN service. |
| **Backup/storage peers** | Persistent storage for encrypted CELL data and wrapped keys; separate from trusted full FRAME execution. |

### Core boundaries

- Working copies use standard `.git` storage. There is no `.comb` file, directory, or custom Git repository format.
- A CELL is managed data, not a separate running service.
- Git manages local edits, staging, commits, branches, resets, cloning, fetching, pushing, pulling, and code integration.
- FRAME manages the remote side and collaboration state. Replication does not silently change a developer's working tree.
- Identity and authorization are self-custodied. There is no provider authentication server, identity-reset authority, or provider-held recovery key.
- Users can run their own FRAMEs and connectivity infrastructure. Global coordination is limited to user finding and TURN, not repository or identity authority.
- Optional backup capacity rented from COMB is a storage service, not an authority over a user's identity or code.

## 2. Standard Git Workflow

1. Install `comb` and initialize or enroll the device's FRAME.
2. Access FRAME to create a remote repository, which FRAME treats as a CELL.
3. Configure an ordinary Git repository with the FRAME-provided remote, or clone from that remote.
4. Use standard Git commands and existing IDE Git integrations.
5. FRAME validates and stores remote updates and replicates them to collaborators' FRAMEs.
6. Collaborators fetch and integrate changes from their configured FRAME remotes through ordinary Git.

The Git remote name is user-selected. Local Git operations work without FRAME. Remote operations require the target FRAME to be reachable.

### Push acknowledgment and replication

A successful Git push acknowledges durable acceptance by its target FRAME. It does not promise that another FRAME is online, that every replica has received the update, or that another collaborator has merged the code.

FRAME reports peer replication health separately from local acceptance. Distinguish durable storage, additional replica acknowledgments, and integration into a working branch.

### Concurrent branch updates

FRAME preserves concurrent histories rather than selecting a winner by timestamp or a single global version counter:

- Fast-forward when one accepted branch tip includes the other.
- Preserve divergent tips and surface them for explicit Git integration.
- Do not silently discard a previously accepted branch tip.
- Resolve code conflicts through Git in the working copy, not through metadata CRDT merging.

## 3. CELL Data and Version Model

### Repository and collaboration state

FRAME tracks each CELL's:

- Git repository state and history.
- Owner and collaborator permissions.
- Verified contributor public keys.
- Authorized-tree history, including grants and revocations.
- Collaboration data, including issues, milestones, documentation, and workflow definitions.
- Contribution provenance, acceptance, and reconciliation decisions.
- Encryption state and recipient-encrypted data-key envelopes.

CELL metadata uses a CRDT data structure. Git code history continues to use Git's own model and merge behavior. CRDT convergence does not by itself authorize a permission change; FRAME validates authority using the authorized tree.

### CELL versions

A CELL version contains collaboration metadata and the Git tree/repository state within it.

- Every valid metadata change creates a new CELL version, even if the Git tree is unchanged.
- Permission and FRAME-key revocations are metadata changes and create new versions without waiting for code changes.
- Each valid CRDT metadata merge produces a fresh CELL decryption key and the applicable recipient envelopes.
- Versions preserve ancestry and may be concurrent. They are not one globally increasing counter and do not necessarily require new Git commits.
- Receiving or replaying an existing version does not itself create another metadata change, version, or key-rotation loop.

### Integrity and recovery

Sealing applies to protected FRAME-managed state, not ordinary local Git activity. Users editing files or running Git directly must not be flagged as corruption merely for bypassing the daemon.

FRAME checks content identifiers/hashes, authenticated provenance, and authorization history to validate received and stored state. Protected collaboration metadata is managed by FRAME rather than manually edited in the working copy.

Unexpected modification of protected state triggers a corruption warning and recovery options. Metadata recovery must allow legitimate code changes to be retained for inspection rather than forcing their loss.

## 4. Identity and FRAME Lifecycle

### Key roles

| Key role | Purpose |
| --- | --- |
| **Identity key** | Stable, user-controlled contributor identity and authority for associating FRAMEs with that identity. Separate from the FRAME key and present in FRAME identity state. |
| **FRAME key** | A distinct per-device credential identifying that device's FRAME. Formerly called a device key. |
| **Recipient-encryption capability** | Opens the collaborator's encrypted CELL data-key envelopes and supports recovery of historical access. Separate in role from identity signing and FRAME authentication. |
| **CELL data key** | Decrypts the protected data associated with a CELL version/merge. Distributed only through encrypted envelopes to authorized recipients. |

Identity keys and FRAME keys are separate even though both are held within FRAMEs. Multiple FRAMEs represent the same contributor without sharing a FRAME key. Cryptographic role separation must preserve selective FRAME revocation and offline recovery; shared identity state must not give an invalidated FRAME a way to open future envelopes or bypass its revocation.

### First installation

1. The user installs `comb`; FRAME initializes and guides local identity creation.
2. Setup collects the user's name and email and generates an identity key and the first FRAME key.
3. FRAME creates the user's identity recovery file and explains its custody and loss consequences.

Names and email addresses are identity metadata, not substitutes for cryptographic authorization.

### Additional devices

1. The user installs `comb` on another device.
2. The new FRAME generates its own FRAME key.
3. The existing first trusted FRAME authenticates and authorizes the new FRAME under the same contributor identity.
4. The new FRAME obtains the CELL state and decryption access appropriate to its validated authorization.

Enrollment is user-controlled, not registration with a provider authentication authority. Copying or importing FRAME state must not blindly duplicate another FRAME's key. Enrollment does not grant additional CELL rights beyond the identity's permissions.

### FRAME-key revocation, lock, and restore

An authorized user FRAME can invalidate another FRAME belonging to that user. A valid FRAME-key revocation:

- Updates affected CELL authorization metadata and creates new CELL versions with fresh keys/envelopes.
- Excludes the invalidated FRAME from later protected CELL-version delivery and decryption, even if its process remains running.
- Preserves access for the identity's other authorized FRAMEs.
- Causes the invalidated FRAME to stop participating as a peer and close its peer listening port after learning and validating the revocation.

On the user's next interaction, the revoked FRAME explains the revocation and requests a restore credential with a bounded number of allowed attempts. The user opens another authorized FRAME and runs `comb restore -lost-frame` to generate the credential for that lost/revoked FRAME. A valid credential restores the FRAME's operation under current authorization. Until restored, the FRAME neither updates code nor participates as a network peer.

When restore attempts are exhausted, the FRAME deletes its managed encrypted CELL metadata/state and reinitializes from scratch. Independent Git working copies and external backups/recovery files are not deletion targets. This replaces immediate self-destruction on receipt of revocation; the self-limiting state precedes any reset.

Cooperative shutdown/reset is not the security boundary against a modified endpoint. Peer-side rejection and cryptographic exclusion must hold even if a compromised FRAME ignores its lock. Notices and restore credentials require validated authority; arbitrary peers cannot invalidate or restore another user's FRAME. No guaranteed physical erasure or deletion of previously copied code is promised.

## 5. Encryption, Key Envelopes, and Backups

### Privacy and recipient selection

Code, issues, documentation, and workflows held and replicated by FRAME are intended to remain private to authorized collaborators. Encryption protects network/replicated data and backup contents; a trusted unlocked FRAME necessarily accesses the plaintext needed to serve repositories and run its operations.

For each valid metadata merge/new CELL version:

1. Generate a fresh CELL data key.
2. Determine authorized collaborators and FRAME access from that version's validated authorization state, not from online presence.
3. Encrypt copies of the data key using the authorized recipients' public encryption keys. Only the corresponding private capabilities may unwrap them.
4. Retain and replicate encrypted CELL data together with its recipient-encrypted envelopes.
5. Deliver applicable envelopes and protected updates when authorized FRAMEs request later changes.

Known revoked identities and FRAMEs must not obtain future decryption capability. In particular, a still-authorized identity must not provide a shared-secret shortcut for one of its revoked FRAMEs. Ciphertext-only storage peers may retain wrapped keys but receive no plaintext CELL keys, recipient private keys, or contributor signing authority.

### Backup deployments

Users may run persistent FRAMEs themselves or rent encrypted backup capacity from COMB.

- **Trusted full FRAME:** An authorized endpoint that can decrypt CELL data, serve repositories, manage collaboration state, and perform its configured operations.
- **Ciphertext-only backup/storage peer:** Retains encrypted CELL objects and their wrapped data keys without being able to decrypt code or act as a contributor.

Possession of all stored envelopes must not enable the storage operator to decrypt the repository. A provider-hosted full FRAME with plaintext/key access is a different trust boundary from provider-unreadable encrypted backup storage; those capabilities must not be conflated.

A persistent full FRAME that knows a revocation can distribute that authorization update and reject revoked contributions. Persistent availability helps policy propagation but does not create a new authority above the owner or eliminate network partitions.

### Recovery and restoration

The identity recovery file can authorize a new FRAME under the original identity and restore the private unwrapping capability needed for historical backup envelopes, or an equivalent user-controlled recovery path.

Users can retain the file offline, such as on a USB drive stored in a safe, or choose to delete it. Setup must warn that deleting the last usable recovery copy sacrifices that path. Protect and verify offline recovery material, then remove exposed online copies; the provider retains no recovery override.

Recovery proceeds as follows:

1. Restore the identity/recovery capability on a new device and generate a fresh FRAME key.
2. Authorize the new FRAME under the recovered identity without reactivating revoked FRAME keys or granting new CELL permissions.
3. Retrieve encrypted CELL data and the matching key envelopes from surviving peers or backups.
4. Unwrap the keys and restore repositories locally.
5. Use ordinary Git to clone or pull through the restored FRAME.

The process can restore code after loss of all trusted team devices without a live collaborator holding plaintext keys, provided sufficient recovery secrets, encrypted objects, and envelopes survive. Restoring one identity does not recreate other contributors' private keys.

Losing a device, losing identity authority, losing decryption capability, and losing every repository replica are different failures. Neither identity proof alone nor ciphertext alone reconstructs the missing counterpart. There is no provider password reset that bypasses these requirements.

## 6. Authorization, Revocation, and Reconciliation

### Prospective enforcement

Revocation limits subsequent access and contribution acceptance; it does not erase prior knowledge.

If Bob had access to an old CELL version, he may retain its code and keys. Revoking him creates a new version, even with unchanged code, and excludes him from new envelopes and authorized updates following that policy. Old keys do not authorize the new state.

COMB does not promise DRM, remote erasure, or prevention of deliberate copying/disclosure of previously accessible code. NDA and contractual enforcement are outside the protocol. Future-version access control remains in scope.

### Disconnected authorization

Permission knowledge can be stale. An offline user can keep editing locally but cannot share through FRAME until connecting to a peer. A valid revocation is enforced when learned.

An updated FRAME rejects revoked access. Two stale FRAMEs may exchange work or disclose keys before learning a revocation; later reconciliation cannot retract that earlier transfer. Subsequent versions following the revocation must exclude the revoked recipient.

### Alice, Bob, and Steve

1. Alice owns the CELL and revokes Bob's repository rights.
2. Bob remains able to edit the old local code while disconnected.
3. If Steve already knows the revocation when Bob reconnects, Steve's FRAME propagates it and rejects Bob's normal authorized sharing. Bob's FRAME updates its authorization state.
4. If Bob and Steve connect while neither knows the revocation, Steve may receive Bob's changes under stale policy.
5. When Alice's authorization history reaches Steve, FRAME identifies affected contributions and warns Steve that they came from Bob after his rights were revoked under that history.
6. Steve, if currently authorized to write, may explicitly adopt responsibility for the exact affected contribution set without additional owner approval. His CELL can then merge with Alice's through reconciliation.
7. Alternatively, Steve uses `comb clean` to reconcile the CELL without the affected unauthorized work.

Adoption preserves Bob's original attribution and Alice's repository ownership. It is not blanket approval of Bob's future submissions.

### Evidence and contribution states

Authorization classification uses authorized-tree history and authenticated FRAME acceptance records, not Git author timestamps:

- Previously accepted authorized history remains valid after revocation.
- New contributions from a revoked identity lacking recognized prior acceptance are flagged.
- Work accepted under stale permissions enters adoption-or-cleanup reconciliation.
- Legitimate unpublished offline work may therefore require adoption.

FRAME tracks received, validated, accepted, pending-reconciliation, adopted, and excluded contribution states. Pending work remains inspectable but cannot automatically integrate or execute workflows.

Authenticated, signed FRAME records bind submission, acceptance, and adoption actions to exact commits and policy history. Git author, authenticated submitter, accepting FRAME, and adopter are distinct roles. Recorded provenance does not identify every possible instance of copied or rewritten code.

### Safe cleanup

`comb clean` is FRAME-side authorization reconciliation, not a wrapper for `git clean` or a general working-copy reset.

Cleanup must:

- Identify affected contributions and later work that depends on them.
- Preserve original history for recovery.
- Preview affected commits and the proposed accepted result.
- Require confirmation before changing accepted FRAME state.
- Allow existing working copies to reconcile using ordinary Git.

Removing a commit identifier is not sufficient if its effects remain in dependent work. This requirement does not select a particular history-rewrite or revert algorithm.

## 7. FRAME Services and Local GUI

FRAME:

- Tracks CELLs and manages their protected metadata.
- Enforces contributor and FRAME authorization and reconciles stale-policy contributions.
- Accepts Git clients as a remote repository manager.
- Replicates missing validated state and preserves concurrent histories.
- Communicates with the user's other FRAMEs and tracks online collaborators.
- Notifies users of received updates and required reconciliation.
- Runs CELL workflows; pending-reconciliation contributions do not execute automatically.
- Handles `comb` management requests and hosts the local web GUI as a child process.

The GUI provides a GitHub- or Bitbucket-like overview for managing CELLs, browsing code, managing issues and milestones, and viewing project history.

## 8. Connectivity and Global Services

Global coordination is limited to a user-finding tool and TURN relay. Neither grants CELL rights, authorizes FRAME enrollment, holds plaintext repository keys, or restores identity.

- Support user-hosted STUN/TURN infrastructure and relay fallback.
- Keep discovery, connection setup, peer authentication, and durable replication as distinct responsibilities.
- Discovery results must not substitute a contributor's identity or confer permissions.
- A TURN relay is not a durable repository backup.
- Persistent FRAMEs and backup/storage peers retain CELL data between collaborators' online sessions.
- User-finding, relay, and rented backup services must not introduce a mandatory provider identity authority.

## 9. Command Reference

All `comb` commands interact with FRAME or connectivity infrastructure. There are no Git-wrapper commands, repository-format conversion commands, or Git-operation aliases.

### Identity, enrollment, and transfer

| Command | Agreed purpose |
| --- | --- |
| `comb user` | Guide or revisit local identity setup, including name, email, initial identity/FRAME keys, and recovery-file handling. First installation also guides setup. |
| `comb new-key` | Generate a named key associated with the user, optionally password-protected. |
| `comb restore -lost-frame` | Generate a restore credential on an authorized FRAME for a lost/revoked sibling FRAME. The revoked FRAME requests and validates the credential before resuming operation. |
| `comb remote login` | Authenticate to a remote host and deploy COMB under the user's identity with a distinct FRAME key and authorized enrollment. Remote host login is not a global COMB identity login. |
| `comb get transfer zip` | Prompt for a password and package user data for transfer. |
| `comb unpack transfer <path/to/zip>` | Initialize the destination from transferred data, respecting distinct FRAME keys, then thoroughly clean up the transfer archive. |

Transfer and recovery must not blindly duplicate FRAME credentials or give rented storage identity/private decryption secrets. Archive cleanup is intended behavior, not a guarantee of physical erasure across backups or storage media.

### CELL reconciliation

| Command | Agreed purpose |
| --- | --- |
| `comb clean` | Reconcile affected unauthorized work in FRAME using dependency analysis, recoverable history, preview, and confirmation. |

### GUI and service management

| Command | Agreed purpose |
| --- | --- |
| `comb webgui` | Open the local web GUI. |
| `comb service -restart` | Restart FRAME. |
| `comb service -update` | Update FRAME. |
| `comb service peers` | List online collaborators and their associated CELLs. |

### Connectivity configuration and diagnostics

| Command | Agreed purpose |
| --- | --- |
| `comb service set ICE` | Guide configuration of the user's ICE URL and check connectivity. |
| `comb ice health` | Report ICE health. |
| `comb ice` | Display ICE information, including URL and ownership. |

## 10. Implementation Acceptance Scenarios

These scenarios exercise the agreed boundaries; they do not select unapproved implementation mechanisms.

- **Standard Git:** Initialize locally, configure a FRAME remote, push, clone/fetch, and integrate using ordinary Git and IDE tooling without `.comb` storage.
- **Durability:** A reachable FRAME durably accepts a push while other peers are offline; peer replication status remains separate from push success.
- **Concurrency:** Independently advance the same branch on disconnected FRAMEs, preserve both tips, and resolve divergence explicitly through Git.
- **Metadata-only version:** Revoke access without changing code; produce a new CELL version with fresh keys/envelopes and the same Git tree.
- **Replay:** Receive an existing version repeatedly without creating endless versions or key rotation.
- **Contributor revocation:** Bob retains old readable code but cannot obtain protected versions following the policy that revokes him.
- **FRAME revocation:** Revoke one FRAME while keeping another FRAME of the same identity authorized; the revoked FRAME receives no later protected updates and cannot unwrap their keys using its retained secrets.
- **Revoked-FRAME restoration:** A conforming FRAME validates revocation, closes its peer listener, and explains the lock on user interaction. An authorized sibling can restore it with a bound credential; exhausted attempts reset only managed FRAME state. Peers still deny access to a modified FRAME that refuses to cooperate.
- **Stale permissions:** Exercise both updated and stale Steve/Bob encounters, late revocation detection, exact-set adoption, and cleanup involving dependent work.
- **Independent recovery:** Lose all trusted devices and restore using only user-held offline recovery material plus ciphertext/envelope backups, without provider keys or live collaborator plaintext-key assistance.
- **Storage isolation:** A backup operator holding ciphertext and all stored envelopes cannot decrypt CELL contents without authorized private recovery/decryption capability.
