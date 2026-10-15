# FRAME identity adapter

`comb_frame::identity` adapts CELL's existing password envelopes, FRAME certificates,
root signatures, and secret types to local persistence. GUARD derives Noise public
keys and rejects non-contributory transport keys. No new cryptographic primitive
is implemented here.

## Public API

```rust,ignore
initialize(data: &Path, name: &str, email: &str, password: &[u8], recovery_path: &Path)
    -> anyhow::Result<LocalIdentity>;
load(data: &Path, password: &[u8]) -> anyhow::Result<LocalIdentity>;
load_root(data: &Path, password: &[u8]) -> anyhow::Result<IdentitySecrets>;
prepare_enrollment(data: &Path, password: &[u8]) -> anyhow::Result<EnrollmentRequest>;
authorize(data: &Path, password: &[u8], request: &EnrollmentRequest)
    -> anyhow::Result<EnrollmentGrant>;
complete_enrollment(data: &Path, password: &[u8], grant: &EnrollmentGrant,
                    expected_identity: &IdentityPublic) -> anyhow::Result<LocalIdentity>;
recover(data: &Path, password: &[u8], recovery_path: &Path, recovery_password: &[u8])
    -> anyhow::Result<LocalIdentity>;
validate_profile(profile: &Profile, expected_identity: &IdentityPublic) -> anyhow::Result<()>;
atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()>;
private_directory(path: &Path) -> anyhow::Result<()>;
```

`Profile` derives Clone, Serialize, Deserialize. Its public fields are `identity:
IdentityPublic`, `certificate: FrameCertificate`, `name: String`, `email: String`,
`noise_public: [u8;32]`, `nonce: String`, `signature: Signature`. `id()` is the
hexadecimal **root identity signing** public key; `frame_id()` is the hexadecimal
**FRAME signing** public key. These are not interchangeable.

`LocalIdentity` contains only public `profile`, device-only `frame: FrameSecrets`,
`noise_private: Zeroizing<[u8;32]>`, and `token: String`. It has no Debug, Clone,
or Serialize implementation. Its token is zeroized on drop. Root signing and
recovery secrets are never fields of this routine runtime object.

`EnrollmentRequest` derives Clone, Serialize, Deserialize and has public `frame:
FramePublic`, `noise_public: [u8;32]`, and `nonce: String`. `EnrollmentGrant` is
an alias for `Profile`: the certificate and every public profile field are sent
alongside a root signature. This signature uses a versioned domain and a fixed
JSON tuple encoding, binding both root public keys, the entire FRAME certificate,
name, email, Noise public key, and nonce. Certificate verification alone does not
bind Noise keys.

## Initialization and persistence

Initialization generates independent root, FRAME, and Noise secrets and a random
32-byte hexadecimal local bearer token. It writes:

* `profile.json`: public, root-signed profile.
* `node.vault`: password-encrypted FRAME envelope, Noise private key, bearer token,
  nonce, and an authenticated copy of the public profile.
* `root.vault`: separately password-encrypted root secrets and their signed profile.
* `recovery_path`: a no-overwrite copy of that root recovery document, protected
  initially by the initialization password. Move it to offline storage.

FRAME secrets are sealed using CELL's `frame-local-v1` export. The node/pending
container is separately sealed with distinct contexts. Root secrets use CELL's
`identity-recovery-v1` export. CELL fixes Argon2id v1.3 at 64 MiB, three passes,
one lane and a 32-byte key; encryption is authenticated. A node load performs
multiple KDF operations. Bound concurrent unlock requests and password input
sizes at the application boundary. Password bytes belong to the caller and are
not zeroized by this API; use strong passwords and zeroizing caller buffers.

`load` never reads `root.vault`. It checks the encrypted profile copy against
`profile.json`, validates the root signature/certificate, and verifies all local
keys against that profile. Public profile substitution is rejected even when
substituting another correctly signed profile. Peer trust still requires an
externally pinned identity with `validate_profile`.

`load_root` is an **explicit offline authority operation**, not a daemon-startup
step. Its returned type grants both certification and historical recovery
capability; drop it immediately after the authorized offline operation. Do not
place it in server state or routine device exports.

## Enrollment

1. On the new FRAME, call `prepare_enrollment`; send only the public request.
   Pending FRAME/Noise secrets and token are encrypted in `pending.vault`.
2. On the root authority holder, call `authorize` after obtaining explicit user
   approval for the request. This intentionally unlocks root authority.
3. Transfer the grant through an authenticated channel and independently pin
   `expected_identity` (not an identity copied blindly from that grant).
4. Call `complete_enrollment`. Identity, root signature, nonce, FRAME keys, and
   Noise keys must all match. The encrypted pending file is removed only after
   the durable node/profile commit.

Enrolled nodes receive no root vault, root private key, or historical recovery
capability. Their FRAME and Noise keys and bearer token are independently fresh.
An enrolled node cannot authorize other nodes unless the user separately restores
root authority through an explicit offline recovery workflow.

## Recovery

`recover` authenticates the offline document with `recovery_password`, restores
the same root identity, creates fresh FRAME/Noise keys and a fresh bearer token,
and writes the root vault encrypted with the **new** `password`. It does not
reuse the original FRAME secrets or automatically decrypt any snapshots.

For historical restore, the caller explicitly uses `load_root`, obtains
`root.recovery_secret()`, and passes it to CELL's `open_snapshot`. Fresh FRAME
keys alone cannot open historical envelopes addressed only to root recovery.
Recovery restores cryptographic capability, not authorization against remote
revocation policy, rollback protection, or snapshot completeness.

## Filesystem and failure semantics

All new private directories use 0700, files use 0600. Writes use a same-directory
temporary file, fsync file contents, atomically persist, and fsync the parent.
`atomic_write` permits replacement for encrypted snapshot/state storage, while
identity commits and recovery exports use atomic **no-clobber** persistence.
`private_directory` rejects symlinks in every existing path component, creates
missing ancestors privately, and enforces 0700 on its target only. Path traversal
with `..` is refused. Existing ancestor permissions are not changed.

Initialization/enrollment commits use an exclusive `.identity-lock` to prevent
concurrent identity writers. Existing permanent or pending identity material is
never overwritten. There is no recursive cleanup. A process/power failure can
leave an incomplete initialization or stale lock; inspect it explicitly rather
than automatically deleting private state. Multi-file commit is not a database
transaction: incomplete state fails closed and requires operator repair. A
recovery document can have been committed before local initialization fails.

Reads reject symlinks and identity files larger than 1 MiB. The path checks and
private directory boundary defend against accidental/ordinary unprivileged
symlink attacks, not a hostile process running as the same OS user or privileged
filesystem mutation between checks. Atomic replacement is per-file only; caller
serialization is still required for application-level read/modify/write cycles.

Run adapter acceptance tests with:

```sh
cargo test -p comb-frame --test identity
```
