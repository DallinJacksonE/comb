# COMB — Rust Development Implementation

An executable local-first Git collaboration prototype. **Not audited or ready for sensitive production code.** The agreed target design is [system/readme.md](system/readme.md); implemented behavior and limits are documented here rather than implied by the design.

## Workspace

| Directory | Implementation |
| --- | --- |
| `CELL/` | Identity/FRAME certificates, delegated enrollment, signatures, password encryption, recipient key envelopes, encrypted snapshots, and signed CELL authorization/version DAG. |
| `FRAME/` | Axum daemon, management CLI/API, canonical Git smart HTTP adapter, encrypted persistence, pinned peer replication, revocation/restore, and React/TypeScript/Vite GUI. |
| `GUARD/` | Pinned Noise transport, coturn configuration/lifecycle, STUN diagnostics, content-addressed ciphertext storage, and deployment examples. |
| `scripts/integration_smoke.py` | Isolated native-process integration test using real Git clients and three FRAME daemons. |

A signed operation-set DAG implements deterministic metadata merging, explicit authority checks, concurrent refs, and stale-work quarantine. This is not a general collaborative text-editing CRDT or an implementation of a published COMB wire standard.

## Prerequisites and Build

Linux/Unix, a recent Rust toolchain supporting edition 2024 and standard file locking, Git, and Node/npm. This implementation uses Unix file permissions. Run from the project root:

```sh
cargo build --workspace
npm ci --prefix FRAME/webgui
npm run build --prefix FRAME/webgui
```

The CLI is `target/debug/comb`. The GUI build is served directly by Axum; a separate Node server is not required in production mode.

## Start a Local FRAME

```sh
target/debug/comb user
target/debug/comb serve
```

Setup asks for a local password, name, and email and generates identity, FRAME, recipient, and Noise transport keys. The default state directory is `$XDG_DATA_HOME/comb`, or `$HOME/.local/share/comb`. Override it with `--data /absolute/path` for separate test devices.

The default endpoints are:

- Management API, Git, GUI: `http://127.0.0.1:7331`
- Authenticated encrypted peer carrier: `http://127.0.0.1:7332`

In another terminal, obtain the local token and open the GUI:

```sh
target/debug/comb token
target/debug/comb webgui
```

Paste the token into the GUI. It is an in-memory management credential, not a global account login. Treat the token as a secret. GUI supports status, CELL creation and inline inspection, issues, and explicit peer registration. Other operations are currently CLI/API based.

For testing only, `COMB_PASSWORD` avoids repeated password prompts; `COMB_RECOVERY_PASSWORD` supplies a separate recovery-file password. Interactive prompts are preferable to putting secrets in shell history. Environment variables can be observed by sufficiently privileged processes.

`serve` supports `--listen`, `--peer-listen`, `--assets`, and `--sync-seconds`. Management/Git HTTP refuses non-loopback binding. The peer carrier may bind a reachable address because its repository traffic uses mutually authenticated end-to-end Noise sessions. Run persistent full FRAMEs with the same daemon and durable private state directory; no provider identity authority is required.

## Standard Git

Create a CELL in the GUI or with:

```sh
target/debug/comb cell create example
```

Use the returned CELL ID in an ordinary Git remote:

```sh
git remote add origin http://127.0.0.1:7331/git/CELL_ID.git
git push origin main
git clone http://127.0.0.1:7331/git/CELL_ID.git
```

For this local prototype, authenticate Git with any nonempty username and the local FRAME management token as its password, preferably using a Git credential helper. Bearer authentication also works. Do not embed the token into a shared repository URL. There are no `comb push`, `comb pull`, or other Git wrappers.

Concurrent same-branch tips are advertised under `refs/comb/divergent/...`; no arbitrary winner is selected. Fetch those refs explicitly and integrate using Git:

```sh
git fetch origin '+refs/*:refs/remotes/comb/*'
git merge COMMIT_TO_INTEGRATE
git push origin HEAD:refs/heads/main
```

A divergent branch may temporarily have no single `main` ref, so cloning without selecting a retained ref will not check out a default branch until integration resolves it.

## Enroll Another Device Without Copying Its FRAME Key

Use distinct state directories or separate machines. Public request/grant files can be transferred over a trusted out-of-band channel; verify the identity fingerprint independently.

```sh
# New device
target/debug/comb --data /path/to/new-frame enroll request --out /path/to/request.json

# Existing authorized device
target/debug/comb enroll authorize --request /path/to/request.json --out /path/to/grant.json

# New device: pin the established identity signing key, not an unverified directory result
target/debug/comb --data /path/to/new-frame enroll complete \
  --grant /path/to/grant.json --identity-key TRUSTED_IDENTITY_SIGNING_KEY_HEX
```

Export the new public profile with `comb profile --out /path/to/profile.json`. Register that FRAME in a CELL with `comb cell register-frame CELL_ID --profile /path/to/profile.json` on an authorized existing FRAME. For a different collaborator identity, use `comb cell grant CELL_ID --profile /path/to/profile.json --role write`.

First/recovered devices keep an encrypted `root.vault` for explicit authority operations. Routine enrolled devices do not receive root/recovery secrets; they use signed delegation chains for further enrollment. Domain validation blocks enrollment from a known revoked issuer without invalidating FRAMEs already validly enrolled before that issuer's revocation. Delegation is bounded to eight certificates.

## Pin and Synchronize Peers

Export profiles and compare the FRAME signing key and Noise public key out of band. Each side must explicitly pin the other; there is no automatic trust-on-first-use from a directory.

```sh
target/debug/comb peers add-profile --profile /path/to/verified-peer.json --url http://PEER:7332
target/debug/comb peers sync PEER_FRAME_SIGNING_KEY_HEX
```

Alternatively `peers add --id FRAME_KEY_HEX --url http://PEER:7332 --key NOISE_KEY_HEX` retrieves the signed profile and requires both pins to match it. Grant/register collaborator FRAMEs in each CELL before sharing it.

Replication uses `Noise_KK_25519_ChaChaPoly_BLAKE2s`, with pinned static keys, authenticated encrypted chunks, single-use request sessions, ordered nonce replay checks, and bounded payload sizes. HTTP is only the carrier; a relay cannot substitute endpoint keys or read repository payloads. Explicitly pinned owners anchor newly imported CELLs. Existing owner pins cannot be replaced by an incoming snapshot.

`--sync-seconds 15` enables periodic attempts against configured peers. The current transport is direct HTTP-carried Noise, not full NAT-traversing ICE/TURN data transport.

## Revocation and Restore

Contributor revocation is CELL-scoped:

```sh
target/debug/comb cell revoke CELL_ID --identity CONTRIBUTOR_ID_HEX
```

A metadata-only change creates a new signed version and freshly encrypted snapshot. Revoked identities are excluded from both FRAME envelopes and offline identity-recovery envelopes. Old code and keys remain readable by former recipients, intentionally.

To invalidate another online FRAME of your own identity:

```sh
target/debug/comb revoke-frame OTHER_FRAME_KEY_HEX
```

The source records applicable CELL FRAME-key revocations and sends a signed same-identity notice. The receiver persists its lock, closes its peer listener, and rejects management operations except status and restore. Existing working copies are not deleted.

On the revoked FRAME, create a replacement request:

```sh
target/debug/comb restore --request-out /path/to/restore-request.json
```

On another authorized FRAME:

```sh
target/debug/comb restore --lost-frame /path/to/restore-request.json
```

Transfer the resulting credential privately, then run `comb restore` on the revoked FRAME and enter it at the hidden prompt. The prototype credential is a long FRAME-signed restore authorization, not yet a short human-friendly password. It binds an enrollment grant to the exact target FRAME, current revocation challenge, fresh keys, and pending nonce. A different explicitly trusted, nonrevoked FRAME must issue it, even when the target has no CELLs. Validation checks every local policy transition before consuming the pending request. Offline-root recovery is a separate path, not an unsigned override for the restore lock. The historical `comb restore -lost-frame` spelling is also supported.

After three invalid attempts, the prototype removes only its managed encrypted CELL snapshots/metadata, drops its runtime cache, and initializes fresh local identity/FRAME state. A new encrypted reset recovery file is written inside the state directory. Independent working copies and external recovery files are not touched. Management tokens rotate after restore/reset; reload the local token. Re-pin/register the restored FRAME's new profile where needed.

Offline lifecycle-notice queuing/global revocation convergence is not yet complete: explicit notification currently requires the target peer to be reachable. Do not treat this as a fully deployed lost-device protocol.

## Encrypted Backup and Independent Recovery

```sh
target/debug/comb cell backup CELL_ID --out /path/to/snapshot.cell
```

Copy that ciphertext artifact to user-controlled storage or a rented storage peer. It contains signed encrypted CELL/Git data and wrapped keys, not plaintext code or private recipient keys. `GUARD::backup::BlobStore` provides durable hash-addressed storage; a hosted backup HTTP service is not yet supplied.

On a fresh state directory, restore using only the offline recovery file and the backup:

```sh
target/debug/comb --data /path/to/restored-frame recover \
  --recovery /path/to/identity.recovery \
  --backup /path/to/snapshot.cell \
  --owner-key TRUSTED_CELL_OWNER_SIGNING_KEY_HEX
```

This creates fresh FRAME/Noise keys, recovers the identity's historical unwrapping capability, decrypts locally, and materializes the repository. Start that FRAME and clone through ordinary Git. It does not require any original trusted device or collaborator to remain online. Missing encrypted objects, envelopes, or recovery secrets cannot be recreated by COMB.

## Tests and Quality Gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm test --prefix FRAME/webgui
npm run build --prefix FRAME/webgui
python scripts/integration_smoke.py
```

The smoke test creates isolated temporary identities, runs real daemons, pushes/clones through Git HTTP, synchronizes over pinned Noise, preserves and explicitly merges divergent histories, revokes contributor/FRAME access, checks listener closure and restore, deletes original FRAME data, and restores clonable code from ciphertext plus offline recovery material. It stops all child processes in `finally`.

GUARD tests include wrong-pin/MITM, tamper/replay, STUN packet validation, safe coturn config, and backup integrity. Real coturn validation is opt-in:

```sh
COTURN_EXECUTABLE=/path/to/turnserver cargo test -p comb-guard --test turn -- --include-ignored
```

See [GUARD/README.md](GUARD/README.md) for coturn installation and deployment. Docker was not usable in the implementation session because the daemon socket denied access; native isolated processes were used instead.

## Security and Completeness Limits

This is an unaudited development implementation, not a military/enterprise assurance claim. Tests exercise particular properties; they do not prove the absence of MITM or other vulnerabilities.

- Canonical bare Git repositories are materialized as private temporary plaintext runtime caches while the trusted daemon is unlocked. Persisted CELL snapshots/control and key vaults are encrypted. A crash can leave runtime files; use an encrypted host filesystem and protected scratch storage. This does not implement transparent encrypted Git object storage or promise every local byte is encrypted at all times.
- A full endpoint with plaintext access is trusted. Root-bearing device/password or offline recovery-secret compromise can defeat identity authority; remote revocation cannot undo stolen root authority or historical plaintext. Enrolled FRAMEs intentionally lack that root secret.
- Policy propagation is eventual. Stale peers may disclose keys or accept work before learning a revocation. The data-adoption flow cannot retract a previously disclosed key.
- Signed history is validated, but secure monotonic rollback prevention, backup completeness proofs, identity/root rotation, and crash-atomic restore across all files are not complete.
- `comb clean` is preview-only. Destructive Git dependency-aware cleanup is deliberately disabled rather than approximated with a hard reset. Metadata adoption/exclusion exists in CELL, but Git history cleanup requires more work.
- The GUI does not yet provide code browsing, milestone editing, workflow configuration, or full reconciliation UX. Issues support create/list. No workflow executor is enabled.
- Full ICE candidate exchange/nomination, TURN client relay transport, global user discovery, hosted storage APIs, remote-host installation, transfer ZIP commands, service updater/restart integration, and the general `new-key` command remain unimplemented. Their design requirements are retained in `system/readme.md`.
- The implementation transfers whole bounded snapshots rather than streaming large Git packs. Current limits are 32 MiB for repository archives and 48 MiB for a serialized peer exchange; JSON byte-array encoding adds overhead.
- Read-only members can re-encrypt/replicate already validated state and recover/reopen backups without gaining code-write authority: every code/policy operation inside the signed DAG is independently authorized. A snapshot carrier signature is not permission to invent a code update.
- Git branch/tag deletion is explicitly rejected until signed ref tombstones are implemented. Non-fast-forward pushes are also rejected; use explicit Git integration rather than silent history replacement.
- Restore issuers must be explicitly trusted and eligible under the affected CELL histories. Unresolved policy/enrollment forks may require offline recovery rather than bypassing those checks. Restore across all local files is not yet a crash-atomic transaction.
- Manual file-based pairing and fingerprint verification are required. There is no automatic secure pairing UI, and no public non-loopback management HTTP without a separately reviewed TLS/auth deployment.
