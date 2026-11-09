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

For a Linux/systemd user installation, see [installation and recovery walkthrough](FRAME/INSTALL.md). From the current checkout:

```sh
bash FRAME/install.sh
```

This builds and installs the binary and GUI, adds user PATH integration, and starts a locked user service without saving your password. Run `comb` in a new terminal for initial setup/unlock. Subsequent commands reuse the private local session; restarting/rebooting requires unlocking again. Both install and setup explain why the encrypted recovery file **plus its original password** and separate encrypted CELL backups matter. Uninstall removes owned program/service files while preserving all identity/repository/recovery data.

The guide includes curl-based installation once this revision is published; uncommitted code is not assumed to exist on the public URL. The commands below are the alternative manual/source-development workflow, not additional steps after installing the user service.

The local script uses its own source checkout; `--source /path/to/comb` overrides it. It validates uninstall support before building and installs a standalone cleanup script. Default installations can also be removed directly from source with `bash FRAME/uninstall.sh`, preserving identity/CELL/recovery data.

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

Setup asks for a local FRAME password, name, email, SSH username, and optional SSH-key passphrase, and generates identity, FRAME, recipient, Noise transport, and separate OpenSSH client/server keys. The default state directory is `$XDG_DATA_HOME/comb`, or `$HOME/.local/share/comb`. Override it with `--data /absolute/path` for separate test devices.

The default endpoints are:

- Management API, Git, GUI: `http://127.0.0.1:7331`
- Authenticated encrypted peer carrier: `http://127.0.0.1:7332`
- Public-key-only SSH Git after setup/unlock: `127.0.0.1:7333`

In another terminal, display the GUI URL:

```sh
target/debug/comb webgui
```

Open that URL in your browser. The GUI automatically connects to the unlocked local FRAME without a token form. If the managed service is locked, first run a management command such as `target/debug/comb cell list`, then reload or choose Retry. Browser API access is same-origin and loopback-only; it is a trusted-local-machine convenience, not OS-user authentication. CLI/Git authentication still uses its existing credentials (`target/debug/comb token` prints the Git/management credential; treat it as a secret). Click a repository to open its Code, Issues, and Settings pages. Code defaults to a file tree and formatted README; Settings exposes membership, FRAME registration, encrypted backup export, rename, and confirmed local deletion. Status, CELL creation, and explicit peer registration remain on the main page.

For testing only, `COMB_PASSWORD` avoids repeated password prompts; `COMB_RECOVERY_PASSWORD` supplies a separate recovery-file password. Interactive prompts are preferable to putting secrets in shell history. Environment variables can be observed by sufficiently privileged processes.

`serve` supports `--managed`, `--listen`, `--peer-listen`, `--ssh-listen`, `--assets`, and `--sync-seconds`. Managed startup waits for private local initialization/unlock instead of prompting in a service journal. Management/Git HTTP refuses non-loopback binding. The peer carrier may bind a reachable address because its repository traffic uses mutually authenticated end-to-end Noise sessions. Run persistent full FRAMEs with the same daemon and durable private state directory; no provider identity authority is required.

## Optional HTTPS WebGUI hosting

Developers can opt into a separate authenticated HTTPS listener for their own FRAME, using either an operator-provisioned PEM certificate/key or an explicitly trusted TLS reverse proxy. See [HTTPS setup, local development certificates, Let's Encrypt/Caddy, managed services, and renewal](FRAME/HTTPS.md). HTTPS is not enabled automatically by installation, and COMB does not issue public certificates itself. Never expose or proxy the default token-free local listener at port 7331; use the separate `--web-listen` endpoint with its configured `--web-origin`. Remote sign-in uses the management token, not the FRAME unlock password, and does not unlock a locked FRAME.

## Standard Git

Create a CELL in the GUI or with:

```sh
target/debug/comb cell create example
```

The GUI and CELL summaries expose an SSH remote such as `comb-YOUR_FRAME_ID_PREFIX:example.git`. Use the actual returned alias in an ordinary Git remote: it automatically selects this FRAME's generated client key. OpenSSH asks for its optional passphrase, and an available `ssh-agent` may cache it. Existing installations add SSH with `comb ssh setup --username YOUR_USERNAME`, then restart/unlock the daemon; see [SSH setup, migration and security](FRAME/INSTALL.md#ssh-git-access). SSH is local-only by default, supports an explicit network bind, and enforces the authenticated FRAME's current CELL permissions. It provides Git transport, not shell access.

HTTP remotes remain supported. Use the returned URL slug (the example's slug is `example`):

```sh
git remote add origin http://127.0.0.1:7331/git/example.git
git push origin main
git clone http://127.0.0.1:7331/git/example.git
```

For this local prototype, authenticate Git with any nonempty username and the local FRAME management token as its password, preferably using a Git credential helper. Bearer authentication also works. Do not embed the token into a shared repository URL. There are no `comb push`, `comb pull`, or other Git wrappers.

### Repository pages and naming

Names map to lowercase ASCII URL slugs: `My Repo` becomes `/git/my-repo.git`. Create/rename reject empty, conflicting, and reserved ID-shaped slugs. Existing `/git/CELL_ID.git` remotes continue working. If old/imported repositories have ambiguous slugs, name lookup fails closed; use their immutable IDs. The GUI pages also use immutable IDs (`/cells/CELL_ID`, `/issues`, `/settings`), so bookmarks survive renaming.

Owner-authorized signed rename events preserve the CELL's genesis identity/history and replicate the effective name. The displayed slug changes with the name; update name-based Git remotes after renaming, or use the ID remote for stable addressing. Older binaries cannot parse the new signed Rename operation; update collaborating FRAME binaries before using rename.

Code browsing exposes only committed objects reachable from accepted branches/tags, with branch/directory/file navigation. README Markdown disables raw HTML, unsafe URL protocols, and embedded images. Binary files, symlinks, and submodules are not previewed; text previews are limited to 1 MiB and directory listings to 2000 entries / 1 MiB of Git output. Empty repositories show push instructions. This is read-only code browsing, not a browser editor.

Deletion requires an active owner FRAME and typing the exact current name. It removes that CELL's local runtime repository and private historical snapshots, persisting an encrypted tombstone so peer sync cannot silently restore it. Unrelated repositories continue syncing. It does not delete other devices' copies, independent working trees, exported backups, or promise secure physical erasure. There is no undo/reimport toggle for that tombstone in this UI; retain an exported backup and use a separate authorized/recovered FRAME if you need the deleted repository again.

Concurrent same-branch tips are advertised under `refs/comb/divergent/...`; no arbitrary winner is selected. Fetch those refs explicitly and integrate using Git:

```sh
git fetch origin '+refs/*:refs/remotes/comb/*'
git merge COMMIT_TO_INTEGRATE
git push origin HEAD:refs/heads/main
```

A divergent branch may temporarily have no single `main` ref, so cloning without selecting a retained ref will not check out a default branch until integration resolves it.

Snapshots preserve notes and custom ref namespaces as well as branches/tags, whether refs are loose or packed. The `refs/comb/` namespace is FRAME-managed: client pushes to it are rejected, while retained divergence refs remain fetchable.

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

Use `make test` for the Rust workspace, GUI tests, and isolated installer contracts. Each phase has a GNU `timeout` watchdog (180 seconds, then forced termination after 5 more seconds). Override it explicitly on slower hosts with `make TEST_TIMEOUT=300s test`. Direct `cargo test` does not use this watchdog.

Development/test builds optimize the Argon2 and Blake2 dependency hot loops. This avoids spending minutes in unoptimized password derivation across identity/recovery fixtures without reducing the actual KDF's memory/pass parameters, substituting test crypto, or skipping coverage. The first run after a profile change rebuilds affected crates. The installer suite also deliberately exercises bounded readiness-failure paths, so it takes longer than the GUI unit tests.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm test --prefix FRAME/webgui
npm run build --prefix FRAME/webgui
python scripts/integration_smoke.py
```

The smoke test creates isolated temporary identities, runs real daemons, pushes/clones through Git HTTP, synchronizes over pinned Noise, preserves and explicitly merges divergent histories, revokes contributor/FRAME access, checks listener closure and restore, deletes original FRAME data, and restores clonable code from ciphertext plus offline recovery material. It stops all child processes in `finally`.

`FRAME/tests/ref_round_trip.rs` additionally exercises ordinary Git HTTP push, encrypted Store shutdown/reopen, and fresh-client fetch of notes, annotated tags, and custom refs; it checks loose/packed custom-ref archive parity and rejects client writes to FRAME-managed refs.

Snapshot import and encrypted Store reopening run Git's full strict object-integrity check, with replacement objects disabled, before exposing the repository. Matching signed refs alone is insufficient: missing descendants, invalid object contents/hashes, and corrupt packs are rejected. `FRAME/tests/snapshot_integrity.rs` covers these cases, unchanged accepted state after rejected imports, and healthy packed snapshots. This validation does not replace crash-atomic persistence or establish backup freshness/completeness beyond the supplied Git object graph.

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
- The GUI does not yet provide browser code editing, milestone editing, workflow configuration, or full reconciliation UX. Issues support create/list. No workflow executor is enabled.
- Full ICE candidate exchange/nomination, TURN client relay transport, global user discovery, hosted storage APIs, remote-host installation, transfer ZIP commands, service updater/restart integration, and the general `new-key` command remain unimplemented. Their design requirements are retained in `system/readme.md`.
- The implementation transfers whole bounded snapshots rather than streaming large Git packs. Current limits are 32 MiB for repository archives and 48 MiB for a serialized peer exchange; JSON byte-array encoding adds overhead.
- Read-only members can re-encrypt/replicate already validated state and recover/reopen backups without gaining code-write authority: every code/policy operation inside the signed DAG is independently authorized. A snapshot carrier signature is not permission to invent a code update.
- Git branch/tag deletion is explicitly rejected until signed ref tombstones are implemented. Non-fast-forward pushes are also rejected; use explicit Git integration rather than silent history replacement.
- Restore issuers must be explicitly trusted and eligible under the affected CELL histories. Unresolved policy/enrollment forks may require offline recovery rather than bypassing those checks. Restore across all local files is not yet a crash-atomic transaction.
- Manual file-based pairing and fingerprint verification are required. There is no automatic secure pairing UI, and no public non-loopback management HTTP without a separately reviewed TLS/auth deployment.
