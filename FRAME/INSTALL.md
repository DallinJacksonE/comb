# Install, initialize, and uninstall COMB

## Supported installation

The source installer targets Linux with a running **systemd user manager**, Bash, Git, OpenSSH client tools, a Rust toolchain with Cargo/rustc, Node.js, and npm. It builds the Rust binary and GUI rather than downloading an opaque prebuilt binary. It does not use sudo, install distribution packages, or silently bootstrap third-party toolchains. Install missing prerequisites with your preferred trusted toolchain/package manager, then rerun it.

Read a downloaded installer before executing it. Once this revision is published on the selected Git branch, the curl entry point is:

```sh
curl -fsSL https://raw.githubusercontent.com/DallinJacksonE/comb/main/FRAME/install.sh -o comb-install.sh
less comb-install.sh
bash comb-install.sh
```

The equivalent pipe form is supported:

```sh
curl -fsSL https://raw.githubusercontent.com/DallinJacksonE/comb/main/FRAME/install.sh | bash
```

These URLs are publication targets, not a claim that uncommitted changes are already available remotely. To build the current checkout before publication:

```sh
bash FRAME/install.sh
```

The repository's local entrypoint detects and builds its own checkout rather than silently cloning an older published revision. From another location, `bash /path/to/comb/FRAME/install.sh` also uses that source checkout; `--source /absolute/path/to/comb` explicitly selects a different one. A standalone downloaded script or stdin pipeline without `--source` clones the published main branch.

Before either build, the installer requires a regular, valid `FRAME/uninstall.sh` in the selected source. It checks again before replacing any installation and packages that cleanup script with the installed files. Missing cleanup therefore fails early without changing an existing installation; binary and GUI output failures report their exact expected paths instead of a combined ambiguous message.

Use `--profile dev` for a faster local development installation; the default is a release build. Review and trust the selected source: Cargo/npm builds execute dependency build scripts.

The installer explains what it builds, adds a user-owned `comb` command to the configured user bin directory, installs built GUI assets independently of your checkout, updates managed PATH blocks in supported user-shell startup files, and enables/starts a user service. Existing FRAME data is not replaced. Open a new terminal (or apply the printed PATH guidance) afterward: a child install script cannot modify its parent shell's environment.

For an isolated/custom installation, `COMB_INSTALL_ROOT`, `COMB_BIN_DIR`, `COMB_DATA_DIR`, `COMB_SERVICE_NAME`, and `COMB_SERVICE_DIR` select program, launcher, data, and unit locations. The installed launcher retains the configured data-directory default in fresh shells; explicit `COMB_DATA_DIR` or `--data` selects another directory (`--data` takes precedence). The installer checks a bounded private control-channel readiness probe, not merely that systemd briefly reports a running process. Reinstall builds first and refuses collisions with files it does not own before removing the old installation.

## Why the service starts locked

An enabled process is not the same as an unlocked repository server. Before setup/unlock, FRAME exposes only a private Unix control socket in its private application directory. It does **not** open the Git, management-HTTP, or peer listeners, and it has not decrypted repository state.

This lets the service start automatically without saving your password in a unit file, shell startup file, or persistent unlock file. After logout/login, reboot, or service restart, your first interactive management command asks you to unlock again. User services normally follow the login session; this installer does not enable system-wide lingering.

Run:

```sh
comb
```

Or begin with an ordinary management command such as `comb cell list`. The first command walks you through your contributor name/email, an SSH username, a new FRAME password and confirmation, an optional SSH-key passphrase, and recovery custody. After setup, bare `comb` prints the same help as `comb -h`, without printing identity information or prompting to unlock. After a restart, use a management command such as `comb cell list` to unlock the service. Normal commands reuse the unlocked session through the private local socket. Explicit authority/recovery operations may still require a password. `comb -h`/`--help`/`--version` do not create identities; explicit enrollment and recovery flows are not replaced by first-device setup.

The local host/user is a trust boundary: processes running as your Unix user can access the unlocked management session. Socket/directory permissions do not protect an unlocked FRAME against compromised same-user processes or root.

### Web GUI access after unlock

Open the GUI at the daemon's local HTTP address (`http://127.0.0.1:7331` by default). It automatically connects to the unlocked FRAME; no management-token entry is needed. The page can manage the existing CELL, issue, and peer capabilities exposed by the GUI. CLI/Git clients still use their existing credentials, and browser access does not bypass FRAME revocation or restore checks.

Token-free browser API requests require a loopback Host, the GUI's custom request header, and browser-controlled `Sec-Fetch-Site: same-origin` metadata. Writes additionally require an Origin matching the HTTP Host, including its port. Cross-origin requests and DNS-rebinding hosts are rejected, and no CORS permission is granted. See the [W3C Fetch Metadata specification](https://www.w3.org/TR/fetch-metadata/) for the browser provenance mechanism. Older browsers that omit Fetch Metadata fail closed. Management responses are not cacheable.

This is a trusted-local-machine convenience, not OS-user authentication: non-browser programs can forge HTTP headers, so other processes/users on this machine must be trusted while the FRAME is unlocked. Do not expose or forward this listener to untrusted clients, use untrusted reverse proxies, or treat the GUI as a multi-user access boundary. No token or password is embedded in the GUI or stored in browser storage.

The managed service still closes HTTP while locked. After a restart, run `comb cell list` (or another management command) to unlock it, then reload the GUI or retry an already-open page. The GUI cannot unlock vaults itself.

Noninteractive commands do not silently initialize or unlock. For isolated tests/explicit automation, `COMB_PASSWORD` opts into noninteractive password input; do not put real secrets in shell history. Environment variables can be observed by sufficiently privileged processes. New setup, enrollment and recovery FRAME passwords are bounded to 4096 UTF-8 bytes to match managed unlock; this is not a restriction on the original password used to decrypt an old recovery file. First-device profile names/emails are bounded to 120/320 UTF-8 bytes before any identity writes. Existing larger public profiles remain exportable and do not block session credential retrieval.

Existing vaults with longer passwords are never rewritten or deleted to force compatibility. Stop the managed user service and use the manual `comb serve` workflow for them; enroll/recover a fresh FRAME in a separate data directory with a compatible new password before switching to managed startup. Retain the old vault/recovery material until the replacement is verified.

## Optional HTTPS WebGUI hosting

The default installation intentionally remains local-only. Developers may opt into direct HTTPS with a certificate/key or use a separate loopback remote-authenticated listener behind an HTTPS proxy. See [the HTTPS hosting guide](HTTPS.md) for certificate provisioning, local development trust, Let's Encrypt-only Caddy configuration, a persistent systemd service drop-in, renewal, and verification. No public certificate or CA trust installation happens automatically. Never proxy/forward the default automatic-access listener on port 7331. HTTPS browser sessions require the management token and do not bypass local FRAME unlock.

## SSH Git access

First-device setup generates a separate Ed25519 OpenSSH client key and adds a dedicated `comb-<FRAME-ID-prefix>` alias to `~/.ssh/config`, preserving existing entries. The alias selects the FRAME's client key automatically for every CELL Git remote on that FRAME. Repository pages and `comb cell list` expose the actual SSH remote; use it verbatim, for example:

```sh
git clone comb-YOUR_FRAME_ID_PREFIX:example.git
git remote set-url origin comb-YOUR_FRAME_ID_PREFIX:example.git
git push origin main
```

The example alias is a placeholder, not a second username. `comb ssh status` shows the actual alias, username, listener, and public metadata, never private key contents. Usernames start with a lowercase ASCII letter and contain up to 32 lowercase letters, digits, underscores, or hyphens; they are distinct from contributor display names and email addresses.

The SSH passphrase protects the client key on disk; the server accepts public-key authentication, not username/password login. OpenSSH asks for the passphrase when necessary. An available `ssh-agent` may cache the unlocked key (`AddKeysToAgent yes`); without an agent, OpenSSH asks again for later Git commands. Entering an empty passphrase is supported and leaves the client key unencrypted with mode `0600`. Neither choice changes the required password encryption of FRAME vaults, recovery material, or the separate SSH server host key. Generated aliases pin that host key in a private known-hosts file; they do not disable host verification. Do not copy the client private key to collaborators or confuse it with recovery authority.

### Add SSH to an existing installation

Reinstall the updated checkout with `bash FRAME/install.sh`; uninstall is unnecessary. Then run:

```sh
comb ssh setup --username YOUR_USERNAME
systemctl --user restart comb.service
comb cell list
comb ssh status
```

Setup asks for the optional SSH passphrase and existing FRAME password. It preserves identity, CELLs, recovery files, and unrelated SSH configuration, and refuses to overwrite an existing SSH key. Restart/unlock loads the newly signed profile and encrypted host key into an already-running daemon. Enrolled devices can configure SSH without root/recovery authority. To install or refresh an alias for an already-generated key, use `comb ssh configure`; `--ssh-config /absolute/path` selects an explicit alternative config file.

SSH binds only `127.0.0.1:7333` by default and remains closed while the managed service is locked. An explicit `comb ssh setup --listen ADDRESS:PORT` (or `comb user --ssh-listen ADDRESS:PORT` at first setup) saves a different address. `comb serve --ssh-listen ADDRESS:PORT` overrides the listener for a particular run; adjust client configuration if overriding its port. A non-loopback address is opt-in: expose it only with appropriate firewalling and independently verified host-key trust. Remote collaborators must use their own client keys in validated, explicitly pinned FRAME profiles, plus current CELL permissions. SSH is restricted to Git upload/receive-pack: it provides no shell, PTY, forwarding, or file-transfer subsystem.

Existing HTTP Git remotes still work. Their password is the local management credential from `comb token`, not the SSH username/passphrase or FRAME password. Existing ID-based Git remotes remain valid alongside slug-based remotes.

For explicit automation, `COMB_USERNAME`, `COMB_SSH_KEY_PASSPHRASE`, and `COMB_SSH_LISTEN` supply setup choices. With `COMB_PASSWORD`, username defaults to `comb` and the SSH passphrase defaults to empty; no real user SSH config is modified unless `COMB_SSH_CONFIG` or `--ssh-config` explicitly selects a destination. Prefer interactive hidden prompts for real secrets and do not put passwords/passphrases in command arguments or shell history.

## Your recovery file is not optional knowledge

Initial setup creates `identity.recovery` in the FRAME data directory by default (`comb user --recovery /your/offline/path` selects another destination during first-device setup).

- The encrypted recovery file **and its original password** can restore identity authority and historical decryption capability after device loss. Neither alone is sufficient.
- It is **not a repository backup**. Keep sufficient encrypted CELL backups/objects/envelopes separately (`comb cell backup ...`).
- Copy the recovery file to protected offline storage, verify the copy, and retain the original password safely and separately. Do not delete your last verified copy.
- If every usable device and recovery copy/password is lost, COMB has no provider password reset, escrow key, or override. Surviving ciphertext alone cannot reconstruct missing secrets.
- A stolen recovery file together with its password compromises identity-wide authority. Device revocation does not undo stolen root/recovery authority.
- The current prototype also retains encrypted `root.vault` on first/recovered devices. Installation does not remove it or change that documented trust boundary.

Uninstall preserves recovery and repository state, but it does not create or verify an independent backup for you.

## Service operation

Defaults:

- Command: `~/.local/bin/comb`.
- Installed build/assets: `${XDG_DATA_HOME:-$HOME/.local/share}/comb-install`.
- Identity and encrypted CELL state: `${XDG_DATA_HOME:-$HOME/.local/share}/comb`.
- User unit: `${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/comb.service`.
- Unlocked management/Git/GUI: `http://127.0.0.1:7331`.
- Default peer carrier: `http://127.0.0.1:7332`.
- SSH Git after setup/unlock: `127.0.0.1:7333`.

```sh
systemctl --user status comb.service
systemctl --user restart comb.service
journalctl --user -u comb.service
comb cell list
comb webgui
```

Restart intentionally locks the service again; the next management command unlocks it. Existing revocation locking is a separate state: unlocking encrypted files does not reverse a revoked FRAME or its CELL permissions. Port conflicts or corrupted/mismatched state fail unlock/start rather than reporting a serving daemon. Native Git operations still use standard Git; installation does not add Git wrappers.

## Uninstall

From the source checkout, default installations can be removed with:

```sh
bash FRAME/uninstall.sh
```

For a custom program root, retain the installation override: `COMB_INSTALL_ROOT=/your/custom/root bash FRAME/uninstall.sh`. This is program cleanup only; it is not a data-purge command.

Run the installed uninstaller (the checkout is not needed):

```sh
bash "${XDG_DATA_HOME:-$HOME/.local/share}/comb-install/uninstall.sh"
```

It stops/disables the owned user service, removes installed binaries/assets and its managed PATH integration, and leaves identity keys, encrypted repositories/snapshots, recovery files, external backups, and working copies untouched. It refuses to treat arbitrary unmarked directories or foreign files as an owned installation. There is no automatic data purge. Keep recovery material and backups before manually removing any state.

## Verification

```sh
python scripts/test_install.py
cargo test -p comb-frame --test managed --test cli
python scripts/managed_walkthrough_smoke.py
make ssh-smoke
```

Installer unit tests use isolated homes and mocked build/service commands; they are not proof that a real systemd daemon ran. The managed Rust tests run real processes and test locked startup, private control permissions, wrong-password rejection, initial setup, repeated commands, bounded SIGTERM shutdown with a held HTTP connection, legacy large-profile export, and locked restart. The walkthrough smoke exercises actual hidden terminal input. Record real installer/systemd smoke results separately when qualifying a release.
