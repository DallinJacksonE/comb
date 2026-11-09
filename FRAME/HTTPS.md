# Optional HTTPS for your FRAME

HTTPS is an opt-in hosting capability, not a certificate issued by COMB or tied to this project's maintainers. Each operator chooses a hostname, provisions its certificate, and controls renewal and network exposure. The default trusted-local-machine HTTP API/Git/GUI remains at `127.0.0.1:7331`; **never forward or reverse-proxy that automatic-access listener**. Configure the separate authenticated web listener instead.

COMB remains an unaudited prototype. HTTPS alone does not make it production-ready or turn the owner console into a multi-user hosting service.

## Choose the TLS boundary

| Mode | FRAME options | Certificate lifecycle |
| --- | --- | --- |
| Direct HTTPS | `--web-listen`, `--web-origin`, `--tls-cert`, `--tls-key` | Operator supplies PEM files and restarts/unlocks FRAME after renewal. |
| HTTPS reverse proxy/tunnel | `--web-listen`, `--web-origin`, `--web-behind-proxy` | Trusted edge terminates TLS and manages its own certificates. FRAME's upstream must bind loopback. |

Both modes use the same remote login, sessions, Host/Origin checks, and WebGUI assets. They work with managed or foreground serving. Do not combine proxy mode with certificate/key flags. No automatic ACME client or CA fallback runs inside FRAME. The supplied public Caddy example explicitly uses Let's Encrypt only, not eMudhra.

## Direct HTTPS with an existing certificate

Build the binary and GUI with `make build`. Substitute your actual hostname and absolute certificate paths:

```sh
target/debug/comb serve \
  --web-listen 0.0.0.0:7443 \
  --web-origin https://code.example.com:7443 \
  --tls-cert /absolute/private/tls/fullchain.pem \
  --tls-key /absolute/private/tls/server.key \
  --assets /absolute/path/to/comb/FRAME/webgui/dist
```

This starts a foreground daemon and prompts locally for the FRAME password. If an installed service already owns this FRAME's state/ports, configure that service instead (below), or use an independently initialized `--data` directory and distinct local/peer/SSH ports. Do not run two daemons against the same FRAME data.

Open the exact `--web-origin` URL. It must be a canonical HTTPS authority: lowercase hostname, no credentials/path/query/fragment, and no explicit `:443`; include other ports. A trailing `/` on the CLI option is accepted. DNS, firewall rules, and port forwarding must route this hostname and port to the HTTPS listener, never to `7331`.

The PEM chain starts with the server certificate followed by its intermediates. Its Subject Alternative Names must match the origin hostname/IP. The private key must match, be a regular file, and on Unix have no group/world access (`chmod 600`). Private-key symlinks are rejected, and each PEM file is limited to 1 MiB. For ACME clients that produce symlinks, use a trusted deployment hook to copy the renewed material into regular, service-user-owned files in a private directory; do not loosen key permissions. Do not commit certificates, keys, or CA state to this repository.

FRAME checks certificate validity, name matching, and key compatibility before binding. It also rejects eMudhra names found in the supplied chain. This is a deployment guard, not independent issuer-chain verification: an omitted root cannot be identified this way. Browsers/Git clients still validate the full trust chain themselves. Obtain publicly trusted certificates using a maintained external ACME client such as Certbot with an explicitly selected Let's Encrypt endpoint. Follow its own issuance and renewal instructions; COMB does not control your DNS or solve ACME challenges.

Direct TLS supports TLS 1.2/1.3 and HTTP/1.1. PEM files are loaded at unlock/start, not hot-reloaded. After renewing and securely deploying the pair, restart FRAME and unlock it again locally. Never automate this by saving a FRAME password in a service unit or renewal hook. If unattended renewal without FRAME restarts is important, prefer the TLS proxy below.

## Local development with a locally trusted certificate

A developer does not need a public hostname or ACME account to exercise HTTPS. Install [mkcert](https://github.com/FiloSottile/mkcert) and the platform/browser trust prerequisites described by its maintainers, then explicitly create and trust a local development CA:

```sh
mkdir -p "$HOME/.local/share/comb-tls"
chmod 700 "$HOME/.local/share/comb-tls"
mkcert -install
mkcert -cert-file "$HOME/.local/share/comb-tls/localhost.pem" \
  -key-file "$HOME/.local/share/comb-tls/localhost.key" localhost 127.0.0.1 ::1
chmod 600 "$HOME/.local/share/comb-tls/localhost.key"
target/debug/comb serve \
  --web-listen 127.0.0.1:7443 \
  --web-origin https://localhost:7443 \
  --tls-cert "$HOME/.local/share/comb-tls/localhost.pem" \
  --tls-key "$HOME/.local/share/comb-tls/localhost.key"
```

Run from the built checkout root for the default assets path. Open `https://localhost:7443` (not the IP URL: FRAME intentionally checks the configured Host). Trust installation is a deliberate change to your machine/browser trust stores and may require elevated permission; COMB never does it implicitly. Never distribute the local CA private key. Other devices need explicit, independently verified trust of the CA's public certificate. Local certificates are not publicly trusted and mkcert is not a production CA/renewal service. Do not bypass certificate warnings, use `curl -k`, or disable Git's TLS verification.

## Public HTTPS with Caddy and automatic renewal

Run FRAME's **separate remote-authenticated upstream**, not its local convenience router:

```sh
target/debug/comb serve \
  --web-listen 127.0.0.1:7443 \
  --web-origin https://code.example.com \
  --web-behind-proxy
```

Use the dedicated [deploy/Caddyfile](deploy/Caddyfile), replacing these nonsecret example values:

```sh
export COMB_WEB_HOST=code.example.com
export COMB_ACME_EMAIL=operator@example.com
caddy adapt --config FRAME/deploy/Caddyfile --adapter caddyfile --validate
caddy run --config FRAME/deploy/Caddyfile --adapter caddyfile
```

Install Caddy separately using its official platform instructions. The example assumes standard external ports 80/443, DNS A/AAAA records reaching this server, appropriate bind privileges/port forwarding, and persistent writable Caddy storage. Review its ACME challenge requirements before deploying; use the Let's Encrypt staging endpoint while testing issuance to avoid production rate limits. Staging certificates are not browser-trusted. The single explicit ACME issuer prevents fallback to another CA. Use a dedicated Caddy instance; wildcard/manually loaded certificates shared from other sites can undermine issuer expectations.

Caddy preserves the public Host and forwards to `127.0.0.1:7443`. Its certificate renewal does not require restarting FRAME. The sample assumes Caddy and FRAME share a host/network namespace. Do not change the upstream to a non-loopback bind to accommodate a separate container/host; use direct TLS or design a separately reviewed authenticated/encrypted upstream.

A TLS-terminating proxy or tunnel sees the management token, session cookies, repository contents, and mutations in plaintext, even when the tunnel itself is encrypted. It is trusted with full FRAME administration. Proxy mode is an explicit assertion that the edge supplies HTTPS; FRAME cannot verify its certificate, CA selection, or public reachability. Forwarded headers never grant local automatic access. For encryption terminating only at FRAME, use direct HTTPS with a TCP/TLS-passthrough forwarder, not an HTTP-terminating tunnel. Public exposure of port 7443 in proxy mode is not supported.

## Installed managed service

The installer deliberately leaves HTTPS disabled. To opt in, use a persistent user-service drop-in rather than editing the generated unit. With default install/data paths, `systemctl --user edit comb.service` can replace `ExecStart` with this proxy-mode example:

```ini
[Service]
ExecStart=
ExecStart="%h/.local/share/comb-install/bin/comb" --data "%h/.local/share/comb" serve --managed --assets "%h/.local/share/comb-install/assets" --sync-seconds 15 --web-listen 127.0.0.1:7443 --web-origin https://code.example.com --web-behind-proxy
```

For direct mode, replace `--web-behind-proxy` with `--tls-cert /absolute/path/fullchain.pem --tls-key /absolute/path/server.key`, and choose the intended bind/origin port. Retain the real installed binary, data, assets, and existing custom listener flags if using nondefault installation paths; inspect your unit locally with `systemctl --user cat comb.service`. Do not put passwords or management tokens in the unit.

```sh
systemctl --user daemon-reload
systemctl --user restart comb.service
comb cell list
```

The last command unlocks locally. Every restart intentionally closes all network listeners and invalidates remote browser sessions until local unlock succeeds. A missing/invalid certificate, origin mismatch, key permissions problem, or occupied port fails startup/unlock rather than falling back to HTTP. `comb webgui` continues to print the local `--api-url` (HTTP by default); open your configured HTTPS origin explicitly. The CLI does not discover the optional remote address.

## Remote sign-in and trust

After local unlock, obtain the management credential with `comb token` in a trusted local terminal. Treat it as a full-administration secret; enter it only into the verified HTTPS origin's login form. This is **not** the FRAME unlock password or SSH-key passphrase. Remote login does not unlock the FRAME or create collaborator accounts. All browser sessions act with the hosting FRAME's authority; do not share the owner's token as a multi-user access mechanism.

The browser exchanges the token for an opaque `__Host-comb_session` cookie with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and an eight-hour absolute lifetime. Token and session secrets are not persisted in localStorage/sessionStorage or URLs. Sessions are in-memory, capped at 128, invalidated by logout/restart/revocation, and login attempts share a bounded rate limit. Logging out revokes that session, not a stolen management token. Cookie login does not authenticate native Git; use its existing explicit credentials or SSH. Remote writes require the exact configured Origin and same-origin browser metadata; no permissive CORS is enabled.

TLS authenticates the hostname according to the client's CA trust store. It does not bind that hostname to a COMB identity or FRAME signing key. The authenticated GUI exposes the public signed FRAME profile for independent out-of-band comparison; code served by a compromised TLS origin cannot prove its own integrity. TLS and the CELL/FRAME identity certificate system have separate purposes.

## Verify a deployment

1. Unlock locally and load the exact configured HTTPS origin without warnings. An anonymous browser must see login, not the private dashboard.
2. Inspect the browser's certificate name, chain, expiry, and issuer. A valid response alone is not proof that the intended CA was selected.
3. Sign in, reload, sign out, and confirm the old session no longer authorizes requests. Restart FRAME and confirm local unlock and remote sign-in are required again.
4. With direct mode, ordinary plaintext HTTP to the web port must fail. With proxy mode, only the trusted loopback edge may reach the upstream. Never expose/forward 7331.
5. Test the renewal process with your ACME tooling. For direct mode, verify secure file deployment plus restart/local unlock; for Caddy, verify renewal and persistent storage independently.

Automated checks from the checkout root:

```sh
make test
make check
make build
make browser-smoke
make https-browser-smoke
```

The HTTPS smoke additionally requires OpenSSL, NSS `certutil`, Chromium (`COMB_CHROMIUM` overrides it), and `TMPDIR` pointing to private scratch storage. It creates a disposable CA, signs a localhost/IP server certificate, and installs trust only into an isolated browser NSS database. Both Node and Chromium verify it without certificate-error bypasses. It exercises direct TLS and a real TLS-terminating proxy, sign-in, cookies, CSRF rejection, reload, logout/replay, and locked restart. It does not request a public certificate or modify your system CA trust. Public DNS, real ACME issuance/renewal, and a real Caddy deployment require operator validation; this smoke does not claim to test them.

## Authoritative references

- [Let's Encrypt getting started and ACME endpoint](https://letsencrypt.org/getting-started/)
- [Caddy automatic HTTPS and challenge requirements](https://caddyserver.com/docs/automatic-https)
- [Caddy TLS issuer configuration](https://caddyserver.com/docs/caddyfile/directives/tls)
- [mkcert usage and local CA custody](https://github.com/FiloSottile/mkcert)
- [OWASP TLS guidance](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP session management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Browser cookie attributes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
