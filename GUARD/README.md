# GUARD (`comb-guard`, library `comb_guard`)

GUARD provides mutually authenticated peer encryption, coturn configuration/process
integration, a STUN reachability diagnostic, and opaque durable ciphertext storage.
It does **not** implement ICE candidate gathering/checklists/nomination, a TURN
client or relay, discovery, FRAME authorization, or a hosted storage API.

## Pinned peer encryption

Protocol: `Noise_KK_25519_ChaChaPoly_BLAKE2s`, with the fixed
`COMB/GUARD/pinned-frame/v1` prologue. Both sides must obtain and authorize the
other FRAME's **X25519** static public key out of band. A directory response is
not identity authority; there is no TOFU. Do not pass Ed25519 signing keys here.
FRAME must check enrollment/revocation independently before accepting a session.

```rust
use comb_guard::{client_start, server_accept, static_public};
# fn main() -> comb_guard::Result<()> {
// Test identities ONLY. Production must use securely generated private keys.
let alice_private = [1u8; 32];
let bob_private = [2u8; 32];
let bob_pin = static_public(&bob_private);
let alice_pin = static_public(&alice_private);
let (pending, first) = client_start(&alice_private, &bob_pin)?;
// Send first over an untrusted connection, framed as one message.
let (mut bob, response) = server_accept(&bob_private, &alice_pin, &first)?;
// Send response back on that connection.
let mut alice = pending.finish(&response)?;
let ciphertext = alice.encrypt(b"FRAME replication payload")?;
assert_eq!(bob.decrypt(&ciphertext)?, b"FRAME replication payload");
# Ok(())
# }
```

Exact API (all fallible operations return `comb_guard::Result<T>`):

- `static_public(private: &[u8; 32]) -> [u8; 32]`
- `client_start(local_private: &[u8; 32], remote_public: &[u8; 32]) -> Result<(ClientHandshake, Vec<u8>)>`
- `server_accept(local_private: &[u8; 32], remote_public: &[u8; 32], first_message: &[u8]) -> Result<(SecureSession, Vec<u8>)>`
- `ClientHandshake::finish(self, response: &[u8]) -> Result<SecureSession>`
- `SecureSession::encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>>`
- `SecureSession::decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>`

Transport is **ordered**, not a datagram protocol: preserve message boundaries,
supply a bounded length prefix or equivalent, limit handshakes and records to
65,535 bytes, serialize writes, and do not reuse a session after reconnecting.
`MAX_PLAINTEXT` is 65,519 bytes (16-byte AEAD tag). Empty plaintext is supported.
Replays, modification, and out-of-order records fail authentication. A failed
read does not advance the receive nonce; an ordered connection should close on
failure rather than skip a missing record. New handshakes generate fresh ephemeral
keys; ciphertext cannot be replayed across sessions. Keys are not persisted by
GUARD; callers are responsible for secure identity storage and buffer lifetime.
Do not store session-encrypted bytes as recoverable backups: session keys are
not a durable CELL encryption/recovery format. This is not a security audit.

## Ciphertext-only persistence

```rust
use comb_guard::backup::BlobStore;
# fn main() -> comb_guard::Result<()> {
# let directory = tempfile::tempdir()?;
let store = BlobStore::open(directory.path(), 16 * 1024 * 1024)?;
// Supply a CELL-encrypted object / wrapped-key envelope, NEVER plaintext/private keys.
let encrypted_object = b"opaque pre-encrypted bytes from CELL";
let id = store.put_ciphertext(encrypted_object)?;
assert_eq!(store.get(&id)?, encrypted_object);
# Ok(())
# }
```

- `BlobStore::open(root: impl AsRef<Path>, max_blob_bytes: usize) -> Result<BlobStore>`
- `put_ciphertext(&self, ciphertext: &[u8]) -> Result<String>` returns lowercase SHA-256.
- `get(&self, id: &str) -> Result<Vec<u8>>` validates identifier, size and digest.

Use a service-owned durable directory (e.g. `/var/lib/comb/ciphertext`) on a local
filesystem; no other user/process may replace its ancestors. Writes use a private
same-directory tempfile, file fsync, atomic no-clobber publication, and directory
fsync. Repeated puts are idempotent and validate existing data. Traversal and
symlinks are rejected; Unix reads also use O_NOFOLLOW. There are no keys or decrypt
operations here, **but bytes cannot be proven to be ciphertext**: callers must
seal them before calling this API. Hashes/size/access timing remain visible.
This utility has a per-object bound, not total quotas, GC, network authentication,
retention policy, replication guarantees, or a backup/recovery scheduler.

A persistent full FRAME has a different trust boundary: give it its own durable
state volume and separately enrolled FRAME key. Never mount full FRAME state or
private keys into a ciphertext-only backup service. Configure the actual FRAME
service manager to restart on failure and preserve its state across upgrades;
GUARD does not deploy/enroll FRAME or make a full FRAME provider-unreadable.

## STUN / coturn

Install the maintained [coturn](https://github.com/coturn/coturn) implementation:
`sudo pacman -S coturn` (Arch), or `sudo apt install coturn` (Debian/Ubuntu).
Use a maintained package/release and review vendor security updates.
GUARD does not silently install, elevate privileges, or start a public server.

```rust
use comb_guard::turn::{CoturnConfig, CoturnProcess, Deployment};
use std::time::Duration;
# fn main() -> comb_guard::Result<()> {
let config = CoturnConfig {
    mode: Deployment::LoopbackTest,
    listen_ip: "127.0.0.1".parse().unwrap(), port: 3478,
    relay_min: 49160, relay_max: 49200,
    realm: "comb.example".into(), username: "frame".into(),
    password: "replace-with-64-random-hex-characters".into(),
};
let private_config = config.render()?; // Sensitive: NEVER log; persist with mode 0600.
# let _ = private_config;
// Requires installed coturn:
// let mut process = CoturnProcess::spawn("turnserver", &config)?;
// assert!(process.is_running()?); // liveness is not readiness
// let mapped = comb_guard::stun::binding("127.0.0.1:3478".parse().unwrap(), Duration::from_secs(2))?;
// Dropping process terminates/reaps the child and removes its private config.
# let _ = Duration::from_secs(2);
# let _ = std::mem::size_of::<CoturnProcess>();
# Ok(())
# }
```

`stun::binding(server: SocketAddr, timeout: Duration) -> Result<SocketAddr>` performs
one UDP request and validates response source (connected socket), success type,
RFC cookie, random 96-bit transaction ID, message length and XOR-MAPPED-ADDRESS
(IPv4/IPv6). `binding_request() -> [u8;20]` and
`parse_binding_response(message: &[u8], transaction: &[u8;12]) -> Result<SocketAddr>`
are also exported. This is a reachability/mapping diagnostic, not authenticated
STUN, a NAT traversal guarantee, TURN allocation health, or ICE nomination.

Config validation rejects injection, empty identities, passwords under 32 token
characters, zero listener/overlapping or invalid relay ports. Password entropy
cannot be measured: generate 32 random bytes and hex-encode, do not use repeated
characters or human passwords. Long-term credential authentication is mandatory;
there is no `no-auth` mode. Private/link-local/loopback/multicast relay targets are
denied even in test mode. Public mode requires an explicit public IPv4 address
assigned to the host (no wildcard, RFC1918, CGNAT, or IPv6 public listener). Test
mode requires loopback. Public IPv6/NAT external-IP mappings are not supported by
this generator. IPv6 mappings from STUN remain supported.

Generated settings use UDP/TCP TURN listeners with TLS/DTLS disabled; peer payloads
MUST retain GUARD E2E encryption. TURN authentication metadata and STUN mapping are
not confidential. Deployments requiring TURN-over-TLS need a separately reviewed
coturn TLS config/certificate setup, not a claim that this generator supplies it.
Restrict firewall access, enforce network egress ACLs as defense in depth, keep
quotas/rate limits, rotate credentials, and run unprivileged. The runner suppresses
child output to prevent accidental credential logging; manage coturn directly for
operator diagnostics. Spawn success is not readiness.

### Docker Compose example (Linux host networking)

`deploy/compose.yaml` uses a read-only, least-capability container with a mandatory
operator-selected pinned `COTURN_IMAGE`. Generate the validated config for the
**actual host address**, store outside Git with mode 0600, then set:

```sh
export TURN_CONFIG_FILE=/absolute/private/path/turnserver.conf
export TURN_UID="$(id -u)" TURN_GID="$(id -g)"
export COTURN_IMAGE='coturn/coturn:<reviewed-release-or-digest>'
docker compose -f GUARD/deploy/compose.yaml config --quiet
docker compose -f GUARD/deploy/compose.yaml up -d
```

The image placeholder is intentionally not a runnable tag. Replace it with a
reviewed supported tag or digest. Allow the configured listener UDP/TCP port and
relay UDP range in the host firewall. Host networking is intentional: publishing
Docker ports does not itself solve TURN advertised-address/NAT configuration.
The relay stores no repositories and needs no FRAME/backup/private-key mount.

## Verification

```sh
cargo test -p comb-guard
# Explicit optional integration against real installed coturn:
COTURN_EXECUTABLE=/path/to/turnserver cargo test -p comb-guard -- --include-ignored
```

Tests cover pinned Noise round-trip, both identity/pin substitutions (MITM),
handshake modification, ciphertext tamper/replay, noncontributory static pins,
size bounds, real filesystem persistence/corruption/traversal/symlinks, a real
local UDP STUN exchange, malformed STUN responses, safe config and process errors.
The opt-in coturn test starts a real server, validates STUN and checks unauthenticated
TURN Allocate receives **401 Unauthorized** rather than a relay allocation.
Authenticated TURN allocation/data relay, full ICE nomination and Docker deployment
have **not** been exercised by these tests.
