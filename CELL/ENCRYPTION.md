# CELL encryption

This document describes the version 1 implementation in `src/encryption.rs`,
`src/password.rs`, `src/lib.rs`, and `src/record.rs`. CELL is an unaudited
prototype. Its primitives encrypt bytes and authenticate bindings; FRAME supplies
storage, transport, recipient authorization, and interactive password handling.

## Algorithms and key roles

| Purpose | Implementation |
| --- | --- |
| Payload and secret encryption | XChaCha20Poly1305, 32-byte key, 24-byte nonce, 16-byte authentication tag |
| Recipient key agreement | X25519 with a fresh ephemeral sender key for each envelope |
| Wrapping-key derivation | HKDF-SHA256, 32-byte output |
| Password-key derivation | Argon2id v1.3, 65,536 KiB (64 MiB), 3 passes, 1 lane, 32-byte output |
| Signatures | Ed25519 with strict verification |
| Content identifiers and ciphertext binding | SHA-256 |
| Randomness | Operating-system RNG through `rand::rngs::OsRng` |

An identity has independent Ed25519 root-signing and X25519 recovery secrets.
A FRAME has independent Ed25519 device-signing and X25519 recipient secrets.
A `DataKey` is a random 32-byte symmetric key. Signing keys authenticate authors;
recipient keys decrypt content keys. Neither role substitutes for the other.
Random-generation failure panics rather than falling back to weaker entropy.

## Encrypting a snapshot

`seal_snapshot(plaintext, recipients, context)` performs these steps:

1. Reject an empty recipient list and generate a fresh `DataKey`.
2. Encrypt the payload once using XChaCha20Poly1305 and a random nonce.
3. Compute a binding containing the payload version, nonce, SHA-256 hash of the
   ciphertext (including its tag), and caller context.
4. Independently wrap the same data key for each supplied recipient, using that
   binding as the envelope context.
5. Return `EncryptedSnapshot { data, envelopes }`.

Each `KeyEnvelope` contains version, recipient public key, ephemeral public key,
key ID, random nonce, and encrypted data key. The key ID is SHA-256 of the common
message encoding under the `data-key-id` domain with the raw key as its field.
The wrapping key comes from ephemeral-static X25519 DH. Non-contributory shared
secrets are rejected. HKDF uses the literal salt
`COMB-CELL-X25519-HKDF-SHA256-v1`, the shared secret as input key material, and
the complete envelope AAD as expansion info. XChaCha20Poly1305 encrypts the
32-byte content key using that wrapping key and the same envelope AAD.

`open_snapshot` tries every envelope addressed to the supplied recipient. It
checks envelope version and recipient, derives the wrapping key, authenticates
and unwraps the content key, checks its length and ID, and authenticates the
payload. A junk matching envelope cannot shadow a later valid one. If no attempt
succeeds it returns `Error::Authentication`.

The lower-level `encrypt_data` API generates a new nonce but uses the key supplied
by its caller. Only `seal_snapshot` guarantees a fresh data key per call.

## Authenticated context and format

Associated authenticated data (AAD) is authenticated but **not encrypted**.
Opening requires the exact original context bytes. Applications should bind a
CELL ID, immutable version ID, and authorization-policy ID using an unambiguous
encoding. CELL does not invent or validate these application identifiers.

The shared binary `message(domain, fields)` encoding starts with ASCII
`COMB-CELL-v1`. The domain and then each field are prefixed with their byte
length as an unsigned 64-bit big-endian integer. Version fields are unsigned
32-bit big-endian integers. This encoding is independent of JSON.

| Domain | Fields in order |
| --- | --- |
| `encrypted-data` | version, payload nonce, caller context |
| `snapshot-key` | payload version, payload nonce, ciphertext SHA-256, caller context |
| `recipient-envelope` | envelope version, recipient key, ephemeral key, key ID, envelope nonce, envelope context |
| `password-envelope` | version, salt, nonce, purpose context |

For snapshots, “envelope context” is the encoded `snapshot-key` binding. For
standalone `wrap_key` it is the caller's supplied context. Envelopes therefore
cannot be moved between different snapshot ciphertexts without authentication
failure. The complete recipient list is not authenticated as a single manifest:
removing envelopes can deny access, and an authorized content-key holder can
construct additional envelopes. Authenticate the intended list and ciphertext
using a signed application manifest where that property is required.

The public envelope types use serde and reject unknown fields. Their public
fields are the wire data; secret types do not implement serde. JSON is a possible
container, not the cryptographic AAD encoding. Unsupported versions are rejected;
there is no negotiation or attacker-selected algorithm/KDF cost in version 1.

## Password-protected secrets

`seal_secret(plaintext, password, context)` generates a random 16-byte salt and
24-byte nonce. Argon2id derives a key with the fixed parameters above, then
XChaCha20Poly1305 seals the bytes with `password-envelope` AAD. The result is
`PasswordEnvelope { version, salt, nonce, ciphertext }`. No password or derived
key is stored in the envelope. Each call generates fresh salt and nonce.

`open_secret` rejects unsupported versions before deriving the key. Wrong
passwords, changed context, and modified ciphertext produce authentication
failure; CELL does not distinguish these causes or prompt for another password.
Interactive retry belongs to FRAME. CELL accepts password byte slices without
imposing password strength or a password-length policy. Applications must limit
input sizes and concurrent KDF operations; each derivation uses 64 MiB of KDF
memory. A stolen envelope permits offline password guessing, so password quality
still matters.

Bundle exports use fixed purpose contexts and layouts:

| Bundle | Purpose context | Plaintext layout |
| --- | --- | --- |
| `IdentitySecrets` | `identity-recovery-v1` | 32-byte signing seed followed by 32-byte recovery secret |
| `FrameSecrets` | `frame-local-v1` | 32-byte signing seed followed by 32-byte recipient secret |

Imports require exactly 64 decrypted bytes. Export/import restores the same
identity or device keys; enrolling a new device requires fresh FRAME keys and a
certificate. Routine devices should not receive identity root/recovery secrets.

## Recovery, revocation, and signatures

Recovery is explicit: include the identity's recovery **public** key among the
snapshot recipients. The offline recovery secret can then decrypt those snapshots
after device loss. Generating a new FRAME alone cannot decrypt old snapshots.
An encrypted identity recovery export holds root authority as well as decryption
capability; possession of both the export and its password exposes those powers.
A recovery file does not contain repository backups.

Recipient selection must come from validated policy. Certificates bind public
keys but do not by themselves grant CELL rights. Exclude revoked devices and
revoked identities' recovery keys from future recipient lists. Revocation cannot
retract keys, plaintext, or ciphertext already copied, and recipient-secret
compromise permits decryption of retained historical envelopes. Fresh ephemeral
wrapping keys do not provide forward secrecy against that compromise.

Encryption authenticates ciphertext under a key, not a publisher identity.
Use `SignedRecord` to authenticate exact manifest/payload bytes, expected domain,
trusted identity, and expected FRAME. Ed25519 signatures use the common
length-delimited domain encoding. Certificate verification requires an externally
trusted identity, bounds chains to eight certificates including the leaf, and
checks signatures and key bindings. Callers still enforce current authorization,
revocation of relevant issuers, freshness, and replay policy. SHA-256 content IDs
alone are not proof of authenticity. The `domain` module signs metadata but does
not encrypt it automatically.

## Memory and operational boundaries

`IdentitySecrets`, `FrameSecrets`, `DataKey`, and `RecipientSecret` zeroize on drop
and omit `Debug`, `Clone`, and serialization. Derived symmetric keys, bundle
buffers, and returned decrypted plaintext use zeroizing owners. These measures
do not guarantee physical erasure, eliminate all intermediate copies, or protect
against a compromised running process. Caller-owned password/plaintext slices
remain the caller's responsibility; copied or logged secrets are not wiped by CELL.

Ciphertext lengths, recipient public keys, envelope counts, nonces, salts, key
IDs, and public metadata are observable. CELL does not provide padding, hidden
recipient identities, streaming/chunked encryption, durable persistence, secure
pairing, rollback detection, backup completeness, or data deletion. Bound untrusted
serialized sizes, nesting, graph work, recipient counts, and concurrent KDF work
at the application boundary.

## Source and verification

- `src/encryption.rs`: content encryption, X25519/HKDF wrapping, snapshot binding.
- `src/password.rs`: password KDF, secret sealing, bundle export/import.
- `src/lib.rs`: randomness, binary encoding, signing keys, certificates.
- `src/record.rs`: signed payloads and content identifiers.
- `src/domain.rs` and [DOMAIN.md](DOMAIN.md): signed metadata and causal policy.

Run `cargo test -p comb-cell` for primitive, tampering, recovery, policy, and
README example tests. Generate API documentation with
`cargo doc -p comb-cell --no-deps`.
