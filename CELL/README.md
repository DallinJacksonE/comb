# comb-cell

Reusable Rust crypto primitives for COMB. **Unaudited prototype; no production-security claim.**
Package `comb-cell`, crate `comb_cell`. Public items are re-exported at crate root.

## Roles and enrollment

`IdentitySecrets` owns two independently random secrets: Ed25519 identity signing
and X25519 offline recovery. `FrameSecrets` owns separate Ed25519 FRAME signing
and X25519 FRAME recipient keys. Routine FRAME storage must contain only its
`FrameSecrets`, identity **public** data, and certificate—not `IdentitySecrets`
or `recovery_secret()`. Root authority is deliberately not shared for routine
peer enrollment: an authorized existing FRAME signs a delegated certificate.

```rust
use comb_cell::*;
let identity = IdentitySecrets::generate(); // setup/offline root authority
let frame = FrameSecrets::generate();       // a NEW FRAME for each device
let trusted_identity = identity.public();   // pin through trusted setup
let certificate = identity.certify_frame(&frame.public())?;
certificate.verify(&trusted_identity)?;
let local_file = frame.export_encrypted(b"a strong local password")?;
let same_frame = FrameSecrets::import_encrypted(&local_file, b"a strong local password")?;
assert_eq!(same_frame.public(), frame.public());
// Frame import restores the SAME device: not an enrollment/transfer mechanism.
# Ok::<(), comb_cell::Error>(())
```

`IdentityPublic { signing_key, recovery_key }`, `FramePublic { signing_key,
encryption_key }`, `FrameCertificate { identity, frame, signature, delegation }` are
serializable, public, and cloneable. Certificate verification requires an
**externally trusted expected identity**. Certificates establish key binding,
not CELL rights, pairing freshness, or non-revocation.

### Delegated device enrollment

```rust
use comb_cell::*;
let root = IdentitySecrets::generate();
let trusted_identity = root.public();
let existing = FrameSecrets::generate();
let issuer = root.certify_frame(&existing.public())?;
drop(root); // routine enrollment needs no root or recovery secrets
let new_device = FrameSecrets::generate();
// REQUIRED before issuance: verify issuer against trusted_identity AND check
// existing + issuer.issuers() are registered, non-revoked, authorized enrollers.
issuer.verify(&trusted_identity)?;
let delegated = existing.certify_frame(&issuer, &new_device.public())?;
delegated.verify(&trusted_identity)?;
assert_eq!(delegated.issuers(), vec![existing.public()]);
# Ok::<(), comb_cell::Error>(())
```

`FrameSecrets::certify_frame(&FrameCertificate, &FramePublic) -> Result<FrameCertificate>`
checks the issuer certificate chain and both issuer device keys, copies its
identity (including recovery key), signs the new device's signing/encryption
keys, and embeds the issuer in `delegation: Option<Box<FrameCertificate>>`.
`FrameCertificate::verify(&IdentityPublic) -> Result<()>` checks every identity
binding and signature, rejects repeated signer keys, and allows at most **eight
certificates total, including the leaf**. `issuers() -> Vec<FramePublic>` returns
the immediate parent first, excluding the leaf; use it only after verification.
Root-issued certificates omit `delegation` in JSON and retain their original
signature encoding. Existing direct certificates, records, and ciphertext formats
remain supported. Delegated signatures additionally authenticate the complete
issuer chain, including signatures, so a different valid path cannot be swapped
into an existing certificate or signed record.

**Caller policy checks are mandatory at issuance and use**, including enrollment,
record acceptance, and issuing restore credentials: pin the expected identity,
then require the relevant device and **every ancestor** to be currently registered,
non-revoked, and authorized for the operation. A valid certificate alone grants
no enrollment or restore right; a revoked ancestor cannot authorize descendants.
The issuance method has no externally pinned identity argument: callers must
verify the issuer against their trusted identity, not trust its embedded identity.
Apply input-size/depth limits before deserializing untrusted JSON as well; the
verification depth limit does not replace parser resource limits or secure pairing.

## Encrypt arbitrary snapshots and recover after total device loss

The caller selects recipients from validated policy; public keys from an
untrusted request, discovery result, or certificate alone do not confer rights.
AAD should bind CELL ID, immutable version ID, and authorization-policy ID using
an unambiguous encoding. Reuse the exact AAD bytes on open.

```rust
use comb_cell::*;
let identity = IdentitySecrets::generate();
let lost_frame = FrameSecrets::generate();
let offline_file = identity.export_encrypted(b"strong offline recovery password")?;
let trusted_identity = identity.public();
let aad = b"cell:42/version:abc/policy:def";
let backup = seal_snapshot(
    b"arbitrary Git pack and metadata bytes",
    &[lost_frame.public().encryption_key, trusted_identity.recovery_key],
    aad,
)?;
// Store serde_json::to_vec(&backup) with AAD and authenticated version records.
assert_eq!(&*open_snapshot(&backup, &lost_frame.recipient_secret(), aad)?,
           b"arbitrary Git pack and metadata bytes");
drop(lost_frame);
drop(identity);
let recovered = IdentitySecrets::import_encrypted(
    &offline_file, b"strong offline recovery password")?;
let new_frame = FrameSecrets::generate();
let new_certificate = recovered.certify_frame(&new_frame.public())?;
new_certificate.verify(&trusted_identity)?;
assert!(open_snapshot(&backup, &new_frame.recipient_secret(), aad).is_err());
let restored = open_snapshot(&backup, &recovered.recovery_secret(), aad)?;
assert_eq!(&*restored, b"arbitrary Git pack and metadata bytes");
# Ok::<(), comb_cell::Error>(())
```

Every `seal_snapshot(plaintext, recipients, aad)` call generates a new random
`DataKey` and ciphertext, with an independently ephemeral X25519 envelope for
each recipient. Explicitly include authorized identities' offline recovery
public keys to make backups recoverable. A revoked FRAME without root secrets
cannot exploit its identity's recovery envelopes. Revoked identities must be
excluded from both FRAME and recovery recipient lists for future versions.
No retroactive secrecy or deletion is implied.

Lower-level public APIs:

- `DataKey::generate()`, `DataKey::id() -> [u8; 32]`.
- `RecipientSecret::generate()`, `.public() -> [u8; 32]`.
- `FrameSecrets::recipient_secret() -> RecipientSecret`.
- `IdentitySecrets::recovery_secret() -> RecipientSecret` (offline use only).
- `encrypt_data(&DataKey, plaintext, aad) -> Result<EncryptedData>`.
- `decrypt_data(&DataKey, &EncryptedData, aad) -> Result<Zeroizing<Vec<u8>>>`.
- `wrap_key(&DataKey, &[u8; 32], aad) -> Result<KeyEnvelope>`.
- `unwrap_key(&KeyEnvelope, &RecipientSecret, aad) -> Result<DataKey>`.
- `seal_snapshot(plaintext, &[[u8; 32]], aad) -> Result<EncryptedSnapshot>`.
- `open_snapshot(&EncryptedSnapshot, &RecipientSecret, aad) -> Result<Zeroizing<Vec<u8>>>`.
- `seal_secret(plaintext, password, context) -> Result<PasswordEnvelope>`.
- `open_secret(&PasswordEnvelope, password, context) -> Result<Zeroizing<Vec<u8>>>`.
- Both secret bundles: `generate()`, `public()`, `export_encrypted(password)`,
  `import_encrypted(&PasswordEnvelope, password)`.

All byte inputs above are `&[u8]`. Secret bundle types, `DataKey`, and
`RecipientSecret` are not `Debug`, `Clone`, or serde-serializable and are
zeroized on drop. Plaintext return buffers are zeroizing, but callers can still
print/copy them: do not log decrypted data or passwords. Borrowed caller input
is not wiped. No physical-erasure or complete memory-remanence guarantee.

## Authenticate records and ciphertext manifests

Encryption does not identify the publisher. Sign the exact serialized snapshot
and its context/metadata in an authenticated version/manifest record:

```rust
use comb_cell::*;
let identity = IdentitySecrets::generate();
let frame = FrameSecrets::generate();
let certificate = identity.certify_frame(&frame.public())?;
let record = SignedRecord::new(&frame, &certificate,
    b"comb.acceptance.v1", b"exact commits + policy + parents")?;
let bytes = record.verify(&identity.public(), &frame.public(), b"comb.acceptance.v1")?;
assert_eq!(bytes, b"exact commits + policy + parents");
let record_id: [u8; 32] = record.id()?; // not itself an authenticity check
let signature = frame.sign(b"comb.custom.v1", b"payload");
signature.verify(&frame.public().signing_key, b"comb.custom.v1", b"payload")?;
# Ok::<(), comb_cell::Error>(())
```

`IdentitySecrets::sign(domain, payload)` is also available. `Signature`,
`SignedRecord`, password envelopes, encrypted data, key envelopes, and encrypted
snapshots derive serde and reject unknown object fields. Signed records require
trusted expected identity, FRAME keys, and expected domain. Callers must still
check authorization/revocation, exact policy/parents, replay, and freshness.

## Format and limitations

Version 1 password encryption: Argon2id v1.3, 64 MiB, 3 passes, 1 lane, 32-byte
key; random 16-byte salt and 24-byte XChaCha20Poly1305 nonce. The suite and KDF
cost are fixed by version, not attacker-chosen parameters. No password-strength
policy is imposed. Limit input sizes and concurrent KDF work at the application
boundary (each operation consumes 64 MiB).

Recipient wrapping uses X25519, HKDF-SHA256, XChaCha20Poly1305, random ephemeral
keys/nonces, and rejects non-contributory DH. Length-delimited domain-separated
binary AAD authenticates version, recipient key, ephemeral key, key ID, nonce,
and caller context. Snapshot envelopes additionally bind the data ciphertext
hash and nonce. Public fields are observable; encryption does not conceal sizes,
recipient lists, or metadata in AAD. Envelope removal can cause denial of service.
No forward secrecy after recipient-secret compromise is claimed.

No version DAG, CRDT, permissions engine, root rotation, enrollment/revocation
protocol, networking, file persistence, rollback/completeness guarantee, secure
pairing, or data deletion is implemented. Those belong to higher-level FRAME
policy. Retain signed history/checkpoints and backup completeness evidence.
Frame exports are local persistence only; transfer must generate fresh keys.

Run: `cargo test -p comb-cell`. README examples run as crate doctests.
