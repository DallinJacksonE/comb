#![doc = include_str!("../README.md")]

pub mod backup;
pub mod stun;
pub mod turn;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Noise authentication or protocol failure: {0}")]
    Noise(#[from] snow::Error),
    #[error("invalid message size")]
    Size,
    #[error("invalid configuration or identifier: {0}")]
    Invalid(&'static str),
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("blob integrity check failed")]
    Integrity,
}
pub type Result<T> = std::result::Result<T, Error>;
pub const MAX_PLAINTEXT: usize = 65_519;
const PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"COMB/GUARD/pinned-frame/v1";
pub struct ClientHandshake(snow::HandshakeState);
pub struct SecureSession(snow::TransportState);

pub fn static_public(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).to_bytes()
}
fn builder<'a>(private: &'a [u8; 32], public: &'a [u8; 32]) -> Result<snow::Builder<'a>> {
    let shared = x25519_dalek::StaticSecret::from(*private)
        .diffie_hellman(&x25519_dalek::PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(Error::Invalid("noncontributory X25519 peer pin"));
    }
    Ok(snow::Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE)?
        .local_private_key(private)?
        .remote_public_key(public)?)
}
pub fn client_start(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
) -> Result<(ClientHandshake, Vec<u8>)> {
    let mut state = builder(local_private, remote_public)?.build_initiator()?;
    let mut message = vec![0; 65535];
    let n = state.write_message(&[], &mut message)?;
    message.truncate(n);
    Ok((ClientHandshake(state), message))
}
pub fn server_accept(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    first_message: &[u8],
) -> Result<(SecureSession, Vec<u8>)> {
    let mut state = builder(local_private, remote_public)?.build_responder()?;
    state.read_message(first_message, &mut [0; 65535])?;
    let mut response = vec![0; 65535];
    let n = state.write_message(&[], &mut response)?;
    response.truncate(n);
    Ok((SecureSession(state.into_transport_mode()?), response))
}
impl ClientHandshake {
    pub fn finish(mut self, response: &[u8]) -> Result<SecureSession> {
        self.0.read_message(response, &mut [0; 65535])?;
        Ok(SecureSession(self.0.into_transport_mode()?))
    }
}
impl SecureSession {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::Size);
        }
        let mut wire = vec![0; plaintext.len() + 16];
        let n = self.0.write_message(plaintext, &mut wire)?;
        wire.truncate(n);
        Ok(wire)
    }
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !(16..=65_535).contains(&ciphertext.len()) {
            return Err(Error::Size);
        }
        let mut plain = vec![0; ciphertext.len()];
        let n = self.0.read_message(ciphertext, &mut plain)?;
        plain.truncate(n);
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (SecureSession, SecureSession) {
        let (c, m) = client_start(&[1; 32], &static_public(&[2; 32])).unwrap();
        let (s, r) = server_accept(&[2; 32], &static_public(&[1; 32]), &m).unwrap();
        (c.finish(&r).unwrap(), s)
    }
    #[test]
    fn hostile_transport_and_size_bounds() {
        let (mut a, mut b) = pair();
        let message = a.encrypt(b"secret").unwrap();
        let mut tampered = message.clone();
        tampered[0] ^= 1;
        assert!(b.decrypt(&tampered).is_err());
        assert_eq!(b.decrypt(&message).unwrap(), b"secret");
        assert!(b.decrypt(&message).is_err(), "replayed nonce must fail");
        assert!(a.encrypt(&vec![0; MAX_PLAINTEXT + 1]).is_err());
        assert!(matches!(b.decrypt(&vec![0; 65_536]), Err(Error::Size)));
        assert!(matches!(b.decrypt(&[0; 15]), Err(Error::Size)));
        let (mut a, mut b) = pair();
        assert_eq!(
            b.decrypt(&a.encrypt(&vec![7; MAX_PLAINTEXT]).unwrap())
                .unwrap()
                .len(),
            MAX_PLAINTEXT
        );
    }
    #[test]
    fn pinned_keys_reject_mitm_and_wrong_identity() {
        let a = [1; 32];
        let b = [2; 32];
        let attacker = [3; 32];
        let (_, first) = client_start(&a, &static_public(&attacker)).unwrap();
        assert!(server_accept(&b, &static_public(&a), &first).is_err());
        let (_, first) = client_start(&attacker, &static_public(&b)).unwrap();
        assert!(server_accept(&b, &static_public(&a), &first).is_err());
        let (c, first) = client_start(&a, &static_public(&b)).unwrap();
        assert!(server_accept(&attacker, &static_public(&a), &first).is_err());
        let (_, mut reply) = server_accept(&b, &static_public(&a), &first).unwrap();
        reply[0] ^= 1;
        assert!(c.finish(&reply).is_err());
    }
    #[test]
    fn rejects_noncontributory_static_pins() {
        assert!(client_start(&[1; 32], &[0; 32]).is_err());
        let mut low_order = [0; 32];
        low_order[0] = 1;
        assert!(client_start(&[1; 32], &low_order).is_err());
    }
    #[test]
    fn pinned_noise_roundtrip() {
        let a = [1; 32];
        let b = [2; 32];
        let (client, first) = client_start(&a, &static_public(&b)).unwrap();
        let (mut server, response) = server_accept(&b, &static_public(&a), &first).unwrap();
        let mut client = client.finish(&response).unwrap();
        let wire = client.encrypt(b"private repository").unwrap();
        assert!(!wire.windows(18).any(|s| s == b"private repository"));
        assert_eq!(server.decrypt(&wire).unwrap(), b"private repository");
        let reply = server.encrypt(b"ack").unwrap();
        assert_eq!(client.decrypt(&reply).unwrap(), b"ack");
    }
}
