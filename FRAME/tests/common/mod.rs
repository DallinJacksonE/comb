use comb_frame::{
    identity,
    store::{Peer, Store},
};
use tempfile::TempDir;
pub const PASSWORD: &[u8] = b"fixture-password";
pub struct Siblings {
    pub directory: TempDir,
    pub target: Store,
    pub issuer: Store,
}

pub fn siblings() -> Siblings {
    let directory = tempfile::tempdir().unwrap();
    let a = directory.path().join("a");
    let b = directory.path().join("b");
    let first = identity::initialize(
        &a,
        "Alice",
        "a@test",
        PASSWORD,
        &directory.path().join("recovery"),
    )
    .unwrap();
    let request = identity::prepare_enrollment(&b, PASSWORD).unwrap();
    let grant = identity::authorize(&a, PASSWORD, &request).unwrap();
    identity::complete_enrollment(&b, PASSWORD, &grant, &first.profile.identity).unwrap();
    drop(first);
    let mut target = Store::open(&a, PASSWORD).unwrap();
    let mut issuer = Store::open(&b, PASSWORD).unwrap();
    let peer = |profile: identity::Profile| Peer {
        id: profile.frame_id(),
        url: "http://127.0.0.1:1".into(),
        public_key: hex::encode(profile.noise_public),
        profile,
    };
    target.add_peer(peer(issuer.profile().clone())).unwrap();
    issuer.add_peer(peer(target.profile().clone())).unwrap();
    Siblings {
        directory,
        target,
        issuer,
    }
}
