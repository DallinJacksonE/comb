use comb_cell::domain::Role;
use comb_frame::{
    api::App,
    identity,
    peer::{peer_router, sync},
    store::{Peer, Store},
};

#[tokio::test]
async fn pinned_frames_replicate_encrypted_snapshots_and_reject_wrong_pins() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ad = a.path().join("node");
    let bd = b.path().join("node");
    identity::initialize(
        &ad,
        "Alice",
        "a@test",
        b"test-password",
        &a.path().join("recovery"),
    )
    .unwrap();
    identity::initialize(
        &bd,
        "Bob",
        "b@test",
        b"test-password",
        &b.path().join("recovery"),
    )
    .unwrap();
    let mut sa = Store::open(&ad, b"test-password").unwrap();
    let sb = Store::open(&bd, b"test-password").unwrap();
    let pa = sa.profile().clone();
    let pb = sb.profile().clone();
    let cell = sa.create_cell("ENCRYPTED PEER REPOSITORY".into()).unwrap();
    sa.grant(&cell.id, &pb, Role::Write).unwrap();
    let la = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ua = format!("http://{}", la.local_addr().unwrap());
    let ub = format!("http://{}", lb.local_addr().unwrap());
    let aa = App::new(sa);
    let ab = App::new(sb);
    let peer_a = Peer {
        id: pa.frame_id(),
        url: ua,
        public_key: hex::encode(pa.noise_public),
        profile: pa.clone(),
    };
    let peer_b = Peer {
        id: pb.frame_id(),
        url: ub,
        public_key: hex::encode(pb.noise_public),
        profile: pb.clone(),
    };
    aa.execute(move |s| s.add_peer(peer_b)).await.unwrap();
    let known_a = peer_a.clone();
    ab.execute(move |s| s.add_peer(known_a)).await.unwrap();
    let ta = tokio::spawn(axum::serve(la, peer_router(aa.clone())).into_future());
    let tb = tokio::spawn(axum::serve(lb, peer_router(ab.clone())).into_future());
    let report = sync(&ab, &peer_a.id).await.unwrap();
    assert_eq!(report.received, 1);
    let id = cell.id.clone();
    let copied = ab.execute(move |s| s.cell_summary(&id)).await.unwrap();
    assert_eq!(copied.name, "ENCRYPTED PEER REPOSITORY");
    let mut hostile = peer_a.clone();
    hostile.public_key = hex::encode([9; 32]);
    assert!(
        comb_frame::peer::exchange(&ab, &hostile, comb_frame::peer::PeerRequest::Pull)
            .await
            .is_err()
    );
    // Removing one local repository must not block replication of unrelated cells.
    let deleted = cell.id.clone();
    aa.execute(move |store| store.delete_cell(&deleted, "ENCRYPTED PEER REPOSITORY"))
        .await
        .unwrap();
    ab.execute(move |store| {
        let cell = store.create_cell("Bob Retained Repo".into())?;
        store.grant(&cell.id, &pa, Role::Write)
    })
    .await
    .unwrap();
    let report = sync(&aa, &pb.frame_id()).await.unwrap();
    assert_eq!(report.received, 1);
    let remaining = aa.execute(|store| store.list_cells()).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].name, "Bob Retained Repo");
    assert_eq!(ab.execute(|store| Ok(store.count())).await.unwrap(), 2);
    sync(&ab, &peer_a.id).await.unwrap();
    assert_eq!(aa.execute(|store| Ok(store.count())).await.unwrap(), 1);
    ta.abort();
    tb.abort();
}
