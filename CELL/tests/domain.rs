use comb_cell::domain::{Cell, Operation, Role, frame_id, identity_id};
use comb_cell::{FrameCertificate, FrameSecrets, IdentitySecrets};
use std::collections::BTreeMap;

fn actor() -> (IdentitySecrets, FrameSecrets, FrameCertificate) {
    let identity = IdentitySecrets::generate();
    let frame = FrameSecrets::generate();
    let cert = identity.certify_frame(&frame.public()).unwrap();
    (identity, frame, cert)
}

fn inject(
    cell: &Cell,
    parents: Vec<String>,
    op: Operation,
    frame: &FrameSecrets,
    cert: &FrameCertificate,
) -> Cell {
    let payload = serde_json::to_vec(
        &serde_json::json!({"cell_id": cell.id, "parents": parents, "operation": op}),
    )
    .unwrap();
    let record =
        comb_cell::SignedRecord::new(frame, cert, b"comb.cell.event.v1", &payload).unwrap();
    let id = hex::encode(record.id().unwrap());
    let mut value = serde_json::to_value(cell).unwrap();
    value["versions"]
        .as_object_mut()
        .unwrap()
        .insert(id, serde_json::to_value(record).unwrap());
    serde_json::from_value(value).unwrap()
}

#[test]
fn authorized_nonowner_writer_can_adopt_an_exact_pending_contribution() {
    let (_, owner_frame, owner_cert) = actor();
    let (bob, bob_frame, bob_cert) = actor();
    let (steve, steve_frame, steve_cert) = actor();
    let mut owner = Cell::create("adopter".into(), &owner_frame, &owner_cert).unwrap();
    for (identity, certificate) in [
        (bob.public(), bob_cert.clone()),
        (steve.public(), steve_cert.clone()),
    ] {
        owner
            .apply(
                Operation::Grant {
                    identity,
                    role: Role::Write,
                },
                &owner_frame,
                &owner_cert,
            )
            .unwrap();
        owner
            .apply(
                Operation::RegisterFrame { certificate },
                &owner_frame,
                &owner_cert,
            )
            .unwrap();
    }
    let mut stale = owner.clone();
    owner
        .apply(
            Operation::Revoke {
                identity_id: identity_id(&bob.public()),
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    let contribution = stale
        .apply(
            Operation::Publish {
                refs: BTreeMap::from([("refs/heads/main".into(), "work".into())]),
            },
            &bob_frame,
            &bob_cert,
        )
        .unwrap();
    owner.merge(&stale).unwrap();
    owner
        .apply(
            Operation::Adopt {
                version_ids: vec![contribution],
            },
            &steve_frame,
            &steve_cert,
        )
        .unwrap();
    assert!(owner.pending().is_empty());
    assert_eq!(owner.refs()["refs/heads/main"], "work");
    assert_eq!(owner.owner, owner_cert.identity);
    assert!(
        owner
            .apply(
                Operation::RevokeFrame {
                    frame_id: frame_id(&owner_frame.public())
                },
                &steve_frame,
                &steve_cert
            )
            .is_err()
    );
}

#[test]
fn stale_policy_cannot_be_laundered_through_reconciliation() {
    let (identity, first, first_cert) = actor();
    let (_, outsider, outsider_cert) = actor();
    let sibling = FrameSecrets::generate();
    let sibling_cert = identity.certify_frame(&sibling.public()).unwrap();
    let mut cell = Cell::create("policy-quarantine".into(), &first, &first_cert).unwrap();
    cell.apply(
        Operation::RegisterFrame {
            certificate: sibling_cert.clone(),
        },
        &sibling,
        &sibling_cert,
    )
    .unwrap();
    let mut stale = cell.clone();
    cell.apply(
        Operation::RevokeFrame {
            frame_id: frame_id(&first.public()),
        },
        &sibling,
        &sibling_cert,
    )
    .unwrap();
    let grant = stale
        .apply(
            Operation::Grant {
                identity: outsider_cert.identity.clone(),
                role: Role::Write,
            },
            &first,
            &first_cert,
        )
        .unwrap();
    stale
        .apply(
            Operation::RegisterFrame {
                certificate: outsider_cert.clone(),
            },
            &outsider,
            &outsider_cert,
        )
        .unwrap();
    cell.merge(&stale).unwrap();
    assert!(!cell.is_frame_authorized(&outsider_cert, false));
    assert!(
        !cell
            .members()
            .contains_key(&identity_id(&outsider_cert.identity))
    );
    assert!(
        cell.apply(
            Operation::Adopt {
                version_ids: vec![grant.clone()]
            },
            &sibling,
            &sibling_cert
        )
        .is_err()
    );
    assert!(
        cell.apply(
            Operation::Exclude {
                version_ids: vec![grant]
            },
            &sibling,
            &sibling_cert
        )
        .is_err()
    );
}

#[test]
fn pending_data_cannot_suppress_a_valid_later_policy_revocation() {
    let (_, owner_frame, owner_cert) = actor();
    let (bob, bob_frame, bob_cert) = actor();
    let (charlie, charlie_frame, charlie_cert) = actor();
    let mut base = Cell::create("policy".into(), &owner_frame, &owner_cert).unwrap();
    for (identity, certificate) in [
        (bob.public(), bob_cert.clone()),
        (charlie.public(), charlie_cert.clone()),
    ] {
        base.apply(
            Operation::Grant {
                identity,
                role: Role::Write,
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
        base.apply(
            Operation::RegisterFrame { certificate },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    }
    let mut branch = base.clone();
    base.apply(
        Operation::Revoke {
            identity_id: identity_id(&bob.public()),
        },
        &owner_frame,
        &owner_cert,
    )
    .unwrap();
    branch
        .apply(
            Operation::Publish {
                refs: BTreeMap::new(),
            },
            &bob_frame,
            &bob_cert,
        )
        .unwrap();
    branch
        .apply(
            Operation::Revoke {
                identity_id: identity_id(&charlie.public()),
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    base.merge(&branch).unwrap();
    assert!(!base.is_frame_authorized(&charlie_cert, false));
    assert!(
        base.apply(
            Operation::Publish {
                refs: BTreeMap::new()
            },
            &charlie_frame,
            &charlie_cert
        )
        .is_err()
    );
}

#[test]
fn reserved_conflict_namespace_cannot_be_published() {
    let (_, frame, cert) = actor();
    let mut cell = Cell::create("reserved".into(), &frame, &cert).unwrap();
    assert!(
        cell.apply(
            Operation::Publish {
                refs: BTreeMap::from([("refs/comb/forged".into(), "x".into())])
            },
            &frame,
            &cert
        )
        .is_err()
    );
}

#[test]
fn signed_invalid_ancestry_authority_and_frame_substitutions_are_rejected() {
    let (root, frame, cert) = actor();
    let (_, attacker, attacker_cert) = actor();
    let mut cell = Cell::create("hostile".into(), &frame, &cert).unwrap();
    let missing = inject(
        &cell,
        vec!["f".repeat(64)],
        Operation::Publish {
            refs: BTreeMap::new(),
        },
        &frame,
        &cert,
    );
    assert!(missing.validate().is_err());
    assert!(cell.merge(&missing).is_err());
    let forged = inject(
        &cell,
        vec![cell.id.clone()],
        Operation::Grant {
            identity: attacker_cert.identity.clone(),
            role: Role::Write,
        },
        &attacker,
        &attacker_cert,
    );
    assert!(forged.validate().is_err());
    assert!(cell.merge(&forged).is_err());
    let mut substituted = frame.public();
    substituted.encryption_key[0] ^= 1;
    let replacement = root.certify_frame(&substituted).unwrap();
    assert!(
        cell.apply(
            Operation::RegisterFrame {
                certificate: replacement.clone()
            },
            &frame,
            &cert
        )
        .is_err()
    );
    assert!(!cell.is_frame_authorized(&replacement, false));
    let mut cycle = serde_json::to_value(&missing).unwrap();
    let versions = cycle["versions"].as_object_mut().unwrap();
    let id = versions.keys().next().unwrap().clone();
    let payload = serde_json::to_vec(&serde_json::json!({"cell_id": cell.id, "parents": [id], "operation": Operation::Publish { refs: BTreeMap::new() }})).unwrap();
    versions.values_mut().next().unwrap()["payload"] = serde_json::to_value(payload).unwrap();
    let cycle: Cell = serde_json::from_value(cycle).unwrap();
    assert!(cycle.validate().is_err());
}

#[test]
fn sibling_revocation_rejects_signed_descendants_and_quarantines_stale_frame_work() {
    let (identity, first, first_cert) = actor();
    let sibling = FrameSecrets::generate();
    let sibling_cert = identity.certify_frame(&sibling.public()).unwrap();
    let mut cell = Cell::create("siblings".into(), &first, &first_cert).unwrap();
    cell.apply(
        Operation::RegisterFrame {
            certificate: sibling_cert.clone(),
        },
        &sibling,
        &sibling_cert,
    )
    .unwrap();
    let mut stale = cell.clone();
    let revocation = cell
        .apply(
            Operation::RevokeFrame {
                frame_id: frame_id(&first.public()),
            },
            &sibling,
            &sibling_cert,
        )
        .unwrap();
    let illegal = inject(
        &cell,
        vec![revocation],
        Operation::Publish {
            refs: BTreeMap::new(),
        },
        &first,
        &first_cert,
    );
    assert!(illegal.validate().is_err());
    assert!(cell.merge(&illegal).is_err());
    let work = stale
        .apply(
            Operation::Publish {
                refs: BTreeMap::from([("refs/heads/x".into(), "stale".into())]),
            },
            &first,
            &first_cert,
        )
        .unwrap();
    assert_eq!(cell.merge(&stale).unwrap().pending, vec![work]);
    assert!(cell.refs().is_empty());
    assert!(!cell.is_frame_authorized(&first_cert, false));
    assert!(cell.is_frame_authorized(&sibling_cert, true));
}

#[test]
fn stale_work_is_quarantined_then_exactly_adopted_or_excluded() {
    use comb_cell::domain::Issue;
    let (_, owner_frame, owner_cert) = actor();
    let (bob, bob_frame, bob_cert) = actor();
    let mut owner = Cell::create("stale".into(), &owner_frame, &owner_cert).unwrap();
    owner
        .apply(
            Operation::Grant {
                identity: bob.public(),
                role: Role::Write,
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    owner
        .apply(
            Operation::RegisterFrame {
                certificate: bob_cert.clone(),
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    owner
        .apply(
            Operation::Publish {
                refs: BTreeMap::from([("refs/heads/main".into(), "prior".into())]),
            },
            &bob_frame,
            &bob_cert,
        )
        .unwrap();
    // The revocation causally acknowledges this prior contribution.
    let known_prior = owner.clone();
    let mut stale = owner.clone();
    owner
        .apply(
            Operation::Revoke {
                identity_id: identity_id(&bob.public()),
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    let work = stale
        .apply(
            Operation::Publish {
                refs: BTreeMap::from([("refs/heads/main".into(), "stale".into())]),
            },
            &bob_frame,
            &bob_cert,
        )
        .unwrap();
    let issue = stale
        .apply(
            Operation::AddIssue {
                issue: Issue {
                    id: "1".into(),
                    title: "pending".into(),
                    body: "body".into(),
                    closed: false,
                },
            },
            &bob_frame,
            &bob_cert,
        )
        .unwrap();
    let report = owner.merge(&stale).unwrap();
    assert_eq!(report.accepted, 0);
    assert_eq!(report.pending.len(), 2);
    assert_eq!(owner.refs()["refs/heads/main"], "prior");
    assert!(owner.issues().is_empty());
    let mut clean = owner.clone();
    assert!(
        owner
            .apply(
                Operation::Adopt {
                    version_ids: vec![]
                },
                &owner_frame,
                &owner_cert
            )
            .is_err()
    );
    assert!(
        owner
            .apply(
                Operation::Adopt {
                    version_ids: vec![work.clone(), work.clone()]
                },
                &owner_frame,
                &owner_cert
            )
            .is_err()
    );
    assert!(
        owner
            .apply(
                Operation::Adopt {
                    version_ids: vec!["missing".into()]
                },
                &owner_frame,
                &owner_cert
            )
            .is_err()
    );
    owner
        .apply(
            Operation::Adopt {
                version_ids: vec![work.clone()],
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    assert_eq!(owner.pending(), vec![issue.clone()]);
    assert_eq!(owner.refs()["refs/heads/main"], "stale");
    owner
        .apply(
            Operation::Adopt {
                version_ids: vec![issue.clone()],
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    assert_eq!(owner.issues()[0].title, "pending");
    assert!(owner.pending().is_empty());
    clean
        .apply(
            Operation::Exclude {
                version_ids: vec![work, issue],
            },
            &owner_frame,
            &owner_cert,
        )
        .unwrap();
    assert!(clean.pending().is_empty());
    assert_eq!(clean.refs()["refs/heads/main"], "prior");
    assert!(clean.issues().is_empty());
    let mut replica = known_prior;
    // Newly received control versions are accepted; excluded data is not.
    let report = replica.merge(&clean).unwrap();
    assert_eq!(report.accepted, 2); // owner revocation and exclusion
    assert!(report.pending.is_empty());
    let bytes = serde_json::to_value(&owner).unwrap();
    let stale_bytes = serde_json::to_value(&stale).unwrap();
    for (id, record) in stale_bytes["versions"].as_object().unwrap() {
        assert_eq!(&bytes["versions"][id], record); // Original attribution is immutable.
    }
}

#[test]
fn merge_preserves_concurrent_refs_and_is_idempotent() {
    let (_, frame, cert) = actor();
    let mut left = Cell::create("merge".into(), &frame, &cert).unwrap();
    let mut right = left.clone();
    left.apply(
        Operation::Publish {
            refs: BTreeMap::from([("refs/heads/main".into(), "left".into())]),
        },
        &frame,
        &cert,
    )
    .unwrap();
    right
        .apply(
            Operation::Publish {
                refs: BTreeMap::from([("refs/heads/main".into(), "right".into())]),
            },
            &frame,
            &cert,
        )
        .unwrap();
    assert_eq!(left.merge(&right).unwrap().accepted, 1);
    let refs = left.refs();
    assert!(refs.values().any(|v| v == "left"));
    assert!(refs.values().any(|v| v == "right"));
    assert!(refs.keys().all(|k| k.starts_with("refs/comb/")));
    let version = left.version_id();
    assert_eq!(left.merge(&right).unwrap().accepted, 0);
    assert_eq!(left.version_id(), version);
    right.merge(&left).unwrap();
    assert_eq!(right.refs(), left.refs());
    assert_eq!(right.version_id(), left.version_id());
    left.apply(
        Operation::Publish {
            refs: BTreeMap::from([("refs/heads/main".into(), "resolved".into())]),
        },
        &frame,
        &cert,
    )
    .unwrap();
    assert_eq!(
        left.refs(),
        BTreeMap::from([("refs/heads/main".into(), "resolved".into())])
    );
}

#[test]
fn merge_validates_untrusted_history_transactionally() {
    let (_, frame, cert) = actor();
    let mut cell = Cell::create("trust".into(), &frame, &cert).unwrap();
    let mut other = cell.clone();
    other
        .apply(
            Operation::Publish {
                refs: BTreeMap::new(),
            },
            &frame,
            &cert,
        )
        .unwrap();
    let before = serde_json::to_value(&cell).unwrap();
    let mut tampered = serde_json::to_value(&other).unwrap();
    let signature_byte = &mut tampered["versions"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap()["signature"]["bytes"][0];
    *signature_byte = (signature_byte.as_u64().unwrap() ^ 1).into();
    let bad: Cell = serde_json::from_value(tampered).unwrap();
    assert!(cell.merge(&bad).is_err());
    assert_eq!(serde_json::to_value(&cell).unwrap(), before);
    let foreign = Cell::create("trust".into(), &frame, &cert).unwrap();
    assert!(cell.merge(&foreign).is_err());
    let mut bad = other;
    bad.owner.recovery_key[0] ^= 1;
    assert!(cell.merge(&bad).is_err());
}

#[test]
fn owner_policy_and_enrolled_writer_authority_are_enforced() {
    let (_, owner_frame, owner_cert) = actor();
    let (bob, bob_frame, bob_cert) = actor();
    let (_, outsider, outsider_cert) = actor();
    let mut cell = Cell::create("auth".into(), &owner_frame, &owner_cert).unwrap();
    let publish = || Operation::Publish {
        refs: BTreeMap::from([("refs/heads/main".into(), "bob".into())]),
    };
    assert!(cell.apply(publish(), &outsider, &outsider_cert).is_err());
    cell.apply(
        Operation::Grant {
            identity: bob.public(),
            role: Role::Read,
        },
        &owner_frame,
        &owner_cert,
    )
    .unwrap();
    assert!(cell.apply(publish(), &bob_frame, &bob_cert).is_err());
    cell.apply(
        Operation::RegisterFrame {
            certificate: bob_cert.clone(),
        },
        &owner_frame,
        &owner_cert,
    )
    .unwrap();
    assert!(cell.is_frame_authorized(&bob_cert, false));
    assert!(!cell.is_frame_authorized(&bob_cert, true));
    cell.apply(
        Operation::Grant {
            identity: bob.public(),
            role: Role::Write,
        },
        &owner_frame,
        &owner_cert,
    )
    .unwrap();
    cell.apply(publish(), &bob_frame, &bob_cert).unwrap();
    assert!(
        cell.apply(
            Operation::Grant {
                identity: outsider_cert.identity.clone(),
                role: Role::Write
            },
            &bob_frame,
            &bob_cert
        )
        .is_err()
    );
    let extra = FrameSecrets::generate();
    let extra_cert = bob.certify_frame(&extra.public()).unwrap();
    assert!(cell.apply(publish(), &extra, &extra_cert).is_err());
    cell.apply(
        Operation::RegisterFrame {
            certificate: extra_cert.clone(),
        },
        &extra,
        &extra_cert,
    )
    .unwrap();
    cell.apply(
        Operation::RevokeFrame {
            frame_id: frame_id(&bob_frame.public()),
        },
        &extra,
        &extra_cert,
    )
    .unwrap();
    assert!(!cell.is_frame_authorized(&bob_cert, false));
    assert!(cell.is_frame_authorized(&extra_cert, true));
    assert!(cell.apply(publish(), &bob_frame, &bob_cert).is_err());
    assert!(
        cell.apply(
            Operation::RegisterFrame {
                certificate: bob_cert.clone()
            },
            &bob_frame,
            &bob_cert
        )
        .is_err()
    );
    assert!(
        cell.apply(
            Operation::RegisterFrame {
                certificate: bob_cert
            },
            &owner_frame,
            &owner_cert
        )
        .is_err()
    );
    cell.apply(
        Operation::Revoke {
            identity_id: identity_id(&bob.public()),
        },
        &owner_frame,
        &owner_cert,
    )
    .unwrap();
    assert!(cell.apply(publish(), &extra, &extra_cert).is_err());
    cell.validate().unwrap();
}

#[test]
fn genesis_is_pinned_signed_and_metadata_changes_version() {
    let (owner, frame, cert) = actor();
    let mut cell = Cell::create("project".into(), &frame, &cert).unwrap();
    cell.validate().unwrap();
    assert_eq!(cell.owner, owner.public());
    assert_eq!(cell.members()[&identity_id(&owner.public())], Role::Write);
    assert_eq!(
        cell.identities()[&identity_id(&owner.public())],
        owner.public()
    );
    assert_eq!(cell.frames()[&frame_id(&frame.public())], cert);
    assert!(cell.is_frame_authorized(&cert, true));
    let old = cell.version_id();
    let version = cell
        .apply(
            Operation::Publish {
                refs: BTreeMap::from([("refs/heads/main".into(), "abc".into())]),
            },
            &frame,
            &cert,
        )
        .unwrap();
    assert_ne!(old, cell.version_id());
    assert!(!version.is_empty());
    assert_eq!(cell.refs()["refs/heads/main"], "abc");
    let restored: Cell = serde_json::from_slice(&serde_json::to_vec(&cell).unwrap()).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored.version_id(), cell.version_id());
    assert!(restored.pending().is_empty());
    assert!(restored.issues().is_empty());
    assert!(restored.revoked_frames().is_empty());
    assert_eq!(serde_json::to_string(&Role::Read).unwrap(), "\"read\"");
}
