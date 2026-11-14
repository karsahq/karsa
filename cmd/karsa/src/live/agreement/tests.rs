use super::*;
use crate::chain;
use std::sync::atomic::{AtomicU64, Ordering};
use validator::slot_agreement::AgreementView;
use validator::{
    Dag, SlotAgreementProofEntry, SlotAgreementViewLineage, SlotDecision, SlotDecisionTip,
    SlotOutcome, SlotProposal, Vertex,
};

struct Dir(std::path::PathBuf);
impl Dir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "karsa-live-adapter-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn signed(
    m: &chain::Membership,
    author: usize,
    round: u64,
    references: Vec<VertexId>,
    payload_hash: [u8; 32],
) -> Vertex {
    let identity = &m.consensus[author];
    let mut v = Vertex {
        chain_id: b"live-adapter-tests".to_vec(),
        epoch: m.set.epoch,
        round,
        author: identity.id.clone(),
        payload_hash,
        references,
        signature: vec![],
    };
    v.signature = Ed25519Scheme
        .sign(&identity.private_key, &v.signing_payload().unwrap())
        .unwrap();
    v
}

fn fixture() -> (
    chain::Membership,
    AuthenticatedSlotAgreementBootstrap,
    AuthenticatedSlotAgreementRequest,
) {
    let m = chain::membership(4, None).unwrap();
    let mut dag = Dag::new(m.set.clone());
    dag.set_chain_id(b"live-adapter-tests".to_vec());
    let mut vertices = vec![];
    let mut refs = vec![];
    for round in 0..=2 {
        let mut ids = vec![];
        for author in 0..4 {
            let v = signed(&m, author, round, refs.clone(), [1; 32]);
            ids.push(dag.insert(v.clone()).unwrap());
            vertices.push(v);
        }
        ids.sort_by(|a, b| (&a.round, &a.author, &a.digest).cmp(&(&b.round, &b.author, &b.digest)));
        refs = ids;
    }
    let leader = dag.leader(1).unwrap().id().unwrap();
    let mut order: Vec<_> = vertices
        .iter()
        .filter(|v| v.round == 0)
        .map(|v| v.id().unwrap())
        .collect();
    order.sort_by(|a, b| (&a.round, &a.author, &a.digest).cmp(&(&b.round, &b.author, &b.digest)));
    order.push(leader.clone());
    let mut ordered = Dag::new(m.set.clone());
    ordered.seed_order(order.clone());
    let context = SlotDecisionTip::from_checkpoint(
        dag.chain_id().to_vec(),
        &m.set,
        1,
        [7; 32],
        0,
        dag.commit_root(),
    )
    .unwrap();
    let proposal = SlotProposal {
        decision: SlotDecision {
            chain_id: dag.chain_id().to_vec(),
            validator_set_id: m.set.id().unwrap(),
            epoch: m.set.epoch,
            round: 1,
            previous: [7; 32],
            before_len: 0,
            before_root: dag.commit_root(),
            after_len: order.len() as u64,
            after_root: ordered.commit_root(),
            outcome: SlotOutcome::Commit { leader },
        },
        voters: refs[..3].to_vec(),
    };
    let mut carriers = vec![];
    for author in 0..4 {
        let v = signed(
            &m,
            author,
            3,
            refs.clone(),
            if author == 0 {
                proposal.digest().unwrap()
            } else {
                [3; 32]
            },
        );
        carriers.push(v.id().unwrap());
        vertices.push(v);
    }
    let mut lineage = SlotAgreementViewLineage {
        entries: vec![SlotAgreementProofEntry {
            proposal: proposal.into(),
            proposal_carrier: carriers[0].clone(),
            view: AgreementView(0),
            view_carrier: carriers[0].clone(),
            previous_pol: None,
            pol: None,
        }],
    };
    let proposer = validator::slot_agreement_view_proposer(&m.set, 1, AgreementView(0)).unwrap();
    for author in 0..4 {
        let elected = m.consensus[author].id == proposer;
        let v = signed(
            &m,
            author,
            4,
            carriers.clone(),
            if elected {
                lineage.view_digest(0).unwrap()
            } else {
                [4; 32]
            },
        );
        if elected {
            lineage.entries[0].view_carrier = v.id().unwrap();
        }
        vertices.push(v);
    }
    let bootstrap = AuthenticatedSlotAgreementBootstrap {
        agreement: store::SlotAgreementBootstrap {
            context,
            set: m.set.clone(),
            local_validator: m.consensus[0].id.clone(),
        },
        predecessor: None,
        order: vec![],
        vertices: vec![],
    };
    (
        m,
        bootstrap,
        AuthenticatedSlotAgreementRequest::Propose { lineage, vertices },
    )
}

#[test]
fn exact_durable_signature_retention_and_recovery_boundary() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let mut store = Store::open(&dir.0).unwrap();
    assert!(disabled_guard(&store).is_ok());
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    assert!(disabled_guard(&store).is_err());
    let stage = store.stage().unwrap();
    assert!(
        disabled_guard(stage.store()).is_err(),
        "a staged generation must still check the signing root"
    );
    drop(stage);
    adapter.apply(request.clone()).unwrap();
    assert_eq!(adapter.driver.sequence(), 1);
    let PendingIntent::Vote { payload, digest } = &adapter.pending()[0] else {
        panic!("expected vote")
    };
    let expected = Ed25519Scheme
        .sign(
            &m.consensus[0].private_key,
            &payload.vote.signing_payload(&m.set).unwrap(),
        )
        .unwrap();
    assert_eq!(payload.signature.signature, expected);
    assert_eq!(*digest, payload.digest(&m.set).unwrap());
    let original = payload.clone();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        panic!("proposal fixture")
    };
    let refs = vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect();
    let carrier = signed(&m, 0, 5, refs, original.digest(&m.set).unwrap());
    // An authenticated observation replaces the driver's latest transition with vote=None.
    adapter
        .apply(AuthenticatedSlotAgreementRequest::ObserveVote {
            lineage,
            witness: validator::SlotAgreementVoteWitness {
                payload: original.clone(),
                carrier: carrier.id().unwrap(),
            },
            vertices: vec![carrier],
        })
        .unwrap();
    assert_eq!(adapter.pending().len(), 1);
    let PendingIntent::Vote { payload, .. } = &adapter.pending()[0] else {
        panic!("expected retained vote")
    };
    assert_eq!(*payload, original);
    assert!(
        adapter
            .driver
            .output()
            .unwrap()
            .transition
            .unwrap()
            .vote
            .is_none()
    );
    drop(adapter);
    let mut recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert_eq!(
        recovered.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    assert!(recovered.pending().is_empty());
    assert!(
        recovered
            .apply(AuthenticatedSlotAgreementRequest::AdvanceSlot)
            .is_err()
    );
}

#[test]
fn identity_mismatch_precedes_wal_and_rejection_never_signs() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    assert!(Adapter::begin(&store, bootstrap.clone(), &m, 1).is_err());
    let mut adapter = Adapter::begin(&store, bootstrap, &m, 0).unwrap();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, .. } = request else {
        panic!("proposal")
    };
    assert!(
        adapter
            .apply(AuthenticatedSlotAgreementRequest::Propose {
                lineage,
                vertices: vec![]
            })
            .is_err()
    );
    assert!(adapter.pending().is_empty());
    assert_eq!(adapter.driver.sequence(), 0);
}

#[test]
fn key_pair_mismatch_is_rejected_before_persistence() {
    let (mut m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    m.consensus[0].private_key[0] ^= 1;
    assert!(Adapter::begin(&store, bootstrap.clone(), &m, 0).is_err());
    // A valid constructor still succeeds: the failed identity check did not create a WAL.
    m.consensus[0].private_key[0] ^= 1;
    assert!(Adapter::begin(&store, bootstrap, &m, 0).is_ok());
}

#[test]
fn failed_durability_result_never_signs_and_requires_recovery() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap, &m, 0).unwrap();
    // Inject the result of an uncertain barrier at the adapter boundary, not a mock signer.
    let result = Err(StoreError::Io(std::io::Error::other(
        "injected sync uncertainty",
    )));
    assert!(adapter.consume_durable_result(result, None).is_err());
    assert!(adapter.pending().is_empty());
    assert_eq!(
        adapter.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    assert!(adapter.apply(request).is_err());
    assert_eq!(adapter.driver.sequence(), 0);
}

#[test]
fn quorum_intents_use_existing_hashes_and_precommit_exact_pol_prerequisite() {
    let (m, bootstrap, request) = fixture();
    let dirs: Vec<_> = (0..3).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut adapters: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(i, store)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            let mut adapter = Adapter::begin(store, b, &m, i).unwrap();
            adapter.apply(request.clone()).unwrap();
            adapter
        })
        .collect();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        panic!("proposal")
    };
    let refs: Vec<_> = vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect();
    let mut vote_vertices = Vec::new();
    let witnesses: Vec<_> = adapters
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let PendingIntent::Vote { payload, digest } = &a.pending()[0] else {
                panic!("prevote")
            };
            let v = signed(&m, i, 5, refs.clone(), *digest);
            let witness = validator::SlotAgreementVoteWitness {
                payload: payload.clone(),
                carrier: v.id().unwrap(),
            };
            vote_vertices.push(v);
            witness
        })
        .collect();
    for adapter in &mut adapters {
        for witness in &witnesses {
            adapter
                .apply(AuthenticatedSlotAgreementRequest::ObserveVote {
                    lineage: lineage.clone(),
                    witness: witness.clone(),
                    vertices: vote_vertices.clone(),
                })
                .unwrap();
        }
    }
    let (candidate, pol_digest) = adapters[0]
        .pending()
        .iter()
        .find_map(|intent| match intent {
            PendingIntent::Pol { candidate, digest } => Some((candidate.clone(), *digest)),
            _ => None,
        })
        .expect("quorum emits POL intent");
    assert_eq!(pol_digest, candidate.digest());
    let refs: Vec<_> = vote_vertices.iter().map(|v| v.id().unwrap()).collect();
    let pol_vertices: Vec<_> = (0..4)
        .map(|i| signed(&m, i, 6, refs.clone(), pol_digest))
        .collect();
    let pol_carrier = pol_vertices[0].id().unwrap();
    let lineage = candidate.bind_carrier(pol_carrier.clone());
    assert_eq!(lineage.pol_digest(0, &m.set).unwrap(), pol_digest);
    let mut incoming = vote_vertices;
    incoming.extend(pol_vertices.clone());
    for adapter in &mut adapters {
        adapter
            .apply(AuthenticatedSlotAgreementRequest::ObservePrevote {
                lineage: lineage.clone(),
                vertices: incoming.clone(),
            })
            .unwrap();
    }
    let refs: Vec<_> = pol_vertices.iter().map(|v| v.id().unwrap()).collect();
    let mut precommit_vertices = Vec::new();
    let witnesses: Vec<_> = adapters
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let (payload, digest) = a
                .pending()
                .iter()
                .find_map(|intent| match intent {
                    PendingIntent::Vote { payload, digest }
                        if payload.vote.phase
                            == validator::slot_agreement::AgreementPhase::Precommit =>
                    {
                        Some((payload, digest))
                    }
                    _ => None,
                })
                .expect("durable precommit");
            assert_eq!(payload.prerequisite, pol_carrier);
            assert_eq!(
                payload.signature.signature,
                Ed25519Scheme
                    .sign(
                        &m.consensus[i].private_key,
                        &payload.vote.signing_payload(&m.set).unwrap()
                    )
                    .unwrap()
            );
            let v = signed(&m, i, 7, refs.clone(), *digest);
            let witness = validator::SlotAgreementVoteWitness {
                payload: payload.clone(),
                carrier: v.id().unwrap(),
            };
            precommit_vertices.push(v);
            witness
        })
        .collect();
    for witness in &witnesses {
        adapters[0]
            .apply(AuthenticatedSlotAgreementRequest::ObserveVote {
                lineage: lineage.clone(),
                witness: witness.clone(),
                vertices: precommit_vertices.clone(),
            })
            .unwrap();
    }
    let pending = adapters[0].pending();
    assert_eq!(
        pending
            .iter()
            .filter(|p| matches!(p, PendingIntent::Pol { .. }))
            .count(),
        1,
        "snapshots must not enqueue the same POL again"
    );
    let (proof, digest) = pending
        .iter()
        .find_map(|p| match p {
            PendingIntent::FinalProof { proof, digest } => Some((proof, digest)),
            _ => None,
        })
        .expect("final proof intent");
    assert_eq!(*digest, proof.digest(&m.set).unwrap());
    assert_eq!(
        adapters[0].readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
}

#[test]
fn nil_has_no_dummy_carrier_or_signature() {
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap, &m, 0).unwrap();
    let error = adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: validator::slot_agreement::AgreementPhase::Prevote,
        })
        .unwrap_err();
    assert!(error.contains("nil vote carriers are unsupported"));
    assert_eq!(adapter.driver.sequence(), 1);
    assert!(adapter.pending().is_empty());
}
