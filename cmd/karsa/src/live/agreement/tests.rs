use super::*;
use crate::chain;
use std::sync::atomic::{AtomicU64, Ordering};
use validator::slot_agreement::AgreementView;
use validator::{
    Dag, SlotAgreementProofEntry, SlotAgreementViewLineage, SlotDecision, SlotDecisionTip,
    SlotOutcome, SlotProposal, Vertex,
};

fn check_envelope(envelope: &CarrierEnvelope, set: &ValidatorSet) {
    let bytes = envelope.encode(set).unwrap();
    let decoded = CarrierEnvelope::decode(&bytes, set).unwrap();
    assert_eq!(&decoded, envelope);
    assert_eq!(decoded.encode(set).unwrap(), bytes);
    assert_eq!(decoded.carrier(), envelope.carrier());
    for end in 0..bytes.len() {
        assert!(
            CarrierEnvelope::decode(&bytes[..end], set).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(CarrierEnvelope::decode(&trailing, set).is_err());
    for offset in [0, 2] {
        let mut unknown = bytes.clone();
        unknown[offset] = 255;
        assert!(CarrierEnvelope::decode(&unknown, set).is_err());
    }
    let mut oversized = bytes.clone();
    oversized.resize(MAX_ENVELOPE_BYTES + 1, 0);
    assert!(CarrierEnvelope::decode(&oversized, set).is_err());
    let mut author_len = bytes.clone();
    author_len[11..15].copy_from_slice(&1025u32.to_le_bytes());
    assert!(CarrierEnvelope::decode(&author_len, set).is_err());
    let digest_offset = 15 + envelope.carrier().author.len() + 32;
    let mut wrong_digest = bytes.clone();
    wrong_digest[digest_offset] ^= 1;
    assert!(CarrierEnvelope::decode(&wrong_digest, set).is_err());
    let body_len_offset = digest_offset + 32;
    let mut body_len = bytes.clone();
    body_len[body_len_offset..body_len_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(CarrierEnvelope::decode(&body_len, set).is_err());
    let mut malformed_body = bytes.clone();
    malformed_body[body_len_offset + 4] = 255;
    assert!(CarrierEnvelope::decode(&malformed_body, set).is_err());
    if matches!(envelope.payload(), CarrierPayload::Pol(_)) {
        // Changing only the claimed outer ID cannot silently rebind the selected POL.
        let mut wrong_carrier = bytes.clone();
        wrong_carrier[3] ^= 1;
        assert!(CarrierEnvelope::decode(&wrong_carrier, set).is_err());
    }
}

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
    assert!(Adapter::recover(&store, bootstrap.clone(), &m, 1).is_err());
    let mut recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert_eq!(
        recovered.readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
    let PendingIntent::Vote { payload, .. } = &recovered.pending()[0] else {
        panic!("recovered historical vote")
    };
    assert_eq!(*payload, original);
    let output = recovered.driver.output();
    recovered.consume_durable_result(output, None).unwrap();
    assert_eq!(
        recovered.pending().len(),
        1,
        "outbox reads deduplicate by ID"
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
            let before = payload.encode(&m.set).unwrap();
            assert_eq!(
                a.pending()[0].prerequisite_carriers().unwrap(),
                vec![payload.prerequisite.clone()]
            );
            assert_eq!(payload.encode(&m.set).unwrap(), before);
            assert_eq!(payload.digest(&m.set).unwrap(), *digest);
            let mut nil = payload.clone();
            nil.vote.value = AgreementValue::Nil;
            assert_eq!(
                PendingIntent::Vote {
                    payload: nil,
                    digest: *digest
                }
                .prerequisite_carriers(),
                Err(PrerequisiteExtractionError::UnsupportedNil)
            );
            let v = signed(&m, i, 5, refs.clone(), *digest);
            let carrier = v.id().unwrap();
            let envelope = PendingIntent::Vote {
                payload: payload.clone(),
                digest: *digest,
            }
            .into_envelope(carrier.clone(), &m.set)
            .unwrap();
            assert_eq!(envelope.payload(), &CarrierPayload::Vote(payload.clone()));
            check_envelope(&envelope, &m.set);
            let mut oversized = payload.clone();
            oversized
                .signature
                .signature
                .resize(MAX_ENVELOPE_BYTES + 1, 0);
            assert!(
                PendingIntent::Vote {
                    payload: oversized,
                    digest: *digest
                }
                .into_envelope(carrier.clone(), &m.set)
                .is_err()
            );
            // Structural construction must not be mistaken for signature verification.
            let mut unauthenticated = payload.clone();
            unauthenticated.signature.signature[0] ^= 1;
            assert!(
                unauthenticated
                    .verify(&payload.vote.context, &m.set)
                    .is_err()
            );
            let unauthenticated_digest = unauthenticated.digest(&m.set).unwrap();
            let constructed = PendingIntent::Vote {
                payload: unauthenticated,
                digest: unauthenticated_digest,
            }
            .into_envelope(carrier.clone(), &m.set)
            .unwrap();
            assert!(CarrierEnvelope::decode(&constructed.encode(&m.set).unwrap(), &m.set).is_ok());
            assert!(
                PendingIntent::Vote {
                    payload: payload.clone(),
                    digest: [0; 32]
                }
                .into_envelope(carrier.clone(), &m.set)
                .is_err()
            );
            let mut wrong_author = carrier.clone();
            wrong_author.author = b"not-the-voter".to_vec();
            assert!(
                PendingIntent::Vote {
                    payload: payload.clone(),
                    digest: *digest
                }
                .into_envelope(wrong_author, &m.set)
                .is_err()
            );
            let mut nil = payload.clone();
            nil.vote.value = AgreementValue::Nil;
            assert!(
                PendingIntent::Vote {
                    payload: nil,
                    digest: *digest
                }
                .into_envelope(carrier.clone(), &m.set)
                .is_err()
            );
            let witness = validator::SlotAgreementVoteWitness {
                payload: payload.clone(),
                carrier,
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
    let before = candidate.clone();
    let mut expected = vec![lineage.entries.last().unwrap().view_carrier.clone()];
    expected.extend(witnesses.iter().map(|w| w.carrier.clone()));
    expected.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
    expected.dedup();
    assert_eq!(
        expected.len(),
        4,
        "all three prevote witnesses plus selected view"
    );
    assert_eq!(candidate.prerequisite_carriers(), expected);
    assert_eq!(
        PendingIntent::Pol {
            candidate: candidate.clone(),
            digest: pol_digest
        }
        .prerequisite_carriers()
        .unwrap(),
        expected
    );
    assert_eq!(candidate, before);
    assert_eq!(candidate.digest(), pol_digest);
    let refs: Vec<_> = vote_vertices.iter().map(|v| v.id().unwrap()).collect();
    let pol_vertices: Vec<_> = (0..4)
        .map(|i| signed(&m, i, 6, refs.clone(), pol_digest))
        .collect();
    let pol_carrier = pol_vertices[0].id().unwrap();
    let envelope = PendingIntent::Pol {
        candidate: candidate.clone(),
        digest: pol_digest,
    }
    .into_envelope(pol_carrier.clone(), &m.set)
    .unwrap();
    check_envelope(&envelope, &m.set);
    assert_eq!(envelope.payload_digest(), pol_digest);
    assert!(
        PendingIntent::Pol {
            candidate: candidate.clone(),
            digest: [0; 32]
        }
        .into_envelope(pol_carrier.clone(), &m.set)
        .is_err()
    );
    let lineage = candidate.bind_carrier(pol_carrier.clone());
    assert_eq!(envelope.payload(), &CarrierPayload::Pol(lineage.clone()));
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
                PendingIntent::Vote {
                    payload: payload.clone(),
                    digest: *digest
                }
                .prerequisite_carriers()
                .unwrap(),
                vec![pol_carrier.clone()]
            );
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
    for (i, adapter) in adapters.iter_mut().enumerate() {
        let expected: Vec<_> = adapter
            .pending()
            .iter()
            .filter_map(|p| match p {
                PendingIntent::Vote { payload, .. } => Some(payload.clone()),
                _ => None,
            })
            .collect();
        let mut b = bootstrap.clone();
        b.agreement.local_validator = m.consensus[i].id.clone();
        let recovered = Adapter::recover(&stores[i], b, &m, i).unwrap();
        let actual: Vec<_> = recovered
            .pending()
            .iter()
            .filter_map(|p| match p {
                PendingIntent::Vote { payload, .. } => Some(payload.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            actual, expected,
            "restart preserves prevote and locked precommit"
        );
        *adapter = recovered;
    }
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
    let before = proof.encode(&m.set).unwrap();
    let mut expected = vec![pol_carrier];
    expected.extend(witnesses.iter().map(|w| w.carrier.clone()));
    expected.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
    expected.dedup();
    assert_eq!(
        expected.len(),
        4,
        "all three precommit witnesses plus selected POL"
    );
    let intent = PendingIntent::FinalProof {
        proof: proof.clone(),
        digest: *digest,
    };
    assert_eq!(intent.prerequisite_carriers().unwrap(), expected);
    let refs = precommit_vertices.iter().map(|v| v.id().unwrap()).collect();
    let final_carrier = signed(&m, 0, 8, refs, *digest).id().unwrap();
    let envelope = intent.into_envelope(final_carrier.clone(), &m.set).unwrap();
    assert_eq!(envelope.payload(), &CarrierPayload::Final(proof.clone()));
    assert_eq!(envelope.payload_digest(), *digest);
    check_envelope(&envelope, &m.set);
    assert!(
        PendingIntent::FinalProof {
            proof: proof.clone(),
            digest: [0; 32]
        }
        .into_envelope(final_carrier, &m.set)
        .is_err()
    );
    // Untrusted duplicate entries cannot duplicate a readiness requirement.
    let mut duplicate = proof.clone();
    duplicate.votes.push(duplicate.votes[0].clone());
    assert_eq!(
        PendingIntent::FinalProof {
            proof: duplicate,
            digest: *digest
        }
        .prerequisite_carriers()
        .unwrap(),
        expected
    );
    let mut missing = proof.clone();
    missing.entries.clear();
    assert_eq!(
        PendingIntent::FinalProof {
            proof: missing,
            digest: *digest
        }
        .prerequisite_carriers(),
        Err(PrerequisiteExtractionError::MissingSelectedPol)
    );
    assert_eq!(proof.encode(&m.set).unwrap(), before);
    assert_eq!(*digest, proof.digest(&m.set).unwrap());
    assert_eq!(
        adapters[0].readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
}

#[test]
fn nil_has_no_dummy_carrier_or_signature() {
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { vertices, .. } = request else {
        panic!("fixture proposal");
    };
    let actual_carrier = vertices.last().unwrap().id().unwrap();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: validator::slot_agreement::AgreementPhase::Prevote,
        })
        .unwrap();
    assert_eq!(adapter.driver.sequence(), 1);
    assert_eq!(
        adapter.pending()[0].prerequisite_carriers(),
        Err(PrerequisiteExtractionError::UnsupportedNil)
    );
    assert!(matches!(
        &adapter.pending()[0],
        PendingIntent::UnsupportedNil { .. }
    ));
    let PendingIntent::UnsupportedNil { intent } = &adapter.pending()[0] else {
        panic!("durable nil obligation");
    };
    assert!(
        PendingIntent::UnsupportedNil {
            intent: intent.clone()
        }
        .into_envelope(actual_carrier, &m.set)
        .is_err()
    );
    let recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert!(matches!(
        &recovered.pending()[0],
        PendingIntent::UnsupportedNil { .. }
    ));
    assert_eq!(
        recovered.readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
}

#[test]
fn stale_owner_cannot_reconstruct_or_sign() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut stale = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let mut current = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    current.apply(request.clone()).unwrap();
    assert!(stale.apply(request).is_err());
    assert!(stale.pending().is_empty());
    assert!(stale.history.is_empty());
    assert_eq!(
        stale.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
}
