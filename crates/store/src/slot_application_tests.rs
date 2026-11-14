//! Public-API coverage of the inactive slot-application write-ahead journal.

use crate::Store;
use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use validator::{
    CertifiedDag, Dag, Decision, SlotApplicationResult, SlotCertificatePayload, SlotDecision,
    SlotDecisionBinding, SlotDecisionCertificate, SlotDecisionTip, SlotOutcome, SlotProposal,
    ValidatorKey, ValidatorRecord, ValidatorSet, ValidatorSignature, Vertex, VertexId,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "karsa-slot-application-tests-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory {path:?}: {error}"),
            }
        }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    set: ValidatorSet,
    keys: Vec<Vec<u8>>,
    vertices: Vec<Vertex>,
    payload: SlotCertificatePayload,
    carrier: VertexId,
    binding: SlotDecisionBinding,
    expected_order: Vec<VertexId>,
    leader: VertexId,
}

fn signed_vertex(
    keys: &[Vec<u8>],
    author: usize,
    round: u64,
    references: Vec<VertexId>,
    payload_hash: [u8; 32],
) -> Vertex {
    let mut vertex = Vertex {
        chain_id: b"slot-store-tests".to_vec(),
        epoch: 0,
        round,
        author: format!("val-{author}").into_bytes(),
        payload_hash,
        references,
        signature: Vec::new(),
    };
    vertex.signature = Ed25519Scheme
        .sign(&keys[author], &vertex.signing_payload().unwrap())
        .unwrap();
    vertex
}

impl Fixture {
    fn new(committing: bool) -> Self {
        let mut keys = Vec::new();
        let validators = (0..4)
            .map(|index| {
                let seed = [u8::try_from(index + 1).unwrap(); 32];
                let public_key = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                keys.push([seed.as_slice(), public_key.as_slice()].concat());
                ValidatorRecord {
                    validator_id: format!("val-{index}").into_bytes(),
                    keys: vec![ValidatorKey {
                        key_id: format!("val-{index}-k0").into_bytes(),
                        algorithm_id: ALG_ED25519,
                        public_key: public_key.to_vec(),
                        activation_epoch: 0,
                        retirement_epoch: u64::MAX,
                    }],
                }
            })
            .collect();
        let set = ValidatorSet {
            epoch: 0,
            validators,
        };
        let mut dag = Dag::new(set.clone());
        dag.set_chain_id(b"slot-store-tests".to_vec());
        let mut vertices = Vec::new();
        let mut references = Vec::new();
        for round in 0..=1 {
            let mut ids = Vec::new();
            for author in 0..4 {
                let vertex = signed_vertex(&keys, author, round, references.clone(), [1; 32]);
                ids.push(dag.insert(vertex.clone()).unwrap());
                vertices.push(vertex);
            }
            references = ids;
        }
        let leader = dag.leader(1).unwrap().id().unwrap();
        if !committing {
            references.retain(|id| id != &leader);
        }
        let mut voters = Vec::new();
        for author in 0..4 {
            let vertex = signed_vertex(&keys, author, 2, references.clone(), [2; 32]);
            voters.push(dag.insert(vertex.clone()).unwrap());
            vertices.push(vertex);
        }
        let expected_order = if committing {
            let mut history: Vec<_> = vertices
                .iter()
                .filter(|vertex| vertex.round == 0)
                .map(|vertex| vertex.id().unwrap())
                .collect();
            history.push(leader.clone());
            history
        } else {
            Vec::new()
        };
        let binding = SlotDecisionBinding::from_checkpoint(
            SlotDecisionTip::from_checkpoint(
                dag.chain_id().to_vec(),
                &set,
                1,
                [7; 32],
                0,
                dag.commit_root(),
            )
            .unwrap(),
            None,
        )
        .unwrap();
        let mut ordered = Dag::new(set.clone());
        ordered.seed_order(expected_order.clone());
        let proposal = SlotProposal {
            decision: SlotDecision {
                chain_id: dag.chain_id().to_vec(),
                validator_set_id: set.id().unwrap(),
                epoch: 0,
                round: 1,
                previous: [7; 32],
                before_len: 0,
                before_root: dag.commit_root(),
                after_len: expected_order.len() as u64,
                after_root: ordered.commit_root(),
                outcome: if committing {
                    SlotOutcome::Commit {
                        leader: leader.clone(),
                    }
                } else {
                    SlotOutcome::Skip {
                        leader_author: leader.author.clone(),
                    }
                },
            },
            voters: voters[..3].to_vec(),
        };
        let mut proposal_round = Vec::new();
        for author in 0..4 {
            let hash = if author == 0 {
                proposal.digest().unwrap()
            } else {
                [3; 32]
            };
            let vertex = signed_vertex(&keys, author, 3, voters.clone(), hash);
            proposal_round.push(dag.insert(vertex.clone()).unwrap());
            vertices.push(vertex);
        }
        let proposal_carrier = proposal_round[0].clone();
        let signing_payload = proposal.decision.signing_payload().unwrap();
        // Test QC construction deliberately bypasses the production signing-intent workflow.
        let signatures = (0..3)
            .map(|index| ValidatorSignature {
                validator_id: format!("val-{index}").into_bytes(),
                key_id: format!("val-{index}-k0").into_bytes(),
                signature: Ed25519Scheme.sign(&keys[index], &signing_payload).unwrap(),
            })
            .collect();
        let payload = SlotCertificatePayload {
            certificate: SlotDecisionCertificate {
                decision: proposal.decision.clone(),
                signatures,
            },
            proposal,
            proposal_carrier: proposal_carrier.clone(),
        };
        let qc_vertex = signed_vertex(&keys, 1, 4, proposal_round, payload.digest().unwrap());
        let carrier = dag.insert(qc_vertex.clone()).unwrap();
        vertices.push(qc_vertex);
        Self {
            set,
            keys,
            vertices,
            payload,
            carrier,
            binding,
            expected_order,
            leader,
        }
    }

    fn extend_second_commit(&mut self) -> (SlotCertificatePayload, VertexId, Vec<VertexId>) {
        let mut state = self.state(self.vertices.clone());
        state.prepare(&self.payload, &self.carrier).unwrap().apply();
        let Decision::Commit(history) = state.dag().inspect_commit(2).unwrap() else {
            panic!("all round-three voters must commit the round-two leader");
        };
        assert!(!history.is_empty());
        let mut expected_order = state.dag().order().to_vec();
        expected_order.extend(history);
        let mut ordered = Dag::new(self.set.clone());
        ordered.seed_order(expected_order.clone());
        let proposal = SlotProposal {
            decision: SlotDecision {
                chain_id: state.dag().chain_id().to_vec(),
                validator_set_id: self.set.id().unwrap(),
                epoch: self.set.epoch,
                round: 2,
                previous: self.payload.certificate.decision.id().unwrap(),
                before_len: state.dag().order().len() as u64,
                before_root: state.dag().commit_root(),
                after_len: expected_order.len() as u64,
                after_root: ordered.commit_root(),
                outcome: SlotOutcome::Commit {
                    leader: state.dag().leader(2).unwrap().id().unwrap(),
                },
            },
            voters: self
                .vertices
                .iter()
                .filter(|vertex| vertex.round == 3)
                .take(3)
                .map(|vertex| vertex.id().unwrap())
                .collect(),
        };
        let round_three: Vec<_> = self
            .vertices
            .iter()
            .filter(|vertex| vertex.round == 3)
            .map(|vertex| vertex.id().unwrap())
            .collect();
        let mut round_four = vec![self.carrier.clone()];
        for author in [0, 2, 3] {
            let vertex = signed_vertex(&self.keys, author, 4, round_three.clone(), [4; 32]);
            round_four.push(state.insert(vertex.clone()).unwrap());
            self.vertices.push(vertex);
        }
        let mut round_five = Vec::new();
        for author in 0..4 {
            let hash = if author == 0 {
                proposal.digest().unwrap()
            } else {
                [5; 32]
            };
            // Every round-five vertex includes the first QC carrier in its causal past.
            let vertex = signed_vertex(&self.keys, author, 5, round_four.clone(), hash);
            round_five.push(state.insert(vertex.clone()).unwrap());
            self.vertices.push(vertex);
        }
        let signing_payload = proposal.decision.signing_payload().unwrap();
        let signatures = (0..3)
            .map(|index| ValidatorSignature {
                validator_id: format!("val-{index}").into_bytes(),
                key_id: format!("val-{index}-k0").into_bytes(),
                signature: Ed25519Scheme
                    .sign(&self.keys[index], &signing_payload)
                    .unwrap(),
            })
            .collect();
        let payload = SlotCertificatePayload {
            certificate: SlotDecisionCertificate {
                decision: proposal.decision.clone(),
                signatures,
            },
            proposal,
            proposal_carrier: round_five[0].clone(),
        };
        let vertex = signed_vertex(&self.keys, 1, 6, round_five, payload.digest().unwrap());
        let carrier = state.insert(vertex.clone()).unwrap();
        self.vertices.push(vertex);
        (payload, carrier, expected_order)
    }

    fn state(&self, vertices: impl IntoIterator<Item = Vertex>) -> CertifiedDag {
        let mut dag = Dag::new(self.set.clone());
        dag.set_chain_id(b"slot-store-tests".to_vec());
        let mut state = CertifiedDag::from_checkpoint(dag, self.binding.clone()).unwrap();
        for vertex in vertices {
            state.insert(vertex).unwrap();
        }
        state
    }

    fn persist(&self, store: &Store) {
        for vertex in &self.vertices {
            store.append_vertex(vertex).unwrap();
        }
    }

    fn assert_applied(&self, state: &CertifiedDag) {
        assert_eq!(state.dag().order(), self.expected_order);
        assert_eq!(
            state.dag().commit_root(),
            self.payload.certificate.decision.after_root
        );
        assert_eq!(state.binding().tip().next_round(), 2);
        assert_eq!(
            state.binding().tip().previous_id(),
            &self.payload.certificate.decision.id().unwrap()
        );
        assert_eq!(
            state.binding().tip().order_len(),
            self.expected_order.len() as u64
        );
        assert_eq!(
            state.binding().tip().order_root(),
            &state.dag().commit_root()
        );
        assert_eq!(state.binding().carrier(), Some(&self.carrier));
        assert_eq!(
            state.dag().skipped().len(),
            usize::from(self.expected_order.is_empty())
        );
    }

    fn assert_baseline(&self, state: &CertifiedDag) {
        assert_eq!(state.binding(), &self.binding);
        assert!(state.dag().order().is_empty());
        assert!(state.dag().skipped().is_empty());
        assert_eq!(
            state.dag().commit_root(),
            self.payload.certificate.decision.before_root
        );
    }
}

#[test]
fn replay_barrier_failure_on_second_record_preserves_a_resumable_prefix() {
    let mut fixture = Fixture::new(false);
    let (second, second_carrier, expected_order) = fixture.extend_second_commit();
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    fixture.persist(&store);
    let mut initial = fixture.state(store.vertices().unwrap());
    store
        .apply_slot_certificate(&mut initial, &fixture.payload, &fixture.carrier)
        .unwrap();
    store
        .apply_slot_certificate(&mut initial, &second, &second_carrier)
        .unwrap();
    let expected_binding = initial.binding().clone();
    let mut recovered = fixture.state(store.vertices().unwrap());
    let mut barriers = 0;
    let result = store.replay_slot_applications_with_barrier(&mut recovered, |file, root| {
        barriers += 1;
        if barriers == 2 {
            return Err(std::io::Error::other("injected second-record sync failure").into());
        }
        file.sync_all()?;
        for directory in fs::canonicalize(root)?.ancestors() {
            fs::File::open(directory)?.sync_all()?;
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(barriers, 2);
    fixture.assert_applied(&recovered);
    assert_eq!(
        store
            .replay_slot_applications(&mut recovered)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(recovered.dag().order(), expected_order);
    assert_eq!(recovered.binding(), &expected_binding);
    assert!(
        store
            .replay_slot_applications(&mut recovered)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.slot_applications().unwrap().len(), 2);
}

#[test]
fn contiguous_decisions_replay_from_baseline_and_interior_prefix() {
    for first_commits in [true, false] {
        let mut fixture = Fixture::new(first_commits);
        let (second, second_carrier, expected_order) = fixture.extend_second_commit();
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        fixture.persist(&store);
        let mut state = fixture.state(store.vertices().unwrap());
        let first_result = store
            .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
            .unwrap();
        fixture.assert_applied(&state);
        let second_result = store
            .apply_slot_certificate(&mut state, &second, &second_carrier)
            .unwrap();
        assert!(matches!(
            second_result,
            SlotApplicationResult::Applied {
                round: 2,
                decision: Decision::Commit(_)
            }
        ));
        assert_eq!(state.dag().order(), expected_order);
        assert!(!expected_order.is_empty());
        assert_eq!(
            state.dag().commit_root(),
            second.certificate.decision.after_root
        );
        let final_binding = state.binding().clone();
        let final_skipped = state.dag().skipped().to_vec();
        assert_eq!(final_binding.tip().next_round(), 3);
        assert_eq!(
            final_binding.tip().previous_id(),
            &second.certificate.decision.id().unwrap()
        );
        assert_eq!(final_binding.tip().order_len(), expected_order.len() as u64);
        assert_eq!(
            final_binding.tip().order_root(),
            &second.certificate.decision.after_root
        );
        assert_eq!(final_binding.carrier(), Some(&second_carrier));
        let records = store.slot_applications().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].payload, fixture.payload);
        assert_eq!(records[0].carrier, fixture.carrier);
        assert_eq!(records[1].payload, second);
        assert_eq!(records[1].carrier, second_carrier);
        let wal = fs::read(dir.0.join("slot-applications")).unwrap();
        drop(state);
        drop(store);

        let store = Store::open(&dir.0).unwrap();
        assert_eq!(store.slot_applications().unwrap(), records);
        for interior_prefix in [false, true] {
            let mut recovered = fixture.state(store.vertices().unwrap());
            let expected_results = if interior_prefix {
                // Restore a valid in-memory prefix without appending another WAL request.
                assert_eq!(
                    recovered
                        .prepare(&fixture.payload, &fixture.carrier)
                        .unwrap()
                        .apply(),
                    first_result
                );
                fixture.assert_applied(&recovered);
                vec![second_result.clone()]
            } else {
                fixture.assert_baseline(&recovered);
                vec![first_result.clone(), second_result.clone()]
            };
            assert_eq!(
                store.replay_slot_applications(&mut recovered).unwrap(),
                expected_results
            );
            for _ in 0..2 {
                assert_eq!(recovered.dag().order(), expected_order);
                assert_eq!(
                    recovered.dag().commit_root(),
                    second.certificate.decision.after_root
                );
                assert_eq!(recovered.binding(), &final_binding);
                assert_eq!(recovered.dag().skipped(), final_skipped);
                assert!(
                    store
                        .replay_slot_applications(&mut recovered)
                        .unwrap()
                        .is_empty()
                );
            }
        }
        assert_eq!(fs::read(dir.0.join("slot-applications")).unwrap(), wal);
    }
}

#[test]
fn replay_rejects_wrong_interior_decision_id_or_carrier_without_mutation() {
    for first_commits in [true, false] {
        let mut fixture = Fixture::new(first_commits);
        let (second, second_carrier, _) = fixture.extend_second_commit();
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        fixture.persist(&store);
        let mut state = fixture.state(store.vertices().unwrap());
        store
            .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
            .unwrap();
        store
            .apply_slot_certificate(&mut state, &second, &second_carrier)
            .unwrap();
        let wal = fs::read(dir.0.join("slot-applications")).unwrap();
        for wrong_id in [true, false] {
            let first = &fixture.payload.certificate.decision;
            let mut previous = first.id().unwrap();
            let mut carrier = fixture.carrier.clone();
            if wrong_id {
                previous[0] ^= 1;
            } else {
                carrier.digest[0] ^= 1;
            }
            let binding = SlotDecisionBinding::from_checkpoint(
                SlotDecisionTip::from_checkpoint(
                    first.chain_id.clone(),
                    &fixture.set,
                    2,
                    previous,
                    first.after_len,
                    first.after_root,
                )
                .unwrap(),
                Some(carrier),
            )
            .unwrap();
            let mut dag = Dag::new(fixture.set.clone());
            dag.set_chain_id(first.chain_id.clone());
            for vertex in store.vertices().unwrap() {
                dag.insert(vertex).unwrap();
            }
            dag.seed_order(fixture.expected_order.clone());
            let mut invalid = CertifiedDag::from_checkpoint(dag, binding.clone()).unwrap();
            let order = invalid.dag().order().to_vec();
            let root = invalid.dag().commit_root();
            let skipped = invalid.dag().skipped().to_vec();
            assert!(
                store.replay_slot_applications(&mut invalid).is_err(),
                "wrong_id={wrong_id}, first_commits={first_commits}"
            );
            assert_eq!(invalid.binding(), &binding);
            assert_eq!(invalid.dag().order(), order);
            assert_eq!(invalid.dag().commit_root(), root);
            assert_eq!(invalid.dag().skipped(), skipped);
        }
        assert_eq!(fs::read(dir.0.join("slot-applications")).unwrap(), wal);
    }
}

#[test]
fn commit_and_skip_persist_retry_and_replay_after_discarding_memory() {
    for committing in [true, false] {
        let fixture = Fixture::new(committing);
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        fixture.persist(&store);
        let mut state = fixture.state(store.vertices().unwrap());
        let applied = store
            .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
            .unwrap();
        assert!(matches!(
            applied,
            SlotApplicationResult::Applied { round: 1, .. }
        ));
        fixture.assert_applied(&state);
        let bytes = fs::read(dir.0.join("slot-applications")).unwrap();
        let records = store.slot_applications().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload, fixture.payload);
        assert_eq!(records[0].carrier, fixture.carrier);
        assert_eq!(
            store
                .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
                .unwrap(),
            SlotApplicationResult::AlreadyApplied { round: 1 }
        );
        assert_eq!(fs::read(dir.0.join("slot-applications")).unwrap(), bytes);
        fixture.assert_applied(&state);
        // Simulate the WAL-persisted/memory-not-installed boundary by discarding a
        // successfully applied volatile state. This is not a power-loss experiment.
        drop(state);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        assert_eq!(store.slot_applications().unwrap(), records);
        let mut recovered = fixture.state(store.vertices().unwrap());
        fixture.assert_baseline(&recovered);
        assert_eq!(
            store.replay_slot_applications(&mut recovered).unwrap(),
            vec![applied]
        );
        fixture.assert_applied(&recovered);
        for _ in 0..2 {
            assert!(
                store
                    .replay_slot_applications(&mut recovered)
                    .unwrap()
                    .is_empty()
            );
            fixture.assert_applied(&recovered);
        }
        assert_eq!(fs::read(dir.0.join("slot-applications")).unwrap(), bytes);
    }
}

#[test]
fn invalid_qc_and_missing_stored_history_do_not_persist_or_mutate() {
    for committing in [true, false] {
        let fixture = Fixture::new(committing);
        for missing_history in [true, false] {
            let dir = TempDir::new();
            let store = Store::open(&dir.0).unwrap();
            if !missing_history {
                fixture.persist(&store);
            }
            let mut state = fixture.state(fixture.vertices.clone());
            let mut payload = fixture.payload.clone();
            if !missing_history {
                payload.certificate.signatures.clear();
            }
            assert!(
                store
                    .apply_slot_certificate(&mut state, &payload, &fixture.carrier)
                    .is_err()
            );
            fixture.assert_baseline(&state);
            assert!(store.slot_applications().unwrap().is_empty());
            assert!(!dir.0.join("slot-applications").exists());
        }
    }
}

#[test]
fn skip_requires_stored_leader_even_when_voters_do_not_reference_it() {
    let fixture = Fixture::new(false);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    for vertex in &fixture.vertices {
        if vertex.id().unwrap() != fixture.leader {
            store.append_vertex(vertex).unwrap();
        }
    }
    let mut state = fixture.state(fixture.vertices.clone());
    assert!(
        store
            .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
            .is_err()
    );
    fixture.assert_baseline(&state);
    assert!(store.slot_applications().unwrap().is_empty());
}

#[test]
fn corrupt_and_torn_application_wal_fail_closed_on_open() {
    let fixture = Fixture::new(true);
    let source = TempDir::new();
    let store = Store::open(&source.0).unwrap();
    fixture.persist(&store);
    let mut state = fixture.state(store.vertices().unwrap());
    store
        .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
        .unwrap();
    let bytes = fs::read(source.0.join("slot-applications")).unwrap();
    let body_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 4 + body_len + 32);
    assert_eq!(&bytes[4..6], &1u16.to_le_bytes());
    // Cover torn length, body, and checksum, including every possible tail cut.
    for end in 1..bytes.len() {
        let dir = TempDir::new();
        fs::write(dir.0.join("slot-applications"), &bytes[..end]).unwrap();
        assert!(Store::open(&dir.0).is_err(), "accepted torn WAL at {end}");
    }
    for offset in [4, 6, bytes.len() - 1] {
        let dir = TempDir::new();
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        fs::write(dir.0.join("slot-applications"), corrupt).unwrap();
        assert!(
            Store::open(&dir.0).is_err(),
            "accepted corruption at {offset}"
        );
    }
}

#[test]
fn readable_uncertain_write_cannot_be_replayed_without_a_successful_sync_barrier() {
    for after_file_sync in [false, true] {
        let fixture = Fixture::new(true);
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        fixture.persist(&store);
        let mut state = fixture.state(store.vertices().unwrap());
        let mut attempts = 0;
        let result = store.apply_slot_certificate_with_barrier(
            &mut state,
            &fixture.payload,
            &fixture.carrier,
            |file, _| {
                attempts += 1;
                if after_file_sync {
                    file.sync_all()?;
                }
                Err(std::io::Error::other("injected WAL durability barrier failure").into())
            },
        );
        assert!(result.is_err());
        assert_eq!(attempts, 1);
        fixture.assert_baseline(&state);
        // Complete, readable framing is not proof that the failed file/directory
        // durability barrier succeeded. Recovery must repeat the barrier.
        assert_eq!(store.slot_applications().unwrap().len(), 1);
        let result = store.replay_slot_applications_with_barrier(&mut state, |_, _| {
            attempts += 1;
            Err(std::io::Error::other("injected replay durability barrier failure").into())
        });
        assert!(result.is_err());
        assert_eq!(attempts, 2);
        fixture.assert_baseline(&state);
        assert_eq!(store.replay_slot_applications(&mut state).unwrap().len(), 1);
        fixture.assert_applied(&state);
        assert_eq!(store.slot_applications().unwrap().len(), 1);
    }
}

#[test]
fn journal_directory_io_failure_leaves_memory_unchanged() {
    let fixture = Fixture::new(true);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    fixture.persist(&store);
    let mut state = fixture.state(store.vertices().unwrap());
    fs::create_dir(dir.0.join("slot-applications")).unwrap();
    assert!(
        store
            .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
            .is_err()
    );
    fixture.assert_baseline(&state);
    fs::remove_dir(dir.0.join("slot-applications")).unwrap();
    assert!(store.slot_applications().unwrap().is_empty());
}

#[test]
fn staged_drop_and_activation_route_clones_without_changing_signing_lock() {
    let fixture = Fixture::new(true);
    let dir = TempDir::new();
    let mut store = Store::open(&dir.0).unwrap();
    fixture.persist(&store);
    store
        .lock_slot_decision(&fixture.payload.certificate.decision)
        .unwrap();
    let clone = store.clone();
    {
        let staged = store.stage().unwrap();
        let mut state = fixture.state(staged.store().vertices().unwrap());
        staged
            .store()
            .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
            .unwrap();
        fixture.assert_applied(&state);
    }
    assert!(store.slot_applications().unwrap().is_empty());
    assert!(clone.slot_applications().unwrap().is_empty());
    {
        let staged = store.stage().unwrap();
        let mut state = fixture.state(staged.store().vertices().unwrap());
        staged
            .store()
            .apply_slot_certificate(&mut state, &fixture.payload, &fixture.carrier)
            .unwrap();
        staged.activate().unwrap();
    }
    assert_eq!(store.slot_applications().unwrap().len(), 1);
    assert_eq!(
        clone.slot_applications().unwrap(),
        store.slot_applications().unwrap()
    );
    let mut recovered = fixture.state(clone.vertices().unwrap());
    clone.replay_slot_applications(&mut recovered).unwrap();
    fixture.assert_applied(&recovered);
    assert_eq!(
        clone.slot_decision_locks().unwrap(),
        vec![fixture.payload.certificate.decision.clone()]
    );
    let mut conflict = fixture.payload.certificate.decision.clone();
    conflict.after_root[0] ^= 1;
    assert!(clone.lock_slot_decision(&conflict).is_err());
    drop(clone);
    drop(store);
    let reopened = Store::open(&dir.0).unwrap();
    assert_eq!(reopened.slot_applications().unwrap().len(), 1);
    assert_eq!(
        reopened.slot_decision_locks().unwrap(),
        vec![fixture.payload.certificate.decision]
    );
}

fn unified_fixture(commit: bool) -> (Fixture, validator::SlotAgreementProof, VertexId) {
    use validator::slot_agreement::{
        AgreementPhase, AgreementQc, AgreementValue, AgreementView, AgreementVote,
    };
    use validator::{
        SlotAgreementProof, SlotAgreementProofEntry, SlotAgreementProofPol,
        SlotAgreementVotePayload, SlotAgreementVoteWitness,
    };
    let mut f = Fixture::new(commit);
    f.vertices.retain(|v| v.round < 4);
    let qc = |phase| {
        let vote = AgreementVote {
            context: f.binding.tip().clone(),
            view: AgreementView(0),
            phase,
            value: AgreementValue::Decision(f.payload.proposal.decision.clone()),
        };
        let bytes = vote.signing_payload(&f.set).unwrap();
        let signatures = (0..3)
            .map(|i| ValidatorSignature {
                validator_id: f.set.validators[i].validator_id.clone(),
                key_id: f.set.validators[i].keys[0].key_id.clone(),
                signature: Ed25519Scheme.sign(&f.keys[i], &bytes).unwrap(),
            })
            .collect();
        AgreementQc { vote, signatures }
    };
    let prevote = qc(AgreementPhase::Prevote);
    let mut proof = SlotAgreementProof {
        entries: vec![SlotAgreementProofEntry {
            proposal: f.payload.proposal.clone(),
            proposal_carrier: f.payload.proposal_carrier.clone(),
            view: AgreementView(0),
            view_carrier: f.carrier.clone(),
            previous_pol: None,
            pol: None,
        }],
        certificate: qc(AgreementPhase::Precommit),
        votes: vec![],
    };
    let mut refs: Vec<_> = f
        .vertices
        .iter()
        .filter(|v| v.round == 3)
        .map(|v| v.id().unwrap())
        .collect();
    let proposer = validator::slot_agreement_view_proposer(&f.set, 1, AgreementView(0)).unwrap();
    let author = f
        .set
        .validators
        .iter()
        .position(|v| v.validator_id == proposer)
        .unwrap();
    for round in 4..=8 {
        let mut hashes = [[9; 32]; 4];
        if round == 4 {
            hashes[author] = proof.view_digest(0).unwrap();
        }
        if round == 5 || round == 7 {
            let certificate = if round == 5 {
                &prevote
            } else {
                &proof.certificate
            };
            for (i, signature) in certificate.signatures.iter().enumerate() {
                let payload = SlotAgreementVotePayload {
                    vote: certificate.vote.clone(),
                    signature: signature.clone(),
                    prerequisite: if round == 5 {
                        proof.entries[0].view_carrier.clone()
                    } else {
                        proof.entries[0].pol.as_ref().unwrap().carrier.clone()
                    },
                };
                hashes[i] = payload.digest(&f.set).unwrap();
                let vertex = signed_vertex(&f.keys, i, round, refs.clone(), hashes[i]);
                let witness = SlotAgreementVoteWitness {
                    payload,
                    carrier: vertex.id().unwrap(),
                };
                if round == 5 {
                    proof.entries[0]
                        .pol
                        .get_or_insert(SlotAgreementProofPol {
                            certificate: prevote.clone(),
                            votes: vec![],
                            carrier: f.carrier.clone(),
                        })
                        .votes
                        .push(witness);
                } else {
                    proof.votes.push(witness);
                }
            }
        }
        if round == 6 {
            hashes[0] = proof.pol_digest(0, &f.set).unwrap();
        }
        if round == 8 {
            hashes[0] = proof.digest(&f.set).unwrap();
        }
        let mut next = vec![];
        for (i, hash) in hashes.into_iter().enumerate() {
            let v = signed_vertex(&f.keys, i, round, refs.clone(), hash);
            next.push(v.id().unwrap());
            f.vertices.push(v);
        }
        if round == 4 {
            proof.entries[0].view_carrier = next[author].clone();
        }
        if round == 6 {
            proof.entries[0].pol.as_mut().unwrap().carrier = next[0].clone();
        }
        refs = next;
    }
    (f, proof, refs[0].clone())
}

#[test]
fn unified_signed_apply_reopen_retry_and_uncertain_sync() {
    for commit in [true, false] {
        let (mut f, proof, carrier) = unified_fixture(commit);
        let refs = f
            .vertices
            .iter()
            .filter(|v| v.round == 8)
            .map(|v| v.id().unwrap())
            .collect();
        let legacy = signed_vertex(&f.keys, 0, 9, refs, f.payload.digest().unwrap());
        f.carrier = legacy.id().unwrap();
        f.vertices.push(legacy);
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        f.persist(&store);
        let mut state = f.state(f.vertices.clone());
        let baseline = state.binding().clone();
        assert!(
            store
                .apply_slot_agreement_with_barrier(&mut state, &proof, &carrier, |_, _| Err(
                    std::io::Error::other("uncertain sync").into()
                ))
                .is_err()
        );
        assert_eq!(state.binding(), &baseline);
        assert_eq!(store.slot_application_requests().unwrap().len(), 1);
        assert!(
            store
                .replay_slot_applications_with_barrier(&mut state, |_, _| Err(
                    std::io::Error::other("still uncertain").into()
                ))
                .is_err()
        );
        assert_eq!(state.binding(), &baseline);
        store
            .apply_slot_agreement(&mut state, &proof, &carrier)
            .unwrap();
        assert_eq!(
            store
                .apply_slot_agreement(&mut state, &proof, &carrier)
                .unwrap(),
            SlotApplicationResult::AlreadyApplied { round: 1 }
        );
        let mut wrong = carrier.clone();
        wrong.digest[0] ^= 1;
        assert!(
            store
                .apply_slot_agreement(&mut state, &proof, &wrong)
                .is_err()
        );
        let mut wrong_proof = proof.clone();
        wrong_proof.certificate.vote.context = SlotDecisionTip::from_checkpoint(
            b"wrong-chain".to_vec(),
            &f.set,
            1,
            [7; 32],
            0,
            baseline.tip().order_root().to_owned(),
        )
        .unwrap();
        assert!(
            store
                .apply_slot_agreement(&mut state, &wrong_proof, &carrier)
                .is_err()
        );
        // The legacy format cannot introduce another request at this slot.
        let mut legacy_state = f.state(f.vertices.clone());
        assert!(
            store
                .apply_slot_certificate(&mut legacy_state, &f.payload, &f.carrier)
                .is_err()
        );
        let expected = state.binding().clone();
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut recovered = f.state(store.vertices().unwrap());
        assert_eq!(
            store
                .replay_slot_applications(&mut recovered)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(recovered.binding(), &expected);
        assert_eq!(recovered.dag().commit_root(), state.dag().commit_root());
        assert!(
            store
                .replay_slot_applications(&mut recovered)
                .unwrap()
                .is_empty()
        );
    }
}
