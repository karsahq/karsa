use super::*;
use crypto::{registry::ALG_ED25519, scheme::Ed25519Scheme};
use validator::slot_agreement::{
    AgreementInput, AgreementPhase, AgreementQc, AgreementValue, AgreementView, AgreementVote,
};
use validator::{
    SlotDecision, SlotDecisionTip, SlotOutcome, ValidatorKey, ValidatorRecord, ValidatorSet,
    ValidatorSignature,
};

struct Fixture {
    root: PathBuf,
    bootstrap: SlotAgreementBootstrap,
    decision: SlotDecision,
    keys: Vec<Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "karsa-agreement-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut keys = Vec::new();
        let validators = (0..4u8)
            .map(|i| {
                let seed = [i + 1; 32];
                let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                keys.push([seed.as_slice(), public.as_slice()].concat());
                ValidatorRecord {
                    validator_id: vec![i],
                    keys: vec![ValidatorKey {
                        key_id: vec![i],
                        algorithm_id: ALG_ED25519,
                        public_key: public.to_vec(),
                        activation_epoch: 0,
                        retirement_epoch: u64::MAX,
                    }],
                }
            })
            .collect();
        let set = ValidatorSet {
            epoch: 2,
            validators,
        };
        let decision = SlotDecision {
            chain_id: b"agreement-store".to_vec(),
            validator_set_id: set.id().unwrap(),
            epoch: 2,
            round: 7,
            previous: [1; 32],
            before_len: 3,
            before_root: [2; 32],
            after_len: 3,
            after_root: [2; 32],
            outcome: SlotOutcome::Skip {
                leader_author: vec![0],
            },
        };
        let context = SlotDecisionTip::from_checkpoint(
            decision.chain_id.clone(),
            &set,
            7,
            decision.previous,
            3,
            decision.before_root,
        )
        .unwrap();
        Self {
            root,
            bootstrap: SlotAgreementBootstrap {
                context,
                set,
                local_validator: vec![0],
            },
            decision,
            keys,
        }
    }
    fn proposal(&self) -> AgreementInput {
        AgreementInput::Propose {
            view: AgreementView(0),
            decision: self.decision.clone(),
            pol: None,
        }
    }
    fn qc(&self, phase: AgreementPhase) -> AgreementInput {
        let vote = AgreementVote {
            context: self.bootstrap.context.clone(),
            view: AgreementView(0),
            phase,
            value: AgreementValue::Decision(self.decision.clone()),
        };
        let payload = vote.signing_payload(&self.bootstrap.set).unwrap();
        let signatures = (0..3u8)
            .map(|i| ValidatorSignature {
                validator_id: vec![i],
                key_id: vec![i],
                signature: Ed25519Scheme
                    .sign(&self.keys[usize::from(i)], &payload)
                    .unwrap(),
            })
            .collect();
        AgreementInput::Evidence {
            qc: AgreementQc { vote, signatures },
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn agreement_event_validation_rejection_retry_and_decision_checks() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut owner = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let path = f.root.join(slot_agreement_journal::FILE);
    let before = fs::read(&path).unwrap();
    let mut seen = Vec::new();
    assert!(
        owner
            .apply_validated(
                1,
                f.proposal(),
                |input| {
                    seen.push(input.clone());
                    reject(&f.decision)
                },
                |_| Ok(())
            )
            .is_err()
    );
    assert_eq!(seen, vec![f.proposal()]);
    assert_eq!(owner.sequence(), 0);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(
        owner
            .apply_validated(1, f.proposal(), |_| Ok(()), reject)
            .is_err()
    );
    assert_eq!(owner.sequence(), 0);
    assert_eq!(fs::read(&path).unwrap(), before);
    let result = owner
        .apply_validated(1, f.proposal(), |_| Ok(()), |_| Ok(()))
        .unwrap();
    let persisted = fs::read(&path).unwrap();
    let mut calls = 0;
    assert!(
        owner
            .apply_validated(
                1,
                f.proposal(),
                |input| {
                    calls += 1;
                    assert_eq!(input, &f.proposal());
                    reject(&f.decision)
                },
                |_| Ok(())
            )
            .is_err()
    );
    assert_eq!(calls, 1);
    assert_eq!(owner.sequence(), 1);
    assert_eq!(fs::read(&path).unwrap(), persisted);
    assert_eq!(
        owner
            .apply_validated(1, f.proposal(), |_| Ok(()), |_| Ok(()))
            .unwrap(),
        result
    );
}

#[test]
fn agreement_event_recovery_checks_history_and_exact_qc() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut owner = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let inputs = vec![
        f.proposal(),
        f.qc(AgreementPhase::Prevote),
        f.qc(AgreementPhase::Precommit),
    ];
    for (index, input) in inputs.iter().enumerate() {
        owner
            .apply_validated(
                index as u64 + 1,
                input.clone(),
                |actual| {
                    assert_eq!(actual, input);
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap();
    }
    let before = fs::read(f.root.join(slot_agreement_journal::FILE)).unwrap();
    let mut seen = Vec::new();
    assert!(
        store
            .recover_slot_agreement_validated(
                f.bootstrap.clone(),
                |input| {
                    seen.push(input.clone());
                    if input == &inputs[1] {
                        reject(&f.decision)
                    } else {
                        Ok(())
                    }
                },
                |_| Ok(())
            )
            .is_err()
    );
    assert_eq!(seen, inputs[..2]);
    assert_eq!(owner.sequence(), 3);
    assert_eq!(
        fs::read(f.root.join(slot_agreement_journal::FILE)).unwrap(),
        before
    );
    let mut seen = Vec::new();
    let recovered = store
        .recover_slot_agreement_validated(
            f.bootstrap.clone(),
            |input| {
                seen.push(input.clone());
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(seen, inputs);
    assert_eq!(recovered.sequence(), 3);
    assert!(
        store
            .recover_slot_agreement_validated(f.bootstrap.clone(), |_| Ok(()), reject)
            .is_err()
    );
}

#[test]
fn agreement_event_validation_includes_timeout_view_and_pol() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut owner = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let event = timeout();
    assert!(
        owner
            .apply_validated(
                1,
                event.clone(),
                |actual| {
                    assert_eq!(actual, &event);
                    reject(&f.decision)
                },
                |_| panic!("timeout has no decision")
            )
            .is_err()
    );
    assert_eq!(owner.sequence(), 0);
    owner
        .apply_validated(
            1,
            event.clone(),
            |_| Ok(()),
            |_| panic!("timeout has no decision"),
        )
        .unwrap();
    let AgreementInput::Evidence { qc } = f.qc(AgreementPhase::Prevote) else {
        unreachable!()
    };
    let proposal = AgreementInput::Propose {
        view: AgreementView(1),
        decision: f.decision.clone(),
        pol: Some(qc),
    };
    assert!(
        owner
            .apply_validated(
                2,
                proposal.clone(),
                |actual| {
                    assert_eq!(actual, &proposal);
                    reject(&f.decision)
                },
                |_| Ok(())
            )
            .is_err()
    );
    assert_eq!(owner.sequence(), 1);
    let mut seen = Vec::new();
    store
        .recover_slot_agreement_validated(
            f.bootstrap.clone(),
            |actual| {
                seen.push(actual.clone());
                Ok(())
            },
            |_| panic!("timeout has no decision"),
        )
        .unwrap();
    assert_eq!(seen, vec![event]);
}

fn timeout() -> AgreementInput {
    AgreementInput::Timeout {
        view: AgreementView(0),
        phase: AgreementPhase::Prevote,
    }
}
fn failure() -> StoreError {
    std::io::Error::other("injected durability failure").into()
}
fn reject(_: &SlotDecision) -> Result<(), CryptoError> {
    Err(CryptoError::new(
        crypto::CryptoErrorKind::MalformedCertificate,
        "oracle rejected",
    ))
}

#[test]
fn agreement_relative_root_survives_cwd_change_subprocess() {
    const CHILD_ROOT: &str = "KARSA_STORE_CWD_REGRESSION_ROOT";
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        let f = Fixture::new();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "slot_agreement_tests::agreement_relative_root_survives_cwd_change_subprocess",
                "--nocapture",
            ])
            .env(CHILD_ROOT, &f.root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cwd regression subprocess failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    };
    // Only this isolated child changes cwd; the shared parent test runner never does.
    let root = PathBuf::from(root);
    let f = Fixture::new();
    let a = root.join("A");
    let b = root.join("B");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    std::env::set_current_dir(&a).unwrap();
    let store_a = Store::open("store").unwrap();
    let mut session_a = store_a.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    std::env::set_current_dir(&b).unwrap();
    let store_b = Store::open("store").unwrap();
    let session_b = store_b.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let wal_a = a.join("store").join(slot_agreement_journal::FILE);
    let wal_b = b.join("store").join(slot_agreement_journal::FILE);
    let before = fs::read(&wal_a).unwrap();
    assert_eq!(before, fs::read(&wal_b).unwrap(), "WAL prefixes must match");
    assert!(
        Store::open(b.join("store")).is_err(),
        "B must hold its independent OS lock"
    );
    session_a.apply(1, timeout(), |_| Ok(())).unwrap();
    assert_ne!(
        fs::read(&wal_a).unwrap(),
        before,
        "A's owner must append to A despite cwd B"
    );
    assert_eq!(
        fs::read(&wal_b).unwrap(),
        before,
        "A's owner must not bypass B's OS lock"
    );
    assert_eq!(store_a.path(), fs::canonicalize(a.join("store")).unwrap());
    drop((session_a, store_a));
    let reopened_a = Store::open(a.join("store")).unwrap();
    assert_eq!(
        reopened_a
            .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
            .unwrap()
            .sequence(),
        1
    );
    drop((session_b, store_b));
    let reopened_b = Store::open(b.join("store")).unwrap();
    assert_eq!(
        reopened_b
            .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
            .unwrap()
            .sequence(),
        0
    );
    std::env::set_current_dir(root).unwrap();
}

#[test]
fn agreement_retry_recovery_stale_and_phase_conflict() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let mut stale = store
        .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
        .unwrap();
    let result = session.apply(1, f.proposal(), |_| Ok(())).unwrap();
    let mut barriers = 0;
    let retry = session
        .apply_with_barrier(
            1,
            f.proposal(),
            |_| panic!("retry uses stored result"),
            |file, _| {
                barriers += 1;
                file.sync_all()?;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(retry, result);
    assert_eq!(barriers, 1);
    assert!(session.apply(1, timeout(), |_| Ok(())).is_err());
    assert!(stale.apply(1, timeout(), |_| Ok(())).is_err());
    drop((stale, session, store));
    let store = Store::open(&f.root).unwrap();
    let mut calls = 0;
    let mut session = store
        .recover_slot_agreement(f.bootstrap.clone(), |_| {
            calls += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(session.sequence(), 1);
    assert_eq!(session.apply(1, f.proposal(), |_| Ok(())).unwrap(), result);
    assert!(session.apply(2, timeout(), |_| Ok(())).is_err());
}

#[test]
fn agreement_uncertain_complete_record_blocks_owner_and_resumes() {
    for stage in 0..3 {
        let f = Fixture::new();
        let store = Store::open(&f.root).unwrap();
        let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
        assert!(
            session
                .apply_with_barrier(
                    1,
                    f.proposal(),
                    |_| Ok(()),
                    |file, root| {
                        if stage == 0 {
                            return Err(failure());
                        }
                        file.sync_all()?;
                        if stage == 1 {
                            return Err(failure());
                        }
                        slot_decision_journal::sync_ancestors(root, |_| {
                            Err(std::io::Error::other("injected ancestor failure"))
                        })?;
                        Ok(())
                    }
                )
                .is_err()
        );
        assert_eq!(session.sequence(), 0);
        assert!(session.apply(1, f.proposal(), |_| Ok(())).is_err());
        assert!(store.begin_slot_agreement(f.bootstrap.clone()).is_err());
        assert!(
            store
                .recover_slot_agreement(f.bootstrap.clone(), reject)
                .is_err()
        );
        let mut barriers = 0;
        let mut recovered = store
            .recover_slot_agreement_with_barrier(
                f.bootstrap.clone(),
                |_| Ok(()),
                |file, root| {
                    barriers += 1;
                    file.sync_all()?;
                    slot_decision_journal::sync_ancestors(root, |p| File::open(p)?.sync_all())?;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(barriers, 2);
        assert_eq!(recovered.sequence(), 1);
        recovered
            .apply(2, f.qc(AgreementPhase::Prevote), |_| Ok(()))
            .unwrap();
    }
}

#[test]
fn agreement_qc_replay_atomic_lock_precommit_and_semantic_validation() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    session.apply(1, f.proposal(), |_| Ok(())).unwrap();
    let lock = session
        .apply(2, f.qc(AgreementPhase::Prevote), |_| Ok(()))
        .unwrap();
    assert_eq!(lock.vote.as_ref().unwrap().phase, AgreementPhase::Precommit);
    drop(session);
    assert!(
        store
            .recover_slot_agreement(f.bootstrap.clone(), reject)
            .is_err()
    );
    let mut session = store
        .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
        .unwrap();
    assert_eq!(
        session
            .apply(2, f.qc(AgreementPhase::Prevote), |_| Ok(()))
            .unwrap(),
        lock
    );
    assert!(
        session
            .apply(
                3,
                AgreementInput::Timeout {
                    view: AgreementView(0),
                    phase: AgreementPhase::Precommit
                },
                |_| Ok(())
            )
            .is_err()
    );
    let result = session
        .apply(3, f.qc(AgreementPhase::Precommit), |_| Ok(()))
        .unwrap();
    assert_eq!(result.decision, Some(f.decision.clone()));
    drop(session);
    let mut session = store
        .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
        .unwrap();
    assert_eq!(
        session
            .apply(3, f.qc(AgreementPhase::Precommit), |_| Ok(()))
            .unwrap(),
        result
    );
}

#[test]
fn agreement_bootstrap_identity_and_set_are_exact() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let _session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let mut other = f.bootstrap.clone();
    other.local_validator = vec![1];
    assert!(store.recover_slot_agreement(other, |_| Ok(())).is_err());
    let mut other = f.bootstrap.clone();
    other.context = SlotDecisionTip::from_checkpoint(
        f.decision.chain_id.clone(),
        &other.set,
        7,
        [9; 32],
        3,
        [2; 32],
    )
    .unwrap();
    assert!(store.recover_slot_agreement(other, |_| Ok(())).is_err());
    let mut other = f.bootstrap.clone();
    other.set.validators[0].keys[0].key_id = b"changed".to_vec();
    assert!(store.recover_slot_agreement(other, |_| Ok(())).is_err());
}

#[test]
fn agreement_legacy_exclusion_both_directions_ignores_context_and_identity() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    store.lock_slot_decision(&f.decision).unwrap();
    assert!(store.begin_slot_agreement(f.bootstrap.clone()).is_err());
    drop(store);
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let _session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let mut decision = f.decision.clone();
    decision.epoch += 1;
    decision.previous = [8; 32];
    decision.validator_set_id = [9; 32];
    assert!(store.lock_slot_decision(&decision).is_err());
    decision.round += 1;
    store.lock_slot_decision(&decision).unwrap();
}

#[test]
fn agreement_open_rejects_all_torn_boundaries_and_corruption() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let path = f.root.join(slot_agreement_journal::FILE);
    let header_len = fs::metadata(&path).unwrap().len() as usize;
    session.apply(1, timeout(), |_| Ok(())).unwrap();
    drop((session, store));
    let bytes = fs::read(&path).unwrap();
    for end in (0..header_len).chain(header_len + 1..bytes.len()) {
        fs::write(&path, &bytes[..end]).unwrap();
        assert!(Store::open(&f.root).is_err(), "accepted torn WAL at {end}");
    }
    for offset in [
        0,
        4,
        header_len - 1,
        header_len,
        header_len + 4,
        bytes.len() - 1,
    ] {
        let mut bad = bytes.clone();
        bad[offset] ^= 0x80;
        fs::write(&path, bad).unwrap();
        assert!(
            Store::open(&f.root).is_err(),
            "accepted corruption at {offset}"
        );
    }
    fs::write(&path, &bytes).unwrap();
    assert!(Store::open(&f.root).is_ok());
}

#[test]
fn agreement_injected_short_append_fails_closed_and_zero_append_can_resume() {
    for prefix in [0, 2, 6, usize::MAX] {
        let f = Fixture::new();
        let store = Store::open(&f.root).unwrap();
        let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
        assert!(
            session
                .apply_with_io(
                    1,
                    timeout(),
                    |_| Ok(()),
                    |file, bytes| {
                        file.write_all(&bytes[..prefix.min(bytes.len())])?;
                        Err(failure())
                    },
                    |_, _| panic!("failed append must not reach sync")
                )
                .is_err()
        );
        assert_eq!(session.sequence(), 0);
        assert!(session.apply(1, timeout(), |_| Ok(())).is_err());
        let recovery = store.recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()));
        if prefix == 0 || prefix == usize::MAX {
            let mut recovered = recovery.unwrap();
            assert_eq!(recovered.sequence(), u64::from(prefix != 0));
            recovered.apply(1, timeout(), |_| Ok(())).unwrap();
        } else {
            assert!(recovery.is_err());
            assert!(store.lock_slot_decision(&f.decision).is_err());
            drop((session, store));
            assert!(Store::open(&f.root).is_err());
        }
    }
}

#[test]
fn agreement_uncertain_creation_and_recovery_barriers() {
    for complete in [false, true] {
        let f = Fixture::new();
        let store = Store::open(&f.root).unwrap();
        assert!(
            store
                .begin_slot_agreement_with_io(
                    f.bootstrap.clone(),
                    |file, bytes| {
                        file.write_all(&bytes[..if complete { bytes.len() } else { 2 }])?;
                        Err(failure())
                    },
                    |_, _| panic!("failed header append must not reach sync")
                )
                .is_err()
        );
        assert!(store.begin_slot_agreement(f.bootstrap.clone()).is_err());
        if complete {
            assert!(
                store
                    .recover_slot_agreement_with_barrier(
                        f.bootstrap.clone(),
                        |_| Ok(()),
                        |_, _| Err(failure())
                    )
                    .is_err()
            );
            assert_eq!(
                store
                    .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
                    .unwrap()
                    .sequence(),
                0
            );
        } else {
            assert!(
                store
                    .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
                    .is_err()
            );
        }
    }
}

#[test]
fn agreement_generation_and_staged_views_preserve_root_session() {
    let f = Fixture::new();
    let mut store = Store::open(&f.root).unwrap();
    let mut session = {
        let stage = store.stage().unwrap();
        let session = stage
            .store()
            .begin_slot_agreement(f.bootstrap.clone())
            .unwrap();
        assert!(f.root.join(slot_agreement_journal::FILE).exists());
        assert!(
            !stage
                .store()
                .path()
                .join(slot_agreement_journal::FILE)
                .exists()
        );
        assert!(stage.store().lock_slot_decision(&f.decision).is_err());
        session
    };
    session.apply(1, timeout(), |_| Ok(())).unwrap();
    let stage = store.stage().unwrap();
    assert!(
        stage
            .store()
            .begin_slot_agreement(f.bootstrap.clone())
            .is_err()
    );
    assert!(stage.store().lock_slot_decision(&f.decision).is_err());
    stage.activate().unwrap();
    store.prune_below(100, 1).unwrap();
    drop((session, store));
    let store = Store::open(&f.root).unwrap();
    let mut session = store
        .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
        .unwrap();
    assert_eq!(session.sequence(), 1);
    session
        .apply(
            2,
            AgreementInput::AdvanceView {
                from: AgreementView(0),
            },
            |_| Ok(()),
        )
        .unwrap();
    assert!(store.lock_slot_decision(&f.decision).is_err());
}

#[test]
fn agreement_optimistic_prepare_rechecks_after_reentrant_callback() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let mut other = store
        .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
        .unwrap();
    assert!(
        session
            .apply(1, f.proposal(), |_| {
                other.apply(1, timeout(), |_| Ok(())).unwrap();
                Ok(())
            })
            .is_err()
    );
    assert_eq!(session.sequence(), 0);
    assert_eq!(
        store
            .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
            .unwrap()
            .sequence(),
        1
    );
}

// Construct correctly checksummed hostile records to distinguish structural checks
// from required semantic/signature/reducer replay checks.
fn raw_frame(previous: &[u8; 32], sequence: u64, body: &[u8]) -> Vec<u8> {
    let length = (body.len() as u32).to_le_bytes();
    let checksum = crypto::merkle::leaf(
        b"KARSA/STORE/SLOT_AGREEMENT/v1",
        &[previous, &sequence.to_le_bytes(), &length, body],
    );
    [length.as_slice(), body, &checksum].concat()
}

#[test]
fn agreement_replay_rejects_validly_framed_phase_conflicts_and_bad_qc() {
    for bad_qc in [false, true] {
        let f = Fixture::new();
        let store = Store::open(&f.root).unwrap();
        let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
        session.apply(1, f.proposal(), |_| Ok(())).unwrap();
        let path = f.root.join(slot_agreement_journal::FILE);
        let bytes = fs::read(&path).unwrap();
        let tip: [u8; 32] = bytes[bytes.len() - 32..].try_into().unwrap();
        let mut input = if bad_qc {
            f.qc(AgreementPhase::Prevote)
        } else {
            timeout()
        };
        if let AgreementInput::Evidence { qc } = &mut input {
            qc.signatures[0].signature[0] ^= 1;
        }
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&raw_frame(
                &tip,
                2,
                &input.encode(&f.bootstrap.set).unwrap(),
            ))
            .unwrap();
        drop((session, store));
        let store = Store::open(&f.root).unwrap();
        assert!(
            store
                .recover_slot_agreement(f.bootstrap.clone(), |_| Ok(()))
                .is_err()
        );
    }
}

#[test]
fn agreement_tip_comparison_rejects_same_sequence_replacement() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let path = f.root.join(slot_agreement_journal::FILE);
    let header = fs::read(&path).unwrap();
    let tip: [u8; 32] = header[header.len() - 32..].try_into().unwrap();
    session.apply(1, timeout(), |_| Ok(())).unwrap();
    let different = AgreementInput::AdvanceView {
        from: AgreementView(0),
    };
    let mut replacement = header;
    replacement.extend_from_slice(&raw_frame(
        &tip,
        1,
        &different.encode(&f.bootstrap.set).unwrap(),
    ));
    fs::write(&path, replacement).unwrap();
    assert!(session.apply(1, timeout(), |_| Ok(())).is_err());
    assert!(session.apply(2, different, |_| Ok(())).is_err());
}

#[test]
fn agreement_invalid_preparation_leaves_disk_and_memory_unchanged() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let mut session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let path = f.root.join(slot_agreement_journal::FILE);
    let before = fs::read(&path).unwrap();
    assert!(session.apply(1, f.proposal(), reject).is_err());
    assert_eq!(session.sequence(), 0);
    assert_eq!(fs::read(&path).unwrap(), before);
    session.apply(1, f.proposal(), |_| Ok(())).unwrap();
}

#[test]
fn agreement_record_count_and_total_bytes_are_bounded() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    let path = f.root.join(slot_agreement_journal::FILE);
    let header = fs::read(&path).unwrap();
    drop((session, store));
    let mut bytes = header.clone();
    let mut tip: [u8; 32] = bytes[bytes.len() - 32..].try_into().unwrap();
    let body = timeout().encode(&f.bootstrap.set).unwrap();
    for sequence in 1..=4097 {
        let record = raw_frame(&tip, sequence, &body);
        tip = record[record.len() - 32..].try_into().unwrap();
        bytes.extend_from_slice(&record);
    }
    fs::write(&path, bytes).unwrap();
    assert!(Store::open(&f.root).is_err());
    fs::write(&path, header).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    assert!(Store::open(&f.root).is_err());
}

#[test]
fn agreement_open_rejects_overlapping_legacy_journals() {
    let f = Fixture::new();
    let store = Store::open(&f.root).unwrap();
    let session = store.begin_slot_agreement(f.bootstrap.clone()).unwrap();
    drop((session, store));
    let body = f.decision.encode().unwrap();
    let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&f.decision.id().unwrap());
    fs::write(f.root.join(slot_decision_journal::FILE), bytes).unwrap();
    assert!(Store::open(&f.root).is_err());
}
