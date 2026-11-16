//! Bounded local pre-sign header intents, separate from execution and finality checkpoints.

use super::*;

const INTENTS_FILE: &str = "agreement-header-intents";
const TEMPORARY_FILE: &str = "agreement-header-intents.tmp";
const INTENTS_DOMAIN: &[u8] = b"KARSA/STORE/AGREEMENT_HEADER_INTENTS/v1";
// Full replacement is deliberately bounded; no pruning or unbounded live use is supported.
const MAX_INTENT_BYTES: u64 = 16 * 1024 * 1024;

/// Immutable local authorization to sign one exact executed application header.
/// This is not an execution proof, completed signature, certificate or recovery checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementHeaderIntent {
    application: usize,
    order_len: usize,
    header: Header,
}

impl AgreementHeaderIntent {
    /// Zero-based replay-derived application index, including skipped decisions.
    pub fn application(&self) -> usize {
        self.application
    }

    /// Exact certified prefix covered by this header.
    pub fn order_len(&self) -> usize {
        self.order_len
    }

    /// Exact header reserved before signing.
    pub fn header(&self) -> &Header {
        &self.header
    }
}

pub(super) struct Journal {
    bootstrap: Vec<u8>,
    pub(super) anchor: Header,
    pub(super) intents: Vec<AgreementHeaderIntent>,
}

impl Journal {
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if self.intents.len() > MAX_EVENTS {
            return Err(invalid("header intent count exceeds bound"));
        }
        let mut e = Encoder::new();
        e.put_bytes(INTENTS_DOMAIN)?;
        e.put_bytes(&self.bootstrap)?;
        e.put_bytes(&self.anchor.encode()?)?;
        e.put_u32(self.intents.len() as u32);
        for intent in &self.intents {
            e.put_u64(intent.application as u64);
            e.put_u64(intent.order_len as u64);
            e.put_bytes(&intent.header.encode()?)?;
        }
        let checksum = digest(&[0; 32], 0, e.as_slice());
        e.put_raw(&checksum);
        if e.as_slice().len() as u64 > MAX_INTENT_BYTES {
            return Err(invalid("header intents exceed byte bound"));
        }
        Ok(e.finish())
    }

    pub(super) fn validate(
        &self,
        bootstrap: &[u8],
        snapshot: &AgreementOrderingSnapshot,
    ) -> Result<(), StoreError> {
        let tip = snapshot.checkpoint_binding().tip();
        if self.bootstrap != bootstrap
            || tip.next_round() != 1
            || tip.order_len() != 0
            || self.anchor.height != 0
            || self.anchor.round != 0
            || self.anchor.applied != 0
            || self.anchor.previous != [0; 32]
            || self.anchor.chain_id != tip.chain_id()
            || self.anchor.epoch != tip.epoch()
            || &self.anchor.dag_root != tip.order_root()
        {
            return Err(invalid("header intent genesis or bootstrap mismatch"));
        }
        let mut commits = snapshot
            .applications()
            .iter()
            .enumerate()
            .filter(|(_, application)| application.is_commit());
        let mut previous = &self.anchor;
        for intent in &self.intents {
            let Some((index, boundary)) = commits.next() else {
                return Err(invalid("header intent has no applied certified commit"));
            };
            let header = &intent.header;
            if intent.application != index
                || intent.order_len != boundary.order_len()
                || header.round != boundary.round()
                || header.height
                    != previous
                        .height
                        .checked_add(1)
                        .ok_or_else(|| invalid("header height overflow"))?
                || header.chain_id != self.anchor.chain_id
                || header.epoch != self.anchor.epoch
                || header.previous != previous.id()?
                || header.applied < previous.applied
                || header.dag_root != validator::commit_root(&snapshot.order()[..intent.order_len])
            {
                return Err(invalid(
                    "header intent differs from certified application history",
                ));
            }
            previous = header;
        }
        Ok(())
    }
}

pub(super) fn read_intents(root: &Path) -> Result<Option<Journal>, StoreError> {
    let path = root.join(INTENTS_FILE);
    validate_pointer_file(&path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_INTENT_BYTES {
        return Err(invalid("header intents exceed byte bound"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INTENT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() < 32 || bytes.len() as u64 > MAX_INTENT_BYTES {
        return Err(invalid("invalid header intent journal size"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if checksum != digest(&[0; 32], 0, body) {
        return Err(invalid("header intent checksum mismatch"));
    }
    let mut d = Decoder::new(body);
    if d.read_bytes()? != INTENTS_DOMAIN {
        return Err(invalid("unknown header intent version"));
    }
    let bootstrap = d.read_bytes()?.to_vec();
    let anchor = Header::decode(d.read_bytes()?)?;
    let count = d.read_u32()? as usize;
    if count == 0 || count > MAX_EVENTS {
        return Err(invalid("invalid header intent count"));
    }
    let mut intents = Vec::with_capacity(count);
    for _ in 0..count {
        intents.push(AgreementHeaderIntent {
            application: usize::try_from(d.read_u64()?)
                .map_err(|_| invalid("application index overflow"))?,
            order_len: usize::try_from(d.read_u64()?)
                .map_err(|_| invalid("order length overflow"))?,
            header: Header::decode(d.read_bytes()?)?,
        });
    }
    d.finish()?;
    Ok(Some(Journal {
        bootstrap,
        anchor,
        intents,
    }))
}

impl AuthenticatedSlotAgreement {
    /// Loads immutable header reservations after checking owner and durable applications.
    /// Missing records return an empty list; corruption is never ignored or repaired.
    /// # Errors
    /// Rejects stale/uncertain owners, corrupt records and incompatible agreement histories.
    pub fn header_intents(&self) -> Result<Vec<AgreementHeaderIntent>, StoreError> {
        let snapshot = self.ordering_snapshot()?;
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        self.check_checkpoint_owner(&root)?;
        let Some(journal) = read_intents(&root)? else {
            return Ok(Vec::new());
        };
        journal.validate(&self.header, &snapshot)?;
        Ok(journal.intents)
    }

    /// Durably reserves an exact header before signing, starting at a caller-trusted genesis.
    /// Every commit needs one contiguous height, including commits with unchanged order length.
    /// The store checks history, linkage and immutable intent, not state-root correctness.
    /// Identical historical reservations retain the same intent but repeat durability barriers;
    /// conflicting bytes are never overwritten.
    /// Success syncs the file and ancestors. Publication failure makes this owner uncertain.
    /// This root-level file is not prunable and does not recover finalizer or execution state.
    /// # Errors
    /// Rejects incompatible genesis, missing commits, skipped heights, conflicts, corruption,
    /// stale ownership, bounded-storage exhaustion and publication failures.
    pub fn reserve_header(
        &mut self,
        anchor: &Header,
        header: &Header,
        order_len: usize,
    ) -> Result<(), StoreError> {
        self.reserve_header_with_io(anchor, header, order_len, publish)
    }

    fn reserve_header_with_io(
        &mut self,
        anchor: &Header,
        header: &Header,
        order_len: usize,
        publish: impl FnOnce(&Path, &[u8]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let snapshot = self.ordering_snapshot()?;
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        self.check_checkpoint_owner(&root)?;
        let mut journal = read_intents(&root)?.unwrap_or_else(|| Journal {
            bootstrap: self.header.clone(),
            anchor: anchor.clone(),
            intents: Vec::new(),
        });
        journal.validate(&self.header, &snapshot)?;
        if &journal.anchor != anchor {
            return Err(invalid("header intent genesis anchor changed"));
        }
        let height =
            usize::try_from(header.height).map_err(|_| invalid("header height overflow"))?;
        let index = height
            .checked_sub(1)
            .ok_or_else(|| invalid("cannot reserve genesis"))?;
        if let Some(old) = journal.intents.get(index) {
            if &old.header != header || old.order_len != order_len {
                return Err(invalid("header intent conflicts at reserved height"));
            }
            // Another handle may have renamed this visible record without completing
            // its directory barrier. Even an identical intent must be durable before signing.
        } else {
            if index != journal.intents.len() || index >= MAX_EVENTS {
                return Err(invalid(
                    "header intent height is not the next bounded height",
                ));
            }
            let application = snapshot
                .applications()
                .iter()
                .enumerate()
                .filter(|(_, boundary)| boundary.is_commit())
                .nth(index)
                .map(|(index, _)| index)
                .ok_or_else(|| invalid("header has no applied certified commit"))?;
            journal.intents.push(AgreementHeaderIntent {
                application,
                order_len,
                header: header.clone(),
            });
        }
        journal.validate(&self.header, &snapshot)?;
        let bytes = journal.encode()?;
        validate_pointer_file(&root.join(TEMPORARY_FILE))?;
        let result = publish(&root, &bytes);
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
}

fn publish(root: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let temporary = root.join(TEMPORARY_FILE);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, root.join(INTENTS_FILE))?;
    slot_decision_journal::sync_ancestors(root, |path| File::open(path)?.sync_all())?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::slot_application_tests::TempDir;

    pub(in crate::authenticated_slot_agreement) fn fixture(
        dir: &TempDir,
        commit: bool,
    ) -> (
        Store,
        AuthenticatedSlotAgreement,
        AuthenticatedSlotAgreementBootstrap,
        Header,
        Header,
    ) {
        let (f, proof, carrier) = crate::slot_application_tests::unified_fixture(commit);
        let bootstrap = AuthenticatedSlotAgreementBootstrap {
            agreement: SlotAgreementBootstrap {
                context: f.binding.tip().clone(),
                set: f.set.clone(),
                local_validator: f.set.validators[0].validator_id.clone(),
            },
            predecessor: None,
            order: vec![],
            vertices: vec![],
        };
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let anchor = Header::genesis(
            bootstrap.agreement.context.chain_id().to_vec(),
            bootstrap.agreement.context.epoch(),
            [0; 32],
            *bootstrap.agreement.context.order_root(),
        );
        owner
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::ObservePrecommit {
                    proof,
                    carrier,
                    vertices: f.vertices,
                },
            )
            .unwrap();
        // A decided but unadvanced slot is not authority to reserve a header.
        let prospective = Header {
            chain_id: anchor.chain_id.clone(),
            epoch: anchor.epoch,
            height: 1,
            round: 1,
            state_root: [7; 32],
            dag_root: validator::commit_root(&[]),
            previous: anchor.id().unwrap(),
            applied: 0,
        };
        assert!(owner.reserve_header(&anchor, &prospective, 0).is_err());
        owner.advance_slot(2).unwrap();
        let snapshot = owner.ordering_snapshot().unwrap();
        let boundary = &snapshot.applications()[0];
        let header = Header {
            round: boundary.round(),
            dag_root: validator::commit_root(snapshot.order()),
            ..prospective
        };
        (store, owner, bootstrap, anchor, header)
    }

    #[test]
    fn durable_intent_rejects_conflicts_corruption_and_wrong_boundaries() {
        let dir = TempDir::new();
        let (store, mut owner, bootstrap, anchor, header) = fixture(&dir, true);
        let coverage = owner.ordering_snapshot().unwrap().order().len();
        assert!(owner.header_intents().unwrap().is_empty());
        assert!(
            owner
                .reserve_header(&anchor, &header, coverage - 1)
                .is_err()
        );
        let mut invalid_header = header.clone();
        invalid_header.previous[0] ^= 1;
        assert!(
            owner
                .reserve_header(&anchor, &invalid_header, coverage)
                .is_err()
        );
        invalid_header = header.clone();
        invalid_header.height = 2;
        assert!(
            owner
                .reserve_header(&anchor, &invalid_header, coverage)
                .is_err()
        );
        owner.reserve_header(&anchor, &header, coverage).unwrap();
        let path = dir.0.join(INTENTS_FILE);
        let bytes = fs::read(&path).unwrap();
        let intents = owner.header_intents().unwrap();
        owner.reserve_header(&anchor, &header, coverage).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let mut changed_anchor = anchor.clone();
        changed_anchor.state_root[0] ^= 1;
        assert!(
            owner
                .reserve_header(&changed_anchor, &header, coverage)
                .is_err()
        );
        let mut conflicting = header.clone();
        conflicting.state_root[0] ^= 1;
        assert!(
            owner
                .reserve_header(&anchor, &conflicting, coverage)
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(owner);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(owner.header_intents().unwrap(), intents);
        assert!(
            owner
                .reserve_header(&anchor, &conflicting, coverage)
                .is_err()
        );
        // A complete but truncated committed file must not be silently recreated.
        fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(owner.header_intents().is_err());
        assert!(owner.reserve_header(&anchor, &header, coverage).is_err());
        assert_eq!(fs::read(&path).unwrap(), &bytes[..bytes.len() - 1]);
    }

    #[test]
    fn skipped_application_cannot_allocate_a_header_intent() {
        let dir = TempDir::new();
        let (_store, mut owner, _, anchor, header) = fixture(&dir, false);
        assert!(owner.reserve_header(&anchor, &header, 0).is_err());
        assert!(owner.header_intents().unwrap().is_empty());
        assert!(!dir.0.join(INTENTS_FILE).exists());
    }

    #[test]
    fn publication_failure_before_or_after_rename_requires_recovery() {
        for renamed in [false, true] {
            let dir = TempDir::new();
            let (store, mut owner, bootstrap, anchor, header) = fixture(&dir, true);
            let coverage = owner.ordering_snapshot().unwrap().order().len();
            assert!(
                owner
                    .reserve_header_with_io(&anchor, &header, coverage, |root, bytes| {
                        if renamed {
                            fs::write(root.join(TEMPORARY_FILE), bytes)?;
                            File::open(root.join(TEMPORARY_FILE))?.sync_all()?;
                            fs::rename(root.join(TEMPORARY_FILE), root.join(INTENTS_FILE))?;
                        } else {
                            fs::write(root.join(TEMPORARY_FILE), &bytes[..bytes.len() / 2])?;
                        }
                        Err(std::io::Error::other("injected publication failure").into())
                    })
                    .is_err()
            );
            assert!(owner.header_intents().is_err());
            assert!(owner.ordering_snapshot().is_err());
            assert!(owner.reserve_header(&anchor, &header, coverage).is_err());
            drop(owner);
            drop(store);
            let store = Store::open(&dir.0).unwrap();
            let mut owner = store
                .recover_authenticated_slot_agreement(bootstrap)
                .unwrap();
            assert_eq!(owner.header_intents().unwrap().len(), usize::from(renamed));
            owner.reserve_header(&anchor, &header, coverage).unwrap();
            assert_eq!(owner.header_intents().unwrap()[0].header(), &header);
        }
    }

    #[test]
    fn sibling_owner_cannot_bypass_barriers_for_visible_uncertain_intent() {
        let dir = TempDir::new();
        let (store, mut owner, bootstrap, anchor, header) = fixture(&dir, true);
        let coverage = owner.ordering_snapshot().unwrap().order().len();
        let mut sibling = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert!(
            owner
                .reserve_header_with_io(&anchor, &header, coverage, |root, bytes| {
                    fs::write(root.join(TEMPORARY_FILE), bytes)?;
                    File::open(root.join(TEMPORARY_FILE))?.sync_all()?;
                    fs::rename(root.join(TEMPORARY_FILE), root.join(INTENTS_FILE))?;
                    Err(std::io::Error::other("directory sync failed after rename").into())
                })
                .is_err()
        );
        // The sibling predates the failed publication; its WAL freshness is unchanged.
        assert_eq!(sibling.header_intents().unwrap().len(), 1);
        let mut barrier_called = false;
        assert!(
            sibling
                .reserve_header_with_io(&anchor, &header, coverage, |_, _| {
                    barrier_called = true;
                    Err(std::io::Error::other("replacement barrier unavailable").into())
                })
                .is_err()
        );
        assert!(
            barrier_called,
            "identical intent still requires a durability barrier"
        );
        assert!(sibling.header_intents().is_err());
    }

    #[test]
    fn root_intents_survive_generation_activation_and_reject_foreign_history() {
        let dir = TempDir::new();
        let (mut store, mut owner, bootstrap, anchor, header) = fixture(&dir, true);
        let coverage = owner.ordering_snapshot().unwrap().order().len();
        owner.reserve_header(&anchor, &header, coverage).unwrap();
        let staged = store.stage().unwrap();
        assert!(!staged.store().root.join(INTENTS_FILE).exists());
        staged.activate().unwrap();
        let intents = owner.header_intents().unwrap();
        drop(owner);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        assert_eq!(owner.header_intents().unwrap(), intents);
        let foreign_dir = TempDir::new();
        let (_foreign_store, foreign, _, _, _) = fixture(&foreign_dir, false);
        fs::copy(dir.0.join(INTENTS_FILE), foreign_dir.0.join(INTENTS_FILE)).unwrap();
        assert!(foreign.header_intents().is_err());
        // A different current owner that extends the WAL invalidates this handle.
        let mut newer = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        newer
            .apply(
                newer.sequence() + 1,
                AuthenticatedSlotAgreementRequest::ReserveViewRequest {
                    target_view: validator::slot_agreement::AgreementView(1),
                },
            )
            .unwrap();
        assert!(owner.header_intents().is_err());
        assert!(owner.reserve_header(&anchor, &header, coverage).is_err());
    }
}
