//! Local execution checkpoints paired with a complete consumed certified prefix.

use super::*;

pub(super) const CHECKPOINT_FILE: &str = "agreement-execution-checkpoint";
const CHECKPOINT_DOMAIN: &[u8] = b"KARSA/STORE/AGREEMENT_EXECUTION/v1";
const MAX_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024;

/// Local execution bytes and cursor published together, not a finality certificate.
/// State is opaque to the store: callers must validate its encoding and semantics.
/// This record neither authorizes pruning nor authenticates a peer checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementExecutionCheckpoint {
    header: Vec<u8>,
    order: Vec<VertexId>,
    applied: u64,
    state: Vec<u8>,
}

impl AgreementExecutionCheckpoint {
    /// Exact consumed certified prefix associated with the encoded execution state.
    pub fn order(&self) -> &[VertexId] {
        &self.order
    }
    /// Number of transactions applied in the associated execution state.
    pub fn applied(&self) -> u64 {
        self.applied
    }
    /// Caller-encoded execution state, stored atomically with the consumed prefix.
    pub fn state(&self) -> &[u8] {
        &self.state
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if self.order.len() > MAX_VERTICES || self.state.len() > MAX_BODY {
            return Err(invalid("execution checkpoint exceeds bounds"));
        }
        let mut e = Encoder::new();
        e.put_bytes(CHECKPOINT_DOMAIN)?;
        e.put_bytes(&self.header)?;
        e.put_u32(self.order.len() as u32);
        for id in &self.order {
            put_id(&mut e, id)?;
        }
        e.put_u64(self.applied);
        e.put_bytes(&self.state)?;
        let checksum = digest(&[0; 32], 0, e.as_slice());
        e.put_raw(&checksum);
        if e.as_slice().len() as u64 > MAX_CHECKPOINT_BYTES {
            return Err(invalid("execution checkpoint exceeds byte bound"));
        }
        Ok(e.finish())
    }
}

fn read_checkpoint(root: &Path) -> Result<Option<AgreementExecutionCheckpoint>, StoreError> {
    let path = root.join(CHECKPOINT_FILE);
    validate_pointer_file(&path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_CHECKPOINT_BYTES {
        return Err(invalid("execution checkpoint exceeds byte bound"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CHECKPOINT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES || bytes.len() < 32 {
        return Err(invalid("invalid execution checkpoint size"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if checksum != digest(&[0; 32], 0, body) {
        return Err(invalid("execution checkpoint checksum mismatch"));
    }
    let mut d = Decoder::new(body);
    if d.read_bytes()? != CHECKPOINT_DOMAIN {
        return Err(invalid("unknown execution checkpoint version"));
    }
    let header = d.read_bytes()?.to_vec();
    let count = d.read_u32()? as usize;
    if count > MAX_VERTICES {
        return Err(invalid("execution checkpoint order exceeds bound"));
    }
    let mut order = Vec::with_capacity(count);
    for _ in 0..count {
        order.push(get_id(&mut d)?);
    }
    let applied = d.read_u64()?;
    let state = d.read_bytes()?.to_vec();
    d.finish()?;
    if state.len() > MAX_BODY {
        return Err(invalid("execution checkpoint state exceeds bound"));
    }
    Ok(Some(AgreementExecutionCheckpoint {
        header,
        order,
        applied,
        state,
    }))
}

impl AuthenticatedSlotAgreement {
    /// Loads a local state/cursor pair only after checking current owner and certified prefix.
    /// Missing records return `None`; corrupt or incompatible records are never ignored.
    /// # Errors
    /// Rejects uncertain/stale ownership, invalid WAL, corrupt checkpoints and foreign prefixes.
    pub fn execution_checkpoint(&self) -> Result<Option<AgreementExecutionCheckpoint>, StoreError> {
        let snapshot = self.ordering_snapshot()?;
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        self.check_checkpoint_owner(&root)?;
        let checkpoint = read_checkpoint(&root)?;
        if let Some(checkpoint) = &checkpoint {
            if checkpoint.header != self.header || !snapshot.order().starts_with(&checkpoint.order)
            {
                return Err(invalid(
                    "execution checkpoint does not match certified history",
                ));
            }
        }
        Ok(checkpoint)
    }

    pub(super) fn check_checkpoint_owner(&self, root: &Path) -> Result<(), StoreError> {
        exclusions(root)?;
        let journal = read(root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if self.uncertain
            || journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale or uncertain execution checkpoint owner"));
        }
        Ok(())
    }

    /// Atomically replaces a local execution state and its consumed certified prefix.
    /// The caller must supply state produced by exactly this prefix. The store checks
    /// association and monotonicity, not execution correctness. State is limited to 2 MiB.
    /// Repeating the exact record is a no-op; rewriting state at the same cursor is rejected.
    /// File and directory are synced before success. Any publication I/O failure makes
    /// this owner uncertain; recover and reread before attempting more work.
    /// # Errors
    /// Rejects stale owners, non-certified/regressing prefixes, conflicting checkpoints,
    /// oversized state, corrupt existing records, and I/O failures.
    pub fn put_execution_checkpoint(
        &mut self,
        order: &[VertexId],
        applied: u64,
        state: &[u8],
    ) -> Result<(), StoreError> {
        self.put_execution_checkpoint_with_io(order, applied, state, publish)
    }

    fn put_execution_checkpoint_with_io(
        &mut self,
        order: &[VertexId],
        applied: u64,
        state: &[u8],
        publish: impl FnOnce(&Path, &[u8]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if order.len() > MAX_VERTICES || state.len() > MAX_BODY {
            return Err(invalid("execution checkpoint exceeds bounds"));
        }
        let snapshot = self.ordering_snapshot()?;
        if !snapshot.order().starts_with(order) {
            return Err(invalid("execution cursor is not a certified prefix"));
        }
        let checkpoint = AgreementExecutionCheckpoint {
            header: self.header.clone(),
            order: order.to_vec(),
            applied,
            state: state.to_vec(),
        };
        let bytes = checkpoint.encode()?;
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        self.check_checkpoint_owner(&root)?;
        if let Some(old) = read_checkpoint(&root)? {
            if old.header != self.header
                || !checkpoint.order.starts_with(&old.order)
                || checkpoint.applied < old.applied
            {
                return Err(invalid("execution checkpoint regressed or changed history"));
            }
            if checkpoint.order == old.order {
                return if checkpoint == old {
                    Ok(())
                } else {
                    Err(invalid("execution checkpoint conflicts at same cursor"))
                };
            }
        }
        let temporary = root.join("agreement-execution-checkpoint.tmp");
        validate_pointer_file(&temporary)?;
        let result = publish(&root, &bytes);
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
}

fn publish(root: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let temporary = root.join("agreement-execution-checkpoint.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, root.join(CHECKPOINT_FILE))?;
    slot_decision_journal::sync_ancestors(root, |p| File::open(p)?.sync_all())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_application_tests::TempDir;

    #[test]
    fn uncertain_checkpoint_publication_requires_recovery_before_or_after_rename() {
        for renamed in [false, true] {
            let (_, _, bootstrap) = crate::authenticated_slot_agreement_tests::fixture(true);
            let dir = TempDir::new();
            let store = Store::open(&dir.0).unwrap();
            let mut owner = store
                .begin_authenticated_slot_agreement(bootstrap.clone())
                .unwrap();
            assert!(
                owner
                    .put_execution_checkpoint_with_io(&[], 0, b"state", |root, bytes| {
                        if renamed {
                            publish(root, bytes)?;
                        } else {
                            fs::write(
                                root.join("agreement-execution-checkpoint.tmp"),
                                &bytes[..bytes.len() / 2],
                            )?;
                        }
                        Err(invalid("injected publication failure"))
                    })
                    .is_err()
            );
            assert!(owner.execution_checkpoint().is_err());
            assert!(owner.ordering_snapshot().is_err());
            assert!(owner.put_execution_checkpoint(&[], 0, b"state").is_err());
            drop(owner);
            drop(store);
            let store = Store::open(&dir.0).unwrap();
            let mut owner = store
                .recover_authenticated_slot_agreement(bootstrap)
                .unwrap();
            let recovered = owner.execution_checkpoint().unwrap();
            assert_eq!(recovered.is_some(), renamed);
            if let Some(checkpoint) = recovered {
                assert_eq!(checkpoint.state(), b"state");
                assert!(checkpoint.order().is_empty());
            }
            owner.put_execution_checkpoint(&[], 0, b"state").unwrap();
            assert_eq!(
                owner.execution_checkpoint().unwrap().unwrap().state(),
                b"state"
            );
        }
    }
}
