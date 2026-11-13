//! Inactive certified-DAG write-ahead requests, scoped to the active generation.
//!
//! A record means replay is required, not that volatile application finished. The
//! trusted activation checkpoint and supporting history must be preserved separately.
//! Legacy pruning/snapshot adoption is not an authenticated migration of this journal.

use super::*;
use std::collections::HashSet;
use validator::{CertifiedDag, SlotApplicationResult, SlotCertificatePayload};

const FILE: &str = "slot-applications";
const VERSION: u16 = 1;
const MAX_RECORD: usize = crypto::encoding::MAX_FIELD_LEN + 1100;

/// A replayable inactive application request, not proof that application completed.
///
/// Reading a record checks encoding and journal continuity, not QC signatures or
/// DAG semantics. Replay must use a trusted checkpoint and the certified inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSlotApplication {
    /// The proposal, its carrier, and the exact decision QC.
    pub payload: SlotCertificatePayload,
    /// The signed DAG carrier binding the entire QC payload.
    pub carrier: VertexId,
}

fn malformed(message: &str) -> StoreError {
    CryptoError::new(crypto::CryptoErrorKind::MalformedCertificate, message).into()
}

impl StoredSlotApplication {
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if self.carrier.author.len() > 1024 {
            return Err(malformed("slot application carrier author too long"));
        }
        let mut e = Encoder::new();
        e.put_u16(VERSION);
        e.put_bytes(&self.payload.encode()?)?;
        e.put_u64(self.carrier.round);
        e.put_bytes(&self.carrier.author)?;
        e.put_bytes(&self.carrier.digest)?;
        if e.len() > MAX_RECORD {
            return Err(malformed("slot application record too large"));
        }
        Ok(e.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_RECORD {
            return Err(malformed("slot application record too large"));
        }
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != VERSION {
            return Err(malformed("unsupported slot application record version"));
        }
        let payload = SlotCertificatePayload::decode(d.read_bytes()?)?;
        let round = d.read_u64()?;
        let author = d.read_bytes()?.to_vec();
        if author.len() > 1024 {
            return Err(malformed("slot application carrier author too long"));
        }
        let digest = d
            .read_bytes()?
            .try_into()
            .map_err(|_| malformed("invalid slot application carrier digest"))?;
        d.finish()?;
        Ok(Self {
            payload,
            carrier: VertexId {
                round,
                author,
                digest,
            },
        })
    }
}

fn checksum(body: &[u8]) -> [u8; 32] {
    crypto::merkle::leaf(b"KARSA/STORE/SLOT_APPLICATION/v1", &[body])
}

fn follows(
    previous: &StoredSlotApplication,
    next: &StoredSlotApplication,
) -> Result<(), StoreError> {
    let before = &previous.payload.certificate.decision;
    let after = &next.payload.certificate.decision;
    if before.round.checked_add(1) != Some(after.round)
        || before.chain_id != after.chain_id
        || before.validator_set_id != after.validator_set_id
        || before.epoch != after.epoch
        || before.id()? != after.previous
        || before.after_len != after.before_len
        || before.after_root != after.before_root
        || previous.carrier.round >= next.payload.proposal_carrier.round
    {
        return Err(malformed("slot application journal continuity mismatch"));
    }
    Ok(())
}

pub(super) fn read(root: &Path) -> Result<Vec<StoredSlotApplication>, StoreError> {
    let path = root.join(FILE);
    validate_pointer_file(&path)?;
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut records = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let header = bytes
            .get(cursor..cursor + 4)
            .ok_or_else(|| malformed("torn slot application journal length"))?;
        let len = u32::from_le_bytes(header.try_into().expect("four-byte length")) as usize;
        if len > MAX_RECORD {
            return Err(malformed("slot application journal record too large"));
        }
        cursor += 4;
        let end = cursor
            .checked_add(len)
            .ok_or_else(|| malformed("slot application journal length overflow"))?;
        let body = bytes
            .get(cursor..end)
            .ok_or_else(|| malformed("torn slot application journal body"))?;
        let checksum_end = end
            .checked_add(32)
            .ok_or_else(|| malformed("slot application journal checksum overflow"))?;
        let stored_checksum = bytes
            .get(end..checksum_end)
            .ok_or_else(|| malformed("torn slot application journal checksum"))?;
        if checksum(body).as_slice() != stored_checksum {
            return Err(malformed("corrupt slot application journal checksum"));
        }
        let record = StoredSlotApplication::decode(body)?;
        if let Some(previous) = records.last() {
            follows(previous, &record)?;
        }
        records.push(record);
        cursor = checksum_end;
    }
    Ok(records)
}

// Validate the replay inputs against the exact first-wins vertex log, including
// signatures (which are outside vertex IDs). Batches/transaction state are not
// part of this inactive order-only protocol. The inspector separately verifies
// every retained causal signature and edge before the request may be written.
fn require_stored_history(
    store: &Store,
    state: &CertifiedDag,
    payload: &SlotCertificatePayload,
    carrier: &VertexId,
) -> Result<(), StoreError> {
    let mut stored = BTreeMap::new();
    for vertex in store.vertices()? {
        stored
            .entry((vertex.round, vertex.author.clone()))
            .or_insert(vertex);
    }
    let dag = state.dag();
    // A direct skip still needs its elected leader on replay, even though
    // nonvoters need not carry that leader in the QC carrier's causal cone.
    let leader = dag
        .leader(payload.proposal.decision.round)
        .ok_or_else(|| malformed("slot application elected leader missing"))?;
    if stored.get(&(leader.round, leader.author.clone())) != Some(leader) {
        return Err(malformed(
            "slot application elected leader is not stored exactly",
        ));
    }
    let mut seen = HashSet::new();
    let mut stack = vec![carrier.clone()];
    while let Some(current) = stack.pop() {
        if !seen.insert(current.clone()) || dag.floor().is_some_and(|floor| current.round <= floor)
        {
            continue;
        }
        let vertex = dag
            .get(current.round, &current.author)
            .ok_or_else(|| malformed("slot application history missing from DAG"))?;
        if vertex.id()? != current
            || stored.get(&(current.round, current.author.clone())) != Some(vertex)
        {
            return Err(malformed("slot application history is not stored exactly"));
        }
        stack.extend(vertex.references.iter().cloned());
    }
    Ok(())
}

fn sync_request(file: &File, root: &Path) -> Result<(), StoreError> {
    file.sync_all()?;
    slot_decision_journal::sync_ancestors(root, |directory| File::open(directory)?.sync_all())?;
    Ok(())
}

fn append_synced(
    root: &Path,
    record: &StoredSlotApplication,
    barrier: &mut impl FnMut(&File, &Path) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let records = read(root)?;
    let existing = records.iter().find(|old| {
        old.payload.certificate.decision.round == record.payload.certificate.decision.round
    });
    if let Some(existing) = existing {
        if existing != record {
            return Err(malformed("conflicting slot application request"));
        }
    } else if let Some(previous) = records.last() {
        follows(previous, record)?;
    }
    let body = record.encode()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join(FILE))?;
    if existing.is_none() {
        file.write_all(&(body.len() as u32).to_le_bytes())?;
        file.write_all(&body)?;
        file.write_all(&checksum(&body))?;
    }
    barrier(&file, root)
}

impl Store {
    /// Persists an inactive certified-DAG request before installing its volatile effect.
    ///
    /// Requires exact supporting vertices already in this store, then syncs vertex
    /// and batch logs before syncing the request and all directory ancestors. A
    /// failed preparation or sync leaves the supplied state unchanged. An I/O error
    /// may leave a complete request on disk: retry or replay, never assume absence.
    /// Exact last-event retries are supported and repeat the durability barriers.
    ///
    /// This is not live integration or transaction/finalizer application. The trusted
    /// activation checkpoint must be independently durable. Do not prune, rewrite, or
    /// adopt a legacy snapshot that discards supporting history while this WAL is
    /// retained; authenticated checkpoint/WAL migration is not implemented. Ordinary
    /// store operations and generation publication must be serialized by the caller.
    /// Work scales with logs, retained cones and order; caller work budgeting is required.
    /// Durability assumes honored filesystem/hardware sync, not rollback resistance.
    ///
    /// # Errors
    /// Returns certificate/history/continuity errors, corrupt or torn WAL errors,
    /// unstored history errors, and I/O failures. No signing intent is changed.
    pub fn apply_slot_certificate(
        &self,
        state: &mut CertifiedDag,
        payload: &SlotCertificatePayload,
        carrier: &VertexId,
    ) -> Result<SlotApplicationResult, StoreError> {
        self.apply_slot_certificate_with_barrier(state, payload, carrier, sync_request)
    }

    pub(super) fn apply_slot_certificate_with_barrier(
        &self,
        state: &mut CertifiedDag,
        payload: &SlotCertificatePayload,
        carrier: &VertexId,
        mut barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<SlotApplicationResult, StoreError> {
        let _guard = self
            .slot_applications
            .lock()
            .expect("slot application lock poisoned");
        require_stored_history(self, state, payload, carrier)?;
        let prepared = state.prepare(payload, carrier)?;
        self.sync()?;
        let record = StoredSlotApplication {
            payload: payload.clone(),
            carrier: carrier.clone(),
        };
        append_synced(
            self.path_of(FILE).parent().expect("journal has a parent"),
            &record,
            &mut barrier,
        )?;
        Ok(prepared.apply())
    }

    /// Reads inactive replay requests in decision order, checking framing and continuity.
    ///
    /// # Errors
    /// Returns I/O or decoding errors, including any torn or corrupt tail. Does not
    /// authenticate QC signatures, the bootstrap anchor, or supporting DAG history.
    pub fn slot_applications(&self) -> Result<Vec<StoredSlotApplication>, StoreError> {
        let _guard = self
            .slot_applications
            .lock()
            .expect("slot application lock poisoned");
        read(self.path_of(FILE).parent().expect("journal has a parent"))
    }

    /// Replays a contiguous inactive WAL suffix into a trusted, history-loaded DAG.
    ///
    /// A checkpoint inside the WAL must match its exact decision ID, frontier and
    /// QC carrier before any suffix is applied. Bootstrap at the first record is
    /// validated by preparation. Repeating replay at the current WAL tip is a no-op.
    /// Repeats supporting-log, WAL-file, and directory sync barriers before every
    /// application, including recovery from a prior uncertain write/sync failure.
    /// This reconstructs order/tip only, not transaction state or finalizer progress.
    ///
    /// # Errors
    /// Returns malformed WAL/checkpoint/history errors or inspector errors. Earlier
    /// validated records may already be installed when a later record fails; the
    /// state is a valid prefix, and replay may resume from that prefix.
    pub fn replay_slot_applications(
        &self,
        state: &mut CertifiedDag,
    ) -> Result<Vec<SlotApplicationResult>, StoreError> {
        self.replay_slot_applications_with_barrier(state, sync_request)
    }

    pub(super) fn replay_slot_applications_with_barrier(
        &self,
        state: &mut CertifiedDag,
        mut barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<Vec<SlotApplicationResult>, StoreError> {
        let _guard = self
            .slot_applications
            .lock()
            .expect("slot application lock poisoned");
        let records = read(self.path_of(FILE).parent().expect("journal has a parent"))?;
        let next = state.binding().tip().next_round();
        let boundary =
            records.partition_point(|record| record.payload.certificate.decision.round < next);
        if boundary > 0 {
            let record = &records[boundary - 1];
            let decision = &record.payload.certificate.decision;
            let tip = state.binding().tip();
            if decision.round.checked_add(1) != Some(next)
                || decision.id()? != *tip.previous_id()
                || decision.chain_id != tip.chain_id()
                || decision.validator_set_id != *tip.set_id()
                || decision.epoch != tip.epoch()
                || decision.after_len != tip.order_len()
                || decision.after_root != *tip.order_root()
                || state.binding().carrier() != Some(&record.carrier)
            {
                return Err(malformed("slot application WAL checkpoint mismatch"));
            }
        }
        let mut applied = Vec::new();
        for record in &records[boundary..] {
            require_stored_history(self, state, &record.payload, &record.carrier)?;
            let prepared = state.prepare(&record.payload, &record.carrier)?;
            self.sync()?;
            append_synced(
                self.path_of(FILE).parent().expect("journal has a parent"),
                record,
                &mut barrier,
            )?;
            applied.push(prepared.apply());
        }
        Ok(applied)
    }
}
