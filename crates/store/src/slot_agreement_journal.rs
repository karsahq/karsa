//! Inactive root-level agreement WAL; no signer, live integration, or liveness claim.
//!
//! Bootstrap trust and the semantic oracle are external: neither is authenticated by
//! this WAL. Recovery must supply the oracle again. One fixed session is supported
//! per logical root, across generations. Deletion, rollback, and complete-boundary
//! truncation can erase promises; backups must preserve this file and the identity.
//! In particular, deleting this WAL permits a legacy-signing downgrade: no external
//! monotonic marker is implemented. Checksums detect damage, not malicious rewriting.
//! Durability assumes honored hardware/filesystem sync and an owner-controlled root.

use super::*;
use validator::slot_agreement::{
    AgreementInput, AgreementPhase, AgreementTransitionResult, AgreementValue, AgreementView,
    AgreementVote, SlotAgreement,
};
use validator::{SlotDecision, SlotDecisionTip, ValidatorSet};

pub(super) const FILE: &str = "slot-agreement";
// Header contains bounded set and context fields; events retain the codec's 1 MiB bound.
const MAX_BODY: usize = 2 * crypto::encoding::MAX_FIELD_LEN + 4096;
// This bounded slice has no compaction, rotation, or next-slot migration protocol.
const MAX_RECORDS: usize = 4096;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const DOMAIN: &[u8] = b"KARSA/STORE/SLOT_AGREEMENT/v1";

fn malformed(message: &str) -> StoreError {
    CryptoError::new(crypto::CryptoErrorKind::MalformedCertificate, message).into()
}

/// Externally trusted, fixed bootstrap and local identity for one root session.
#[derive(Debug, Clone)]
pub struct SlotAgreementBootstrap {
    /// Trusted fixed slot and predecessor/frontier context.
    pub context: SlotDecisionTip,
    /// Complete fixed validator set, including key schedules.
    pub set: ValidatorSet,
    /// Local validator identity; changing it is not a journal migration.
    pub local_validator: Vec<u8>,
}

impl SlotAgreementBootstrap {
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if self.local_validator.len() > 1024 || self.set.validator(&self.local_validator).is_none()
        {
            return Err(malformed("invalid local agreement identity"));
        }
        let vote = AgreementVote {
            context: self.context.clone(),
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
            value: AgreementValue::Nil,
        };
        let mut e = Encoder::new();
        e.put_u16(1);
        e.put_bytes(&self.set.encode()?)?;
        e.put_bytes(&vote.encode(&self.set)?)?;
        e.put_bytes(&self.local_validator)?;
        let body = e.finish();
        if body.len() > MAX_BODY {
            return Err(malformed("agreement header exceeds bound"));
        }
        Ok(body)
    }

    fn decode(body: &[u8]) -> Result<Self, StoreError> {
        let mut d = Decoder::new(body);
        if d.read_u16()? != 1 {
            return Err(malformed("unknown agreement WAL version"));
        }
        let set = ValidatorSet::decode(d.read_bytes()?)?;
        let vote = AgreementVote::decode(d.read_bytes()?, &set)?;
        let local_validator = d.read_bytes()?.to_vec();
        d.finish()?;
        let bootstrap = Self {
            context: vote.context,
            set,
            local_validator,
        };
        if bootstrap.encode()? != body {
            return Err(malformed("noncanonical agreement header"));
        }
        Ok(bootstrap)
    }
}

struct Journal {
    bootstrap: SlotAgreementBootstrap,
    header: Vec<u8>,
    inputs: Vec<AgreementInput>,
    tip: [u8; 32],
    bytes: u64,
}

fn digest(previous: &[u8; 32], sequence: u64, body: &[u8]) -> [u8; 32] {
    crypto::merkle::leaf(
        DOMAIN,
        &[
            previous,
            &sequence.to_le_bytes(),
            &(body.len() as u32).to_le_bytes(),
            body,
        ],
    )
}

fn frame(previous: &[u8; 32], sequence: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(body.len() + 36);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&digest(previous, sequence, body));
    bytes
}

fn read(root: &Path) -> Result<Option<Journal>, StoreError> {
    let path = root.join(FILE);
    validate_pointer_file(&path)?;
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_BYTES {
        return Err(malformed("agreement WAL exceeds total byte bound"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(malformed("agreement WAL exceeds total byte bound"));
    }
    let mut cursor = 0;
    let mut tip = [0; 32];
    let mut bodies = Vec::new();
    while cursor < bytes.len() {
        if bodies.len() > MAX_RECORDS {
            return Err(malformed("agreement WAL exceeds record bound"));
        }
        let length = bytes
            .get(cursor..cursor + 4)
            .ok_or_else(|| malformed("torn agreement length"))?;
        let len = u32::from_le_bytes(length.try_into().expect("four-byte length")) as usize;
        if len > MAX_BODY {
            return Err(malformed("agreement body exceeds bound"));
        }
        cursor += 4;
        let end = cursor + len;
        let body = bytes
            .get(cursor..end)
            .ok_or_else(|| malformed("torn agreement body"))?;
        let stored = bytes
            .get(end..end + 32)
            .ok_or_else(|| malformed("torn agreement checksum"))?;
        tip = digest(&tip, bodies.len() as u64, body);
        if stored != tip {
            return Err(malformed("corrupt agreement hash chain"));
        }
        bodies.push(body);
        cursor = end + 32;
    }
    let header = bodies
        .first()
        .ok_or_else(|| malformed("empty agreement WAL"))?;
    let bootstrap = SlotAgreementBootstrap::decode(header)?;
    let inputs = bodies[1..]
        .iter()
        .map(|body| {
            let input = AgreementInput::decode(body, &bootstrap.set)?;
            if input.encode(&bootstrap.set)? != *body {
                return Err(malformed("noncanonical agreement input"));
            }
            Ok(input)
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    Ok(Some(Journal {
        bootstrap,
        header: header.to_vec(),
        inputs,
        tip,
        bytes: bytes.len() as u64,
    }))
}

fn overlap(root: &Path, bootstrap: &SlotAgreementBootstrap) -> Result<(), StoreError> {
    if slot_decision_journal::read(root)?.iter().any(|d| {
        d.chain_id == bootstrap.context.chain_id() && d.round == bootstrap.context.next_round()
    }) {
        return Err(malformed("legacy decision overlaps agreement session"));
    }
    Ok(())
}

pub(super) fn validate(root: &Path) -> Result<(), StoreError> {
    if let Some(journal) = read(root)? {
        overlap(root, &journal.bootstrap)?;
    }
    Ok(())
}

pub(super) fn exclude_legacy(root: &Path, decision: &SlotDecision) -> Result<(), StoreError> {
    if let Some(journal) = read(root)? {
        if journal.bootstrap.context.chain_id() == decision.chain_id
            && journal.bootstrap.context.next_round() == decision.round
        {
            return Err(malformed("agreement session excludes legacy signing"));
        }
    }
    Ok(())
}

fn sync(file: &File, root: &Path) -> Result<(), StoreError> {
    file.sync_all()?;
    slot_decision_journal::sync_ancestors(root, |p| File::open(p)?.sync_all())?;
    Ok(())
}

fn copy_result(result: &AgreementTransitionResult) -> AgreementTransitionResult {
    AgreementTransitionResult {
        vote: result.vote.clone(),
        view: result.view,
        decision: result.decision.clone(),
    }
}

/// Owned inactive reducer; no mutable reducer access and no signing authority.
///
/// Any uncertain append/barrier error blocks this owner until recovery. Recovery
/// revalidates all events with the caller's external semantic oracle. There is no
/// authenticated persisted oracle, rollback protection, production safety or
/// liveness claim. Only the exact last sequence/input may be retried. At most
/// 4096 events and 64 MiB (including the header) are retained; there is no rotation.
#[derive(Debug)]
pub struct DurableSlotAgreement {
    store: Store,
    bootstrap: SlotAgreementBootstrap,
    header: Vec<u8>,
    reducer: SlotAgreement,
    sequence: u64,
    tip: [u8; 32],
    last: Option<(AgreementInput, AgreementTransitionResult)>,
    uncertain: bool,
}

impl Store {
    /// Creates the only agreement session permitted at this logical root.
    ///
    /// # Errors
    /// Rejects existing sessions, legacy chain/slot reservations, invalid bootstrap,
    /// and I/O failures. On I/O failure recover; never infer that creation was absent.
    pub fn begin_slot_agreement(
        &self,
        bootstrap: SlotAgreementBootstrap,
    ) -> Result<DurableSlotAgreement, StoreError> {
        self.begin_slot_agreement_with_io(bootstrap, |file, bytes| Ok(file.write_all(bytes)?), sync)
    }

    pub(super) fn begin_slot_agreement_with_io(
        &self,
        bootstrap: SlotAgreementBootstrap,
        mut write: impl FnMut(&mut File, &[u8]) -> Result<(), StoreError>,
        mut barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<DurableSlotAgreement, StoreError> {
        let header = bootstrap.encode()?;
        let reducer = SlotAgreement::new(bootstrap.context.clone(), bootstrap.set.clone())?;
        let root = self
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        if read(&root)?.is_some() {
            return Err(malformed("agreement session already exists"));
        }
        overlap(&root, &bootstrap)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(FILE))?;
        write(&mut file, &frame(&[0; 32], 0, &header))?;
        barrier(&file, &root)?;
        let tip = digest(&[0; 32], 0, &header);
        Ok(DurableSlotAgreement {
            store: self.clone(),
            bootstrap,
            header,
            reducer,
            sequence: 0,
            tip,
            last: None,
            uncertain: false,
        })
    }

    /// Recovers a session using exact trusted bootstrap and mandatory semantic checks.
    ///
    /// Recovery callbacks execute under the root signing mutex and MUST NOT reenter
    /// either journal, including through a store clone. Callback side effects are
    /// external and cannot be rolled back. A failed recovery releases no session.
    /// Complete uncertain records repeat file and ancestor barriers before apply.
    /// Ordinary `Store::open` checks only structure and legacy overlap, not these
    /// semantic, signature, and reducer replay obligations.
    ///
    /// # Errors
    /// Rejects bootstrap/identity mismatch, corrupt/torn WAL, legacy overlap,
    /// invalid signatures or semantics, reducer conflicts, and durability failures.
    pub fn recover_slot_agreement(
        &self,
        bootstrap: SlotAgreementBootstrap,
        validate: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
    ) -> Result<DurableSlotAgreement, StoreError> {
        self.recover_slot_agreement_with_barrier(bootstrap, validate, sync)
    }

    pub(super) fn recover_slot_agreement_with_barrier(
        &self,
        bootstrap: SlotAgreementBootstrap,
        validate: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
        barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<DurableSlotAgreement, StoreError> {
        self.recover_slot_agreement_validated_with_barrier(bootstrap, |_| Ok(()), validate, barrier)
    }

    /// Replays each exact canonical event through an external semantic validator.
    ///
    /// The input callback sees the persisted view, phase/QC and exact POL, not a
    /// reconstructed latest lineage. Decision validation remains mandatory through
    /// reducer preparation. Both callbacks run under the root signing mutex and
    /// MUST NOT reenter either journal, even through a store clone. External callback
    /// side effects cannot be rolled back; failure returns no owner.
    ///
    /// # Errors
    /// Returns input/decision validation, replay, bootstrap, WAL or durability errors.
    pub fn recover_slot_agreement_validated(
        &self,
        bootstrap: SlotAgreementBootstrap,
        validate_input: impl FnMut(&AgreementInput) -> Result<(), CryptoError>,
        validate_decision: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
    ) -> Result<DurableSlotAgreement, StoreError> {
        self.recover_slot_agreement_validated_with_barrier(
            bootstrap,
            validate_input,
            validate_decision,
            sync,
        )
    }

    fn recover_slot_agreement_validated_with_barrier(
        &self,
        bootstrap: SlotAgreementBootstrap,
        mut validate_input: impl FnMut(&AgreementInput) -> Result<(), CryptoError>,
        mut validate: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
        mut barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<DurableSlotAgreement, StoreError> {
        let header = bootstrap.encode()?;
        let mut reducer = SlotAgreement::new(bootstrap.context.clone(), bootstrap.set.clone())?;
        let root = self
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        let journal = read(&root)?.ok_or_else(|| malformed("agreement session missing"))?;
        if journal.header != header {
            return Err(malformed("agreement bootstrap or identity mismatch"));
        }
        overlap(&root, &bootstrap)?;
        let file = File::open(root.join(FILE))?;
        barrier(&file, &root)?;
        let mut last = None;
        for input in &journal.inputs {
            validate_input(input)?;
            let prepared = reducer.prepare(input.clone(), &mut validate)?;
            barrier(&file, &root)?;
            last = Some((input.clone(), prepared.apply()));
        }
        Ok(DurableSlotAgreement {
            store: self.clone(),
            bootstrap,
            header,
            reducer,
            sequence: journal.inputs.len() as u64,
            tip: journal.tip,
            last,
            uncertain: false,
        })
    }
}

impl DurableSlotAgreement {
    /// Number of successfully installed events; the next new request uses this plus one.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Persists one canonical event atomically, including lock/precommit effects.
    ///
    /// Preparation runs outside the root mutex, then rechecks sequence and chain tip.
    /// Exact last retries repeat barriers and return the original result. Never sign
    /// or act on an error: I/O uncertainty requires recovering a new owned session.
    /// Every accepted new sequence consumes a WAL record, even when the reducer
    /// effect is a no-op. Only an exact last-sequence retry avoids growth; no-op
    /// requests can exhaust the bounded WAL, and no compaction is implemented.
    ///
    /// # Errors
    /// Rejects stale sessions, incorrect sequence/retry input, semantic or reducer
    /// errors, WAL bounds/corruption, legacy collisions, and filesystem failures.
    pub fn apply(
        &mut self,
        sequence: u64,
        input: AgreementInput,
        validate: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
    ) -> Result<AgreementTransitionResult, StoreError> {
        self.apply_with_barrier(sequence, input, validate, sync)
    }

    pub(super) fn apply_with_barrier(
        &mut self,
        sequence: u64,
        input: AgreementInput,
        validate: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
        barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<AgreementTransitionResult, StoreError> {
        self.apply_with_io(
            sequence,
            input,
            validate,
            |file, bytes| Ok(file.write_all(bytes)?),
            barrier,
        )
    }

    pub(super) fn apply_with_io(
        &mut self,
        sequence: u64,
        input: AgreementInput,
        validate: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
        write: impl FnMut(&mut File, &[u8]) -> Result<(), StoreError>,
        barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<AgreementTransitionResult, StoreError> {
        self.apply_validated_with_io(sequence, input, |_| Ok(()), validate, write, barrier)
    }

    /// Validates the exact event before persistence or output, including exact retries.
    ///
    /// The callback receives the actual view, phase/QC and POL, including timeouts.
    /// Both callbacks run outside the root mutex and may reenter via another owner;
    /// the WAL tip is rechecked afterward. Callback side effects cannot be rolled
    /// back. Decision validation still runs through reducer preparation for new
    /// events; retries retain the already prepared original result.
    ///
    /// # Errors
    /// Returns the same errors as `apply`, plus input validation failures. Validation
    /// failure does not change this owner or append a record.
    pub fn apply_validated(
        &mut self,
        sequence: u64,
        input: AgreementInput,
        validate_input: impl FnMut(&AgreementInput) -> Result<(), CryptoError>,
        validate_decision: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
    ) -> Result<AgreementTransitionResult, StoreError> {
        self.apply_validated_with_io(
            sequence,
            input,
            validate_input,
            validate_decision,
            |file, bytes| Ok(file.write_all(bytes)?),
            sync,
        )
    }

    fn apply_validated_with_io(
        &mut self,
        sequence: u64,
        input: AgreementInput,
        mut validate_input: impl FnMut(&AgreementInput) -> Result<(), CryptoError>,
        mut validate: impl FnMut(&SlotDecision) -> Result<(), CryptoError>,
        mut write: impl FnMut(&mut File, &[u8]) -> Result<(), StoreError>,
        mut barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<AgreementTransitionResult, StoreError> {
        if self.uncertain {
            return Err(malformed("uncertain agreement I/O requires recovery"));
        }
        let retry =
            sequence == self.sequence && self.last.as_ref().is_some_and(|(old, _)| old == &input);
        if !retry && sequence != self.sequence + 1 {
            return Err(malformed("incorrect agreement sequence or retry"));
        }
        let body = input.encode(&self.bootstrap.set)?;
        validate_input(&input)?;
        let prepared = if retry {
            None
        } else {
            Some(self.reducer.prepare(input.clone(), &mut validate)?)
        };
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        let journal = read(&root)?.ok_or_else(|| malformed("agreement WAL missing"))?;
        if journal.header != self.header
            || journal.inputs.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(malformed("stale agreement session"));
        }
        overlap(&root, &self.bootstrap)?;
        let bytes = frame(&self.tip, sequence, &body);
        if !retry
            && (journal.inputs.len() >= MAX_RECORDS
                || journal.bytes + bytes.len() as u64 > MAX_BYTES)
        {
            return Err(malformed("agreement WAL capacity exhausted"));
        }
        self.uncertain = true;
        let mut file = OpenOptions::new().append(true).open(root.join(FILE))?;
        if !retry {
            write(&mut file, &bytes)?;
        }
        barrier(&file, &root)?;
        self.uncertain = false;
        if let Some(prepared) = prepared {
            let result = prepared.apply();
            self.sequence = sequence;
            self.tip = digest(&self.tip, sequence, &body);
            self.last = Some((input, copy_result(&result)));
            Ok(result)
        } else {
            Ok(copy_result(
                &self.last.as_ref().expect("retry has a last event").1,
            ))
        }
    }
}
