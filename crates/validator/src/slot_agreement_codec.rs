//! Canonical bounded storage bodies, distinct from agreement signing payloads.
//! Decoding reconstructs structurally checked context using the supplied set;
//! it does NOT establish checkpoint trust, authenticate signatures, or validate semantics.

use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};

use super::{
    AgreementInput, AgreementPhase, AgreementQc, AgreementValue, AgreementView, AgreementVote,
    invalid,
};
use crate::{SlotDecision, SlotDecisionTip, ValidatorSet, ValidatorSignature};
use crypto::CryptoError;

const VERSION: u16 = 1;
const INPUT: u8 = 0;
const VOTE: u8 = 1;
const QC: u8 = 2;
const MAX_SIGNATURES: usize = 4096;
const MAX_ID: usize = 1024;

fn bound(size: usize) -> Result<usize, CryptoError> {
    if size > MAX_FIELD_LEN {
        return Err(invalid("agreement codec exceeds one MiB"));
    }
    Ok(size)
}

fn add(size: usize, extra: usize) -> Result<usize, CryptoError> {
    bound(
        size.checked_add(extra)
            .ok_or_else(|| invalid("agreement codec length overflow"))?,
    )
}

fn start(kind: u8) -> Encoder {
    let mut e = Encoder::new();
    e.put_u16(VERSION);
    e.put_u8(kind);
    e
}

fn decoder(bytes: &[u8], kind: u8) -> Result<Decoder<'_>, CryptoError> {
    bound(bytes.len())?;
    let mut d = Decoder::new(bytes);
    if d.read_u16()? != VERSION || d.read_u8()? != kind {
        return Err(invalid("unknown agreement codec version or body kind"));
    }
    Ok(d)
}

fn phase(phase: AgreementPhase) -> u8 {
    match phase {
        AgreementPhase::Prevote => 0,
        AgreementPhase::Precommit => 1,
    }
}

fn read_phase(d: &mut Decoder<'_>) -> Result<AgreementPhase, CryptoError> {
    match d.read_u8()? {
        0 => Ok(AgreementPhase::Prevote),
        1 => Ok(AgreementPhase::Precommit),
        _ => Err(invalid("unknown agreement phase")),
    }
}

fn id<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8], CryptoError> {
    let bytes = d.read_bytes()?;
    if bytes.len() > MAX_ID {
        return Err(invalid("agreement identifier exceeds bound"));
    }
    Ok(bytes)
}

fn digest(d: &mut Decoder<'_>) -> Result<[u8; 32], CryptoError> {
    d.read_bytes()?
        .try_into()
        .map_err(|_| invalid("expected agreement 32-byte digest"))
}

impl AgreementVote {
    /// Encodes a full canonical storage body, including the complete decision.
    /// This is NOT the signing payload and authenticates nothing.
    ///
    /// # Errors
    /// Rejects structural/context/set errors and bodies larger than one MiB.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        self.signing_payload(set)?;
        let decision = match &self.value {
            AgreementValue::Nil => None,
            AgreementValue::Decision(d) => Some(d.encode()?),
        };
        // Header, context length prefixes, four u64s, phase/value tags.
        let size = add(
            3 + 4 + self.context.chain_id().len() + 3 * 36 + 4 * 8 + 2,
            decision.as_ref().map_or(0, |b| 4 + b.len()),
        )?;
        let mut e = start(VOTE);
        let c = &self.context;
        e.put_bytes(c.chain_id())?;
        e.put_bytes(c.set_id())?;
        e.put_u64(c.epoch());
        e.put_u64(c.next_round());
        e.put_bytes(c.previous_id())?;
        e.put_u64(c.order_len());
        e.put_bytes(c.order_root())?;
        e.put_u64(self.view.0);
        e.put_u8(phase(self.phase));
        if let Some(bytes) = decision {
            e.put_u8(1);
            e.put_bytes(&bytes)?;
        } else {
            e.put_u8(0);
        }
        debug_assert_eq!(e.len(), size);
        Ok(e.finish())
    }

    /// Decodes full context against a supplied set without establishing its trust.
    /// A decoded tip is only an untrusted statement; compare it with the trusted
    /// owner context during preparation/verification. No signatures are checked.
    ///
    /// # Errors
    /// Rejects bounds, malformed/truncated/trailing data, tags, and set/context mismatch.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        let mut d = decoder(bytes, VOTE)?;
        let chain = id(&mut d)?.to_vec();
        let set_id = digest(&mut d)?;
        let epoch = d.read_u64()?;
        let slot = d.read_u64()?;
        let previous = digest(&mut d)?;
        let before_len = d.read_u64()?;
        let before_root = digest(&mut d)?;
        let context =
            SlotDecisionTip::from_checkpoint(chain, set, slot, previous, before_len, before_root)?;
        if *context.set_id() != set_id || context.epoch() != epoch {
            return Err(invalid("decoded agreement set or epoch mismatch"));
        }
        let view = AgreementView(d.read_u64()?);
        let phase = read_phase(&mut d)?;
        let value = match d.read_u8()? {
            0 => AgreementValue::Nil,
            1 => AgreementValue::Decision(SlotDecision::decode(d.read_bytes()?)?),
            _ => return Err(invalid("unknown agreement value tag")),
        };
        d.finish()?;
        let vote = Self {
            context,
            view,
            phase,
            value,
        };
        vote.signing_payload(set)?;
        Ok(vote)
    }
}

impl AgreementQc {
    /// Encodes bounded evidence in strictly increasing validator-ID order.
    /// Does not sort, verify quorum signatures, or authenticate semantics.
    ///
    /// # Errors
    /// Rejects malformed votes, duplicate/reordered signers, more than 4096
    /// signatures, identifiers over 1024 bytes, and total bodies over one MiB.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(invalid("too many agreement signatures"));
        }
        // Preflight all signature lengths/order before copying any signature bytes.
        let mut size = 3 + 4 + 4;
        let mut previous: Option<&[u8]> = None;
        for s in &self.signatures {
            if s.validator_id.len() > MAX_ID
                || s.key_id.len() > MAX_ID
                || previous.is_some_and(|p| p >= s.validator_id.as_slice())
            {
                return Err(invalid("noncanonical agreement signer order or identifier"));
            }
            previous = Some(&s.validator_id);
            for bytes in [&s.validator_id, &s.key_id, &s.signature] {
                size = add(size, 4)?;
                size = add(size, bytes.len())?;
            }
        }
        let vote = self.vote.encode(set)?;
        add(size, vote.len())?;
        let mut e = start(QC);
        e.put_bytes(&vote)?;
        e.put_u32(
            u32::try_from(self.signatures.len())
                .map_err(|_| invalid("signature count overflow"))?,
        );
        for s in &self.signatures {
            e.put_bytes(&s.validator_id)?;
            e.put_bytes(&s.key_id)?;
            e.put_bytes(&s.signature)?;
        }
        Ok(e.finish())
    }

    /// Decodes canonical untrusted evidence without cryptographic verification.
    /// Signature count, order and lengths are preflighted before owned allocation.
    ///
    /// # Errors
    /// Rejects noncanonical order, excessive counts/lengths, invalid vote bodies,
    /// unknown versions/tags, truncation, and trailing bytes.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        let mut d = decoder(bytes, QC)?;
        let vote_bytes = d.read_bytes()?;
        let count =
            usize::try_from(d.read_u32()?).map_err(|_| invalid("signature count overflow"))?;
        if count > MAX_SIGNATURES || count > d.remaining() / 12 {
            return Err(invalid(
                "agreement signature count exceeds bound or remaining bytes",
            ));
        }
        let mut scan = d.clone();
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let validator = id(&mut scan)?;
            if previous.is_some_and(|p| p >= validator) {
                return Err(invalid("noncanonical agreement signer order"));
            }
            previous = Some(validator);
            id(&mut scan)?;
            scan.read_bytes()?;
        }
        scan.finish()?;
        let vote = AgreementVote::decode(vote_bytes, set)?;
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(ValidatorSignature {
                validator_id: id(&mut d)?.to_vec(),
                key_id: id(&mut d)?.to_vec(),
                signature: d.read_bytes()?.to_vec(),
            });
        }
        d.finish()?;
        Ok(Self { vote, signatures })
    }
}

impl AgreementInput {
    /// Encodes the exact owned event as a canonical storage body, not a signing payload.
    /// Does not authenticate evidence or establish semantic/checkpoint trust.
    ///
    /// # Errors
    /// Rejects nested codec errors and total encoded size over one MiB.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        let mut e = start(INPUT);
        match self {
            Self::Propose {
                view,
                decision,
                pol,
            } => {
                decision.validate(set)?;
                let decision = decision.encode()?;
                let pol = pol.as_ref().map(|q| q.encode(set)).transpose()?;
                add(
                    3 + 1 + 8 + 4 + decision.len() + 1,
                    pol.as_ref().map_or(0, |q| 4 + q.len()),
                )?;
                e.put_u8(0);
                e.put_u64(view.0);
                e.put_bytes(&decision)?;
                match pol {
                    None => e.put_u8(0),
                    Some(q) => {
                        e.put_u8(1);
                        e.put_bytes(&q)?;
                    }
                }
            }
            Self::Timeout { view, phase: p } => {
                e.put_u8(1);
                e.put_u64(view.0);
                e.put_u8(phase(*p));
            }
            Self::AdvanceView { from } => {
                e.put_u8(2);
                e.put_u64(from.0);
            }
            Self::Evidence { qc } => {
                let qc = qc.encode(set)?;
                add(3 + 1 + 4, qc.len())?;
                e.put_u8(3);
                e.put_bytes(&qc)?;
            }
        }
        Ok(e.finish())
    }

    /// Decodes a bounded canonical event; replay must still call `prepare` with
    /// external semantic validation. Decoding alone does not authorize a transition.
    ///
    /// # Errors
    /// Rejects invalid nested bodies, unknown tags/versions, oversized bodies,
    /// truncation, trailing bytes and noncanonical signature order.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        let mut d = decoder(bytes, INPUT)?;
        let input = match d.read_u8()? {
            0 => {
                let view = AgreementView(d.read_u64()?);
                let decision = SlotDecision::decode(d.read_bytes()?)?;
                decision.validate(set)?;
                let pol = match d.read_u8()? {
                    0 => None,
                    1 => Some(AgreementQc::decode(d.read_bytes()?, set)?),
                    _ => return Err(invalid("unknown agreement optional POL tag")),
                };
                Self::Propose {
                    view,
                    decision,
                    pol,
                }
            }
            1 => Self::Timeout {
                view: AgreementView(d.read_u64()?),
                phase: read_phase(&mut d)?,
            },
            2 => Self::AdvanceView {
                from: AgreementView(d.read_u64()?),
            },
            3 => Self::Evidence {
                qc: AgreementQc::decode(d.read_bytes()?, set)?,
            },
            _ => return Err(invalid("unknown agreement input tag")),
        };
        d.finish()?;
        Ok(input)
    }
}
