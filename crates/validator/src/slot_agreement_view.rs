//! Inactive authenticated view proposals using the legacy strong POL trust basis.
//!
//! Earlier POL votes bind a plain direct proposal, not an authenticated earlier
//! view proposal. This API does not prove recursive view authorization, local lock
//! safety, or a view-aware final chain; it never authorizes signing or application.

use crypto::CryptoError;
use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use sha2::{Digest, Sha256};

use crate::slot_agreement::AgreementView;
use crate::slot_agreement_phase::invalid;
use crate::{SlotAgreementStrongPrevotePayload, SlotProposal, ValidatorSet, VertexId};

/// Independent canonical view-proposal domain.
pub const SLOT_AGREEMENT_VIEW_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_AGREEMENT_VIEW/v1";

/// A strong earlier POL and its exact signed carrier, without recursive view claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementPreviousPol {
    /// Complete aggregate and individual vote witnesses.
    pub payload: SlotAgreementStrongPrevotePayload,
    /// Carrier binding the complete strong payload.
    pub carrier: VertexId,
}

/// Complete direct evidence plus optional earlier strong POL for the same decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementViewProposal {
    /// Agreement view, independent of the DAG round.
    pub view: AgreementView,
    /// Complete direct-rule evidence.
    pub proposal: SlotProposal,
    /// Exact plain-proposal carrier, preceding this view proposal.
    pub proposal_carrier: VertexId,
    /// Earlier strong POL under the explicitly nonrecursive legacy trust basis.
    pub previous_pol: Option<SlotAgreementPreviousPol>,
}

fn bound(size: usize) -> Result<(), CryptoError> {
    if size > MAX_FIELD_LEN {
        return Err(invalid("view proposal exceeds one MiB"));
    }
    Ok(())
}

fn put_id(e: &mut Encoder, id: &VertexId) -> Result<(), CryptoError> {
    if id.author.len() > 1024 {
        return Err(invalid("view carrier author exceeds bound"));
    }
    e.put_u64(id.round);
    e.put_bytes(&id.author)?;
    e.put_bytes(&id.digest)
}

fn read_id(d: &mut Decoder<'_>) -> Result<VertexId, CryptoError> {
    let round = d.read_u64()?;
    let author = d.read_bytes()?;
    if author.len() > 1024 {
        return Err(invalid("view carrier author exceeds bound"));
    }
    let digest = d
        .read_bytes()?
        .try_into()
        .map_err(|_| invalid("invalid view carrier digest"))?;
    Ok(VertexId {
        round,
        author: author.to_vec(),
        digest,
    })
}

impl SlotAgreementViewProposal {
    /// Encodes bounded canonical evidence without authenticating it.
    ///
    /// # Errors
    /// Rejects nested codec errors and total or author bounds.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        let proposal = self.proposal.encode()?;
        let pol = self
            .previous_pol
            .as_ref()
            .map(|p| p.payload.encode(set))
            .transpose()?;
        let mut e = Encoder::new();
        e.put_u16(1);
        e.put_u64(self.view.0);
        e.put_bytes(&proposal)?;
        put_id(&mut e, &self.proposal_carrier)?;
        match (&self.previous_pol, pol) {
            (Some(p), Some(bytes)) => {
                e.put_u8(1);
                e.put_bytes(&bytes)?;
                put_id(&mut e, &p.carrier)?;
            }
            _ => e.put_u8(0),
        }
        let bytes = e.finish();
        bound(bytes.len())?;
        Ok(bytes)
    }

    /// Decodes bounded nonrecursive evidence; does not authenticate it.
    ///
    /// # Errors
    /// Rejects unknown tags, malformed nested evidence, bounds and trailing bytes.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        bound(bytes.len())?;
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != 1 {
            return Err(invalid("unknown view proposal version"));
        }
        let view = AgreementView(d.read_u64()?);
        let proposal = SlotProposal::decode(d.read_bytes()?)?;
        let proposal_carrier = read_id(&mut d)?;
        let previous_pol = match d.read_u8()? {
            0 => None,
            1 => Some(SlotAgreementPreviousPol {
                payload: SlotAgreementStrongPrevotePayload::decode(d.read_bytes()?, set)?,
                carrier: read_id(&mut d)?,
            }),
            _ => return Err(invalid("unknown view POL tag")),
        };
        d.finish()?;
        Ok(Self {
            view,
            proposal,
            proposal_carrier,
            previous_pol,
        })
    }

    /// Hashes canonical bytes in an independent domain.
    ///
    /// # Errors
    /// Propagates encoding errors.
    pub fn digest(&self, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        let mut e = Encoder::new();
        e.put_bytes(SLOT_AGREEMENT_VIEW_DOMAIN)?;
        e.put_raw(&self.encode(set)?);
        Ok(Sha256::digest(e.finish()).into())
    }
}

/// Selects an equal-identity proposer, distinct from DAG leader selection.
///
/// Lexicographically sorted identities rotate by `(slot + view) mod n`, using
/// modular arithmetic without overflow. Set order and keys do not affect rotation;
/// the caller must pin and validate the chain/set/epoch context separately.
/// No stake weighting is implied.
///
/// # Errors
/// Rejects empty or invalid sets (including duplicate identities).
pub fn slot_agreement_view_proposer(
    set: &ValidatorSet,
    slot: u64,
    view: AgreementView,
) -> Result<&[u8], CryptoError> {
    set.validate()?;
    let mut ids: Vec<_> = set
        .validators
        .iter()
        .map(|v| v.validator_id.as_slice())
        .collect();
    ids.sort_unstable();
    let n = ids.len() as u128;
    if n == 0 {
        return Err(invalid("empty view proposer set"));
    }
    Ok(ids[((u128::from(slot) + u128::from(view.0)) % n) as usize])
}
