//! Header production and certificate collection over a commit stream.
//!
//! The DAG decides an order; a header commits the state and the order at one
//! decision, and a certificate is what makes that header final. This module is
//! the transport-free part of that pipeline: it turns commit boundaries into
//! headers, signs the headers this node is allowed to sign, collects shares from
//! the other validators, and advances a [`HeaderChain`] once a quorum exists.
//!
//! It deliberately knows nothing about vertices, batches, execution, sockets, or
//! clocks. The caller supplies:
//!
//! - the committed order (for `dag_root`),
//! - the state root and applied count at each prefix (from execution),
//! - the timestamp to attach to each share.
//!
//! That is the seam the live TCP node uses, so the transport and the header
//! rules can be tested apart. The in-process finality harness still carries its
//! own copy of the same rules; it is the measured reference and moves over in a
//! separate change with a fresh run matrix. A node that is not in the set at a
//! header's epoch still builds the header, so its chain stays readable, but it
//! does not sign.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crypto::scheme::Ed25519Scheme;
use crypto::{CryptoError, CryptoErrorKind};

use crate::certificate::{Certificate, bitmap_len, set_bit};
use crate::dag::commit_root;
use crate::header::{Header, HeaderChain};
use crate::schedule::EpochSchedule;
use crate::set_change::SetSchedule;
use crate::vertex::VertexId;

/// Opaque validator-set label carried by every certificate.
///
/// It does not resolve keys; the set and epoch do. Keeping it stable means a
/// certificate signed by the finality harness and one signed by the live node
/// describe the same object.
pub const VALIDATOR_SET_ID: &[u8] = b"karsa-finality-1";

/// One validator's signature over one header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The header being signed.
    pub header: Header,
    /// The signer's index in the set active at the header's epoch.
    pub signer: usize,
    /// Ed25519 signature over [`signing_payload`].
    pub signature: Vec<u8>,
    /// Sender timestamp, used only to pick the earliest quorum.
    pub at: u64,
}

/// A header that reached a quorum.
#[derive(Debug, Clone)]
pub struct Certified {
    /// The certified header.
    pub header: Header,
    /// The quorum certificate over it.
    pub certificate: Certificate,
    /// The latest share time in the certificate.
    pub at: u64,
}

/// Headers built and certificates found during one [`Finalizer::build_ready`].
#[derive(Debug, Default)]
pub struct Build {
    /// Shares this node produced; the caller broadcasts them.
    pub shares: Vec<Share>,
    /// Certificates that became complete while building.
    pub certified: Vec<Certified>,
}

#[derive(Debug, Clone)]
struct Pending {
    round: u64,
    order_len: usize,
    height: u64,
    state_root: Option<[u8; 32]>,
    applied: u64,
}

#[derive(Debug, Clone)]
struct Signed {
    signature: Vec<u8>,
    at: u64,
}

#[derive(Debug, Clone)]
struct ShareSet {
    header: Header,
    signatures: BTreeMap<usize, Signed>,
}

/// One signature selected for a certificate: signer index, bytes, timestamp.
type SignedShare = (usize, Vec<u8>, u64);

/// One header and the earliest quorum over it.
type Candidate = ([u8; 32], Header, Vec<SignedShare>);

/// Builds headers and collects the certificates over them.
pub struct Finalizer {
    sets: SetSchedule,
    schedule: EpochSchedule,
    chain_id: Vec<u8>,
    signer: Vec<u8>,
    private_key: Vec<u8>,
    chain: HeaderChain,
    last_built: Header,
    last_built_order: usize,
    next_height: u64,
    pending: VecDeque<Pending>,
    shares: HashMap<[u8; 32], ShareSet>,
    certified_ids: BTreeMap<u64, [u8; 32]>,
    /// Committed entries each header this node built covers, by header id.
    ///
    /// A share only names the header, not the commit prefix behind it, so the
    /// mapping is recorded when the header is built and consulted when the same
    /// header is certified. A header this node never built is certified without
    /// an entry, and its coverage is reported as unknown rather than guessed.
    order_lens: HashMap<[u8; 32], usize>,
    /// The committed prefix each certified height covers, when this node built
    /// that header itself. Heights adopted from a peer are absent.
    certified_orders: BTreeMap<u64, usize>,
    built: usize,
    conflicts: usize,
}

impl Finalizer {
    /// Starts a finalizer whose trusted anchor is `anchor`.
    ///
    /// `anchor_order_len` is the number of committed entries the anchor covers.
    /// Use `0` for the genesis header and the snapshot prefix length when a node
    /// joins from a state snapshot.
    ///
    /// # Errors
    ///
    /// Every error from [`HeaderChain::with_schedule_and_change`], which rejects
    /// a transition that does not preserve the quorum intersection.
    pub fn new(
        sets: SetSchedule,
        schedule: EpochSchedule,
        chain_id: Vec<u8>,
        signer: Vec<u8>,
        private_key: Vec<u8>,
        anchor: Header,
        anchor_order_len: usize,
    ) -> Result<Self, CryptoError> {
        let chain = match sets.change_epoch() {
            Some(change_epoch) => HeaderChain::with_schedule_and_change(
                sets.base().clone(),
                sets.set_for_epoch(change_epoch).clone(),
                change_epoch,
                anchor.clone(),
                schedule,
            )?,
            None => HeaderChain::with_schedule(sets.base().clone(), anchor.clone(), schedule),
        };
        Ok(Self {
            sets,
            schedule,
            chain_id,
            signer,
            private_key,
            chain,
            next_height: anchor.height.saturating_add(1),
            last_built: anchor,
            last_built_order: anchor_order_len,
            pending: VecDeque::new(),
            shares: HashMap::new(),
            certified_ids: BTreeMap::new(),
            order_lens: HashMap::new(),
            certified_orders: BTreeMap::new(),
            built: 0,
            conflicts: 0,
        })
    }

    /// The header at the head of the verified chain.
    #[must_use]
    pub fn head(&self) -> &Header {
        self.chain.head()
    }

    /// The last header this node built, certified or not.
    #[must_use]
    pub fn last_built(&self) -> &Header {
        &self.last_built
    }

    /// Committed entries the last built header covers.
    #[must_use]
    pub fn last_built_order(&self) -> usize {
        self.last_built_order
    }

    /// The height the next commit will be built at.
    #[must_use]
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Headers this node has built.
    #[must_use]
    pub fn built_headers(&self) -> usize {
        self.built
    }

    /// Certified header ids by height.
    #[must_use]
    pub fn certified_ids(&self) -> &BTreeMap<u64, [u8; 32]> {
        &self.certified_ids
    }

    /// Committed entries the certified header at `height` covers.
    ///
    /// `None` when this node did not build that header itself, which is the case
    /// for a height it only adopted or certified from peer shares. Callers that
    /// map work to finality must treat `None` as unknown, not as zero.
    #[must_use]
    pub fn certified_order(&self, height: u64) -> Option<usize> {
        self.certified_orders.get(&height).copied()
    }

    /// Whether a header at `height` is certified on this chain.
    #[must_use]
    pub fn is_certified(&self, height: u64) -> bool {
        self.certified_ids.contains_key(&height)
    }

    /// Certificate conflicts seen so far.
    #[must_use]
    pub fn conflicts(&self) -> usize {
        self.conflicts
    }

    /// The chain id every header and certificate must carry.
    #[must_use]
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }

    /// The epoch schedule this finalizer resolves sets against.
    #[must_use]
    pub fn schedule(&self) -> EpochSchedule {
        self.schedule
    }

    /// Reserves the next header height for a decided commit.
    ///
    /// `order_len` is the committed order length after this commit. The caller
    /// records one header per decision, in decision order.
    pub fn record_commit(&mut self, round: u64, order_len: usize) -> u64 {
        let height = self.next_height;
        self.next_height = self.next_height.saturating_add(1);
        self.pending.push_back(Pending {
            round,
            order_len,
            height,
            state_root: None,
            applied: 0,
        });
        height
    }

    /// Captures the state at a committed prefix.
    ///
    /// Every pending header whose `order_len` matches this applied cursor gets
    /// the same root. That covers several commits that added no entries.
    pub fn mark_applied(&mut self, order_len: usize, state_root: [u8; 32], applied: u64) {
        for pending in &mut self.pending {
            if pending.order_len == order_len && pending.state_root.is_none() {
                pending.state_root = Some(state_root);
                pending.applied = applied;
            }
        }
    }

    /// Builds every pending header whose state is available, signs the ones this
    /// node may sign, and returns the shares plus any certificates that became
    /// complete.
    ///
    /// `order` is the full committed order; only its prefix at each pending
    /// header's `order_len` is read.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::InvalidVertex`] when a pending prefix is longer than
    /// `order`, and every error from signing, certificate verification, or chain
    /// advance.
    pub fn build_ready(&mut self, order: &[VertexId], at: u64) -> Result<Build, CryptoError> {
        let mut shares = Vec::new();
        while self
            .pending
            .front()
            .is_some_and(|pending| pending.state_root.is_some())
        {
            let pending = self
                .pending
                .pop_front()
                .ok_or_else(|| invalid("the pending header disappeared"))?;
            let state_root = pending
                .state_root
                .ok_or_else(|| invalid("a pending header lost its state root"))?;
            if pending.order_len > order.len() {
                return Err(invalid(format!(
                    "header {} covers {} commits, but the order has {}",
                    pending.height,
                    pending.order_len,
                    order.len()
                )));
            }
            let epoch = self.schedule.epoch_of(pending.round);
            let header = Header {
                chain_id: self.chain_id.clone(),
                epoch,
                height: pending.height,
                round: pending.round,
                state_root,
                dag_root: commit_root(&order[..pending.order_len]),
                previous: self.last_built.id()?,
                applied: pending.applied,
            };
            let id = header.id()?;

            if let Some(certified) = self.certified_ids.get(&pending.height)
                && *certified != id
            {
                self.conflicts = self.conflicts.saturating_add(1);
            }

            self.order_lens.insert(id, pending.order_len);
            self.last_built = header.clone();
            self.last_built_order = pending.order_len;
            self.built = self.built.saturating_add(1);

            let set = self.sets.set_for_epoch(epoch);
            if let Some(signer) = set
                .validators
                .iter()
                .position(|record| record.validator_id == self.signer)
            {
                let payload = signing_payload(&header)?;
                let signature = Ed25519Scheme.sign(&self.private_key, &payload)?;
                let entry = self.shares.entry(id).or_insert_with(|| ShareSet {
                    header: header.clone(),
                    signatures: BTreeMap::new(),
                });
                entry.signatures.entry(signer).or_insert_with(|| Signed {
                    signature: signature.clone(),
                    at,
                });
                shares.push(Share {
                    header,
                    signer,
                    signature,
                    at,
                });
            }
        }

        let certified = self.advance_certified()?;
        Ok(Build { shares, certified })
    }

    /// Accepts one share and returns the certificates it completes.
    ///
    /// A share for another chain or from an index outside the header's set is a
    /// conflict and is ignored. A share at or below the certified head is a
    /// duplicate and is ignored.
    ///
    /// # Errors
    ///
    /// Every error from header id, certificate verification, or chain advance.
    pub fn receive_share(&mut self, share: Share) -> Result<Vec<Certified>, CryptoError> {
        let Share {
            header,
            signer,
            signature,
            at,
        } = share;
        if header.chain_id != self.chain_id {
            self.conflicts = self.conflicts.saturating_add(1);
            return Ok(Vec::new());
        }
        if signer >= self.sets.set_for_epoch(header.epoch).validators.len() {
            self.conflicts = self.conflicts.saturating_add(1);
            return Ok(Vec::new());
        }
        if header.height <= self.chain.head().height {
            return Ok(Vec::new());
        }
        let id = header.id()?;
        let entry = self.shares.entry(id).or_insert_with(|| ShareSet {
            header,
            signatures: BTreeMap::new(),
        });
        entry
            .signatures
            .entry(signer)
            .or_insert(Signed { signature, at });
        self.advance_certified()
    }

    /// Adopts a certified header above the current head, as a tail replay does.
    ///
    /// # Errors
    ///
    /// Every error from [`HeaderChain::advance`].
    pub fn adopt_certified(
        &mut self,
        header: Header,
        certificate: Certificate,
    ) -> Result<(), CryptoError> {
        self.chain.advance(&header, &certificate)?;
        let id = header.id()?;
        self.certified_ids.insert(header.height, id);
        Ok(())
    }

    /// Replaces the trusted anchor with a snapshot's certified header.
    ///
    /// A joining node cannot advance from genesis to a distant header without the
    /// headers in between, so it verifies the quorum certificate over the anchor
    /// once and starts its chain there. `anchor_order_len` is the committed prefix
    /// the anchor covers.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::HeaderMismatch`] when the certificate does not name the
    /// anchor, every error from [`Certificate::verify_quorum`], header id encoding,
    /// and [`HeaderChain::with_schedule_and_change`] for an inconsistent schedule.
    pub fn adopt_anchor(
        &mut self,
        anchor: Header,
        certificate: &Certificate,
        anchor_order_len: usize,
    ) -> Result<(), CryptoError> {
        let id = anchor.id()?;
        if certificate.chain_id != anchor.chain_id
            || certificate.epoch != anchor.epoch
            || certificate.round != anchor.round
            || certificate.vertex_id != id
        {
            return Err(CryptoError::new(
                CryptoErrorKind::HeaderMismatch,
                "certificate does not name the snapshot anchor",
            ));
        }
        certificate.verify_quorum(self.sets.set_for_epoch(anchor.epoch))?;
        self.chain = match self.sets.change_epoch() {
            Some(change_epoch) => HeaderChain::with_schedule_and_change(
                self.sets.base().clone(),
                self.sets.set_for_epoch(change_epoch).clone(),
                change_epoch,
                anchor.clone(),
                self.schedule,
            )?,
            None => {
                HeaderChain::with_schedule(self.sets.base().clone(), anchor.clone(), self.schedule)
            }
        };
        self.last_built = anchor.clone();
        self.last_built_order = anchor_order_len;
        self.next_height = anchor.height.saturating_add(1);
        self.pending.clear();
        self.shares.clear();
        self.certified_ids.clear();
        self.certified_ids.insert(anchor.height, id);
        self.order_lens.clear();
        self.certified_orders.clear();
        self.certified_orders
            .insert(anchor.height, anchor_order_len);
        Ok(())
    }

    /// Continues above the certified head after a restart.
    ///
    /// The store persisted the certified chain, not every built header. The next
    /// header therefore extends the certified head, and a commit that was built
    /// but not certified before the restart is covered by that next header. The
    /// order length at the head is not persisted: the live node does not serve a
    /// snapshot from it yet, and a tail snapshot will carry it explicitly.
    pub fn resume_from_head(&mut self) {
        self.last_built = self.chain.head().clone();
        self.last_built_order = 0;
        self.next_height = self.last_built.height.saturating_add(1);
    }

    /// Verifies a certificate against a header without advancing the chain.
    ///
    /// This is what a joining node uses to check the snapshot anchor when the
    /// peer still had its certificate.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::HeaderMismatch`] when the certificate names another
    /// object, and every error from [`Certificate::verify_quorum`].
    pub fn verify_certificate(
        &self,
        header: &Header,
        certificate: &Certificate,
    ) -> Result<(), CryptoError> {
        if certificate.chain_id != header.chain_id
            || certificate.epoch != header.epoch
            || certificate.round != header.round
            || certificate.vertex_id != header.id()?
        {
            return Err(CryptoError::new(
                CryptoErrorKind::HeaderMismatch,
                "certificate does not name the header it is attached to",
            ));
        }
        certificate
            .verify_quorum(self.sets.set_for_epoch(header.epoch))
            .map(|_| ())
    }

    fn advance_certified(&mut self) -> Result<Vec<Certified>, CryptoError> {
        let mut certified = Vec::new();
        loop {
            let height = self.chain.head().height.saturating_add(1);
            let previous = self.chain.head().id()?;
            let Some((id, header, mut signed)) = self.candidate(height, previous) else {
                break;
            };
            let at = signed.iter().map(|(_, _, at)| *at).max().unwrap_or(0);
            signed.sort_by_key(|(index, _, _)| *index);

            let set = self.sets.set_for_epoch(header.epoch);
            let mut bitmap = vec![0u8; bitmap_len(set.validators.len())];
            for (index, _, _) in &signed {
                set_bit(&mut bitmap, *index);
            }
            let certificate = Certificate {
                chain_id: header.chain_id.clone(),
                epoch: header.epoch,
                round: header.round,
                vertex_id: id.to_vec(),
                validator_set_id: VALIDATOR_SET_ID.to_vec(),
                signer_bitmap: bitmap,
                signatures: signed
                    .into_iter()
                    .map(|(_, signature, _)| signature)
                    .collect(),
            };
            certificate.verify_quorum(set)?;
            self.chain.advance(&header, &certificate)?;
            self.certified_ids.insert(height, id);
            if let Some(order_len) = self.order_lens.remove(&id) {
                self.certified_orders.insert(height, order_len);
            }
            certified.push(Certified {
                header,
                certificate,
                at,
            });
        }
        Ok(certified)
    }

    fn candidate(&self, height: u64, previous: [u8; 32]) -> Option<Candidate> {
        for (id, collected) in &self.shares {
            if collected.header.height != height || collected.header.previous != previous {
                continue;
            }
            let quorum = self
                .sets
                .set_for_epoch(collected.header.epoch)
                .quorum_size();
            if collected.signatures.len() < quorum {
                continue;
            }
            // The certificate exists from the moment the earliest quorum does,
            // not when the last late signature arrives.
            let mut signed: Vec<SignedShare> = collected
                .signatures
                .iter()
                .map(|(index, signed)| (*index, signed.signature.clone(), signed.at))
                .collect();
            signed.sort_by_key(|(_, _, at)| *at);
            signed.truncate(quorum);
            return Some((*id, collected.header.clone(), signed));
        }
        None
    }
}

/// The bytes a certificate share signs.
///
/// The bitmap and the signatures are not part of it, so the same payload covers
/// every signer of one header.
///
/// # Errors
///
/// Every error from header id encoding and certificate payload encoding.
pub fn signing_payload(header: &Header) -> Result<Vec<u8>, CryptoError> {
    Certificate {
        chain_id: header.chain_id.clone(),
        epoch: header.epoch,
        round: header.round,
        vertex_id: header.id()?.to_vec(),
        validator_set_id: VALIDATOR_SET_ID.to_vec(),
        signer_bitmap: Vec::new(),
        signatures: Vec::new(),
    }
    .signing_payload()
}

fn invalid(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::InvalidVertex, detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord, ValidatorSet};
    use crypto::registry::ALG_ED25519;

    fn keypair(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let seed = [seed; 32];
        let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
        let mut private = seed.to_vec();
        private.extend_from_slice(&public);
        (public.to_vec(), private)
    }

    fn fixture(count: usize) -> (ValidatorSet, Vec<Vec<u8>>) {
        let mut validators = Vec::with_capacity(count);
        let mut keys = Vec::with_capacity(count);
        for index in 0..count {
            let (public, private) = keypair(u8::try_from(index + 1).unwrap());
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: public,
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
            keys.push(private);
        }
        let set = ValidatorSet {
            epoch: 1,
            validators,
        };
        (set, keys)
    }

    fn genesis(chain_id: &[u8], state_root: [u8; 32]) -> Header {
        Header::genesis(chain_id.to_vec(), 1, state_root, commit_root(&[]))
    }

    fn order_entry(round: u64, author: &[u8]) -> VertexId {
        VertexId {
            round,
            author: author.to_vec(),
            digest: [round as u8; 32],
        }
    }

    #[test]
    fn a_commit_becomes_a_header_and_a_quorum_certifies_it() {
        let (set, keys) = fixture(4);
        let sets = SetSchedule::single(set.clone());
        let schedule = EpochSchedule::single(1);
        let chain_id = b"karsa-test-1".to_vec();
        let anchor = genesis(&chain_id, [0u8; 32]);
        let mut finalizer = Finalizer::new(
            sets,
            schedule,
            chain_id,
            b"val-0".to_vec(),
            keys[0].clone(),
            anchor,
            0,
        )
        .unwrap();

        finalizer.record_commit(1, 1);
        finalizer.mark_applied(1, [7u8; 32], 1);
        let order = vec![order_entry(1, b"val-0")];
        let build = finalizer.build_ready(&order, 10).unwrap();
        assert_eq!(build.shares.len(), 1, "the active validators signs");
        let header = build.shares[0].header.clone();
        assert_eq!(header.height, 1);
        assert_eq!(header.state_root, [7u8; 32]);
        assert_eq!(header.applied, 1);
        assert!(build.certified.is_empty(), "one share is not a quorum");

        let payload = signing_payload(&header).unwrap();
        for (signer, key) in keys.iter().enumerate().take(3).skip(1) {
            let signature = Ed25519Scheme.sign(key, &payload).unwrap();
            finalizer
                .receive_share(Share {
                    header: header.clone(),
                    signer,
                    signature,
                    at: 10 + signer as u64,
                })
                .unwrap();
        }
        assert_eq!(finalizer.head().height, 1, "three of four certify");
        assert!(finalizer.is_certified(1));
        assert_eq!(finalizer.conflicts(), 0);
    }

    #[test]
    fn a_share_from_an_unknown_signer_is_a_conflict() {
        let (set, keys) = fixture(4);
        let sets = SetSchedule::single(set.clone());
        let schedule = EpochSchedule::single(1);
        let chain_id = b"karsa-test-1".to_vec();
        let anchor = genesis(&chain_id, [0u8; 32]);
        let mut finalizer = Finalizer::new(
            sets,
            schedule,
            chain_id,
            b"val-0".to_vec(),
            keys[0].clone(),
            anchor,
            0,
        )
        .unwrap();
        finalizer.record_commit(1, 1);
        finalizer.mark_applied(1, [7u8; 32], 1);
        let order = vec![order_entry(1, b"val-0")];
        let header = finalizer.build_ready(&order, 10).unwrap().shares[0]
            .header
            .clone();
        let payload = signing_payload(&header).unwrap();
        let signature = Ed25519Scheme.sign(&keys[1], &payload).unwrap();
        finalizer
            .receive_share(Share {
                header,
                signer: 9,
                signature,
                at: 11,
            })
            .unwrap();
        assert_eq!(finalizer.conflicts(), 1);
        assert_eq!(finalizer.head().height, 0);
    }

    #[test]
    fn a_share_for_another_chain_is_a_conflict() {
        let (set, keys) = fixture(4);
        let sets = SetSchedule::single(set.clone());
        let schedule = EpochSchedule::single(1);
        let chain_id = b"karsa-test-1".to_vec();
        let anchor = genesis(&chain_id, [0u8; 32]);
        let mut finalizer = Finalizer::new(
            sets,
            schedule,
            chain_id,
            b"val-0".to_vec(),
            keys[0].clone(),
            anchor,
            0,
        )
        .unwrap();
        let foreign = genesis(b"karsa-test-2", [0u8; 32]);
        finalizer
            .receive_share(Share {
                header: foreign,
                signer: 1,
                signature: vec![0u8; 64],
                at: 1,
            })
            .unwrap();
        assert_eq!(finalizer.conflicts(), 1);
    }

    #[test]
    fn a_header_cannot_cover_more_commits_than_the_order_holds() {
        let (set, keys) = fixture(4);
        let sets = SetSchedule::single(set.clone());
        let schedule = EpochSchedule::single(1);
        let chain_id = b"karsa-test-1".to_vec();
        let anchor = genesis(&chain_id, [0u8; 32]);
        let mut finalizer = Finalizer::new(
            sets,
            schedule,
            chain_id,
            b"val-0".to_vec(),
            keys[0].clone(),
            anchor,
            0,
        )
        .unwrap();
        finalizer.record_commit(1, 2);
        finalizer.mark_applied(2, [7u8; 32], 2);
        let error = finalizer.build_ready(&[], 10).unwrap_err();
        assert!(error.to_string().contains("covers"), "{error}");
    }
}
