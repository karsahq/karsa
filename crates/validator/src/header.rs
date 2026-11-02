//! Committed-state headers and the finality certificate that names them.
//!
//! The DAG decides *order*. It never decides *state*: a node can compute the
//! account root after applying a commit, but nothing in the commit rules binds
//! that root for anyone else. A header does that, and a quorum signature over the
//! header identifier is what turns "my node computed this" into "this chain
//! agreed on this".
//!
//! The header is never signed directly. Its identifier is a domain-separated hash
//! of its fields, and a finality certificate is the existing [`Certificate`] — a
//! bitmap and one signature per signer over `(chain_id, epoch, round, id)`. The
//! certificate costs `n` signatures but is produced once per commit rather than
//! once per round, which is why it is affordable where a per-round certificate was
//! not (§8.6 of the registry prices the difference).
//!
//! [`HeaderChain`] is the verifier a light client runs: it holds a trusted header
//! and accepts the next one only when it extends that header, the certificate
//! names it, and a supermajority of the epoch's validators signed.

use crypto::domain::{HeaderFields, encode_header_payload};
use crypto::encoding::{Decoder, Encoder};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::certificate::Certificate;
use crate::schedule::ValidatorSet;

/// Canonical header encoding version.
pub const HEADER_VERSION_V1: u16 = 1;

/// The state a chain agreed on at one height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Chain identifier.
    pub chain_id: Vec<u8>,
    /// Epoch the header was produced in.
    pub epoch: u64,
    /// Monotone height, starting at 0 for the genesis header.
    pub height: u64,
    /// DAG round whose commits this header covers.
    pub round: u64,
    /// Merkle root of the account state.
    pub state_root: [u8; 32],
    /// Merkle root over the committed vertices, in commit order.
    ///
    /// This is what lets a client check that a vertex was part of the commit the
    /// header names, instead of having to trust the node that told it.
    pub dag_root: [u8; 32],
    /// Identifier of the previous header, all zero at genesis.
    pub previous: [u8; 32],
    /// Cumulative transactions applied at this height.
    pub applied: u64,
}

fn header_mismatch(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::HeaderMismatch, detail)
}

fn read_digest(decoder: &mut Decoder<'_>) -> Result<[u8; 32], CryptoError> {
    let bytes = decoder.read_bytes()?;
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::TruncatedInput,
            format!("expected 32 bytes, found {}", bytes.len()),
        )
    })
}

impl Header {
    /// The genesis header: height 0, no predecessor, no transactions applied.
    #[must_use]
    pub fn genesis(
        chain_id: Vec<u8>,
        epoch: u64,
        state_root: [u8; 32],
        dag_root: [u8; 32],
    ) -> Self {
        Self {
            chain_id,
            epoch,
            height: 0,
            round: 0,
            state_root,
            dag_root,
            previous: [0u8; 32],
            applied: 0,
        }
    }

    fn fields(&self) -> HeaderFields<'_> {
        HeaderFields {
            chain_id: &self.chain_id,
            epoch: self.epoch,
            height: self.height,
            round: self.round,
            state_root: &self.state_root,
            dag_root: &self.dag_root,
            previous: &self.previous,
            applied: self.applied,
        }
    }

    /// The identifier a certificate names.
    ///
    /// # Errors
    ///
    /// Returns an error only when a field exceeds the encoding limit.
    pub fn id(&self) -> Result<[u8; 32], CryptoError> {
        Ok(Sha256::digest(encode_header_payload(&self.fields())?).into())
    }

    /// Writes the canonical header encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::FieldTooLong`] for an oversized field.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoder = Encoder::with_capacity(96 + self.chain_id.len());
        encoder.put_u16(HEADER_VERSION_V1);
        encoder.put_bytes(&self.chain_id)?;
        encoder.put_u64(self.epoch);
        encoder.put_u64(self.height);
        encoder.put_u64(self.round);
        encoder.put_bytes(&self.state_root)?;
        encoder.put_bytes(&self.dag_root)?;
        encoder.put_bytes(&self.previous)?;
        encoder.put_u64(self.applied);
        Ok(encoder.finish())
    }

    /// Reads a canonical header encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TruncatedInput`],
    /// [`CryptoErrorKind::TrailingBytes`], or
    /// [`CryptoErrorKind::MalformedCertificate`] for an unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != HEADER_VERSION_V1 {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedCertificate,
                format!("unsupported header version {version}"),
            ));
        }
        let chain_id = decoder.read_bytes()?.to_vec();
        let epoch = decoder.read_u64()?;
        let height = decoder.read_u64()?;
        let round = decoder.read_u64()?;
        let state_root = read_digest(&mut decoder)?;
        let dag_root = read_digest(&mut decoder)?;
        let previous = read_digest(&mut decoder)?;
        let applied = decoder.read_u64()?;
        decoder.finish()?;
        Ok(Self {
            chain_id,
            epoch,
            height,
            round,
            state_root,
            dag_root,
            previous,
            applied,
        })
    }
}

/// The verifier a light client runs over a chain of headers.
///
/// It holds one trusted header and accepts a successor only when every link
/// checks. It never needs the DAG, the transactions, or the account state.
#[derive(Debug, Clone)]
pub struct HeaderChain {
    set: ValidatorSet,
    head: Header,
}

impl HeaderChain {
    /// Starts a verifier from a trusted header.
    #[must_use]
    pub fn new(set: ValidatorSet, genesis: Header) -> Self {
        Self { set, head: genesis }
    }

    /// The header currently trusted.
    #[must_use]
    pub fn head(&self) -> &Header {
        &self.head
    }

    /// The validator set keys are resolved against.
    #[must_use]
    pub fn set(&self) -> &ValidatorSet {
        &self.set
    }

    /// Accepts `header` when it extends the trusted head and `certificate` names it.
    ///
    /// The cheap structural checks run first and signature verification last, so a
    /// forged link never costs a verification.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::HeaderMismatch`] when the header does not extend the head
    /// or the certificate names a different object, and every error from
    /// [`Certificate::verify_quorum`], which includes
    /// [`CryptoErrorKind::PolicyUnsatisfied`] when too few validators signed.
    pub fn advance(
        &mut self,
        header: &Header,
        certificate: &Certificate,
    ) -> Result<(), CryptoError> {
        if header.chain_id != self.head.chain_id {
            return Err(header_mismatch("header is for another chain"));
        }
        if header.epoch != self.head.epoch {
            return Err(header_mismatch(format!(
                "header epoch {} is not the trusted epoch {}",
                header.epoch, self.head.epoch
            )));
        }
        if header.height != self.head.height.saturating_add(1) {
            return Err(header_mismatch(format!(
                "header height {} does not follow {}",
                header.height, self.head.height
            )));
        }
        let previous = self.head.id()?;
        if header.previous != previous {
            return Err(header_mismatch(
                "header does not name the trusted head as its predecessor",
            ));
        }

        let id = header.id()?;
        if certificate.chain_id != header.chain_id {
            return Err(header_mismatch("certificate is for another chain"));
        }
        if certificate.epoch != header.epoch {
            return Err(header_mismatch("certificate is for another epoch"));
        }
        if certificate.round != header.round {
            return Err(header_mismatch("certificate is for another round"));
        }
        if certificate.vertex_id != id {
            return Err(header_mismatch(
                "certificate names a different header identifier",
            ));
        }

        certificate.verify_quorum(&self.set)?;
        self.head = header.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::bitmap_of;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    const EPOCH: u64 = 1;
    const COUNT: usize = 4;

    struct Fixture {
        keys: Vec<Vec<u8>>,
        set: ValidatorSet,
    }

    fn fixture() -> Fixture {
        let mut keys = Vec::with_capacity(COUNT);
        let mut validators = Vec::with_capacity(COUNT);
        for index in 0..COUNT {
            let seed = [u8::try_from(index + 1).unwrap(); 32];
            let public_key = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
            let mut private_key = Vec::with_capacity(64);
            private_key.extend_from_slice(&seed);
            private_key.extend_from_slice(&public_key);
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: public_key.to_vec(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
            keys.push(private_key);
        }
        let set = ValidatorSet {
            epoch: EPOCH,
            validators,
        };
        set.validate().unwrap();
        Fixture { keys, set }
    }

    impl Fixture {
        fn genesis(&self) -> Header {
            Header::genesis(b"karsa-header-1".to_vec(), EPOCH, [1u8; 32], [2u8; 32])
        }

        fn next(&self, head: &Header, applied: u64) -> Header {
            Header {
                chain_id: head.chain_id.clone(),
                epoch: head.epoch,
                height: head.height + 1,
                round: head.round + 1,
                state_root: [u8::try_from(applied % 256).unwrap(); 32],
                dag_root: [u8::try_from((applied + 1) % 256).unwrap(); 32],
                previous: head.id().unwrap(),
                applied,
            }
        }

        /// Signs `header` with the first `signers` validators.
        fn certify(&self, header: &Header, signers: usize) -> Certificate {
            let mut certificate = Certificate {
                chain_id: header.chain_id.clone(),
                epoch: header.epoch,
                round: header.round,
                vertex_id: header.id().unwrap().to_vec(),
                validator_set_id: b"karsa-header-1/epoch-1".to_vec(),
                signer_bitmap: bitmap_of(COUNT, signers),
                signatures: Vec::new(),
            };
            let payload = certificate.signing_payload().unwrap();
            certificate.signatures = (0..signers)
                .map(|index| Ed25519Scheme.sign(&self.keys[index], &payload).unwrap())
                .collect();
            certificate
        }
    }

    #[test]
    fn a_header_roundtrips_and_its_id_covers_every_field() {
        let fixture = fixture();
        let header = fixture.next(&fixture.genesis(), 8);
        assert_eq!(Header::decode(&header.encode().unwrap()).unwrap(), header);

        let mut changed = header.clone();
        changed.applied += 1;
        assert_ne!(changed.id().unwrap(), header.id().unwrap());
    }

    #[test]
    fn a_certified_header_advances_the_chain() {
        let fixture = fixture();
        let genesis = fixture.genesis();
        let header = fixture.next(&genesis, 8);
        let certificate = fixture.certify(&header, 3);

        let mut chain = HeaderChain::new(fixture.set.clone(), genesis);
        chain.advance(&header, &certificate).unwrap();
        assert_eq!(chain.head(), &header);
    }

    #[test]
    fn too_few_signers_are_refused() {
        let fixture = fixture();
        let genesis = fixture.genesis();
        let header = fixture.next(&genesis, 8);
        let certificate = fixture.certify(&header, 2);

        let mut chain = HeaderChain::new(fixture.set.clone(), genesis);
        let error = chain.advance(&header, &certificate).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
        assert_eq!(chain.head().height, 0);
    }

    #[test]
    fn a_certificate_naming_another_header_is_refused() {
        let fixture = fixture();
        let genesis = fixture.genesis();
        let header = fixture.next(&genesis, 8);
        let mut certificate = fixture.certify(&header, 3);
        certificate.vertex_id = [9u8; 32].to_vec();

        let mut chain = HeaderChain::new(fixture.set.clone(), genesis);
        let error = chain.advance(&header, &certificate).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::HeaderMismatch);
    }

    #[test]
    fn a_header_that_does_not_extend_the_head_is_refused() {
        let fixture = fixture();
        let genesis = fixture.genesis();
        let mut header = fixture.next(&genesis, 8);
        header.previous = [7u8; 32];
        let certificate = fixture.certify(&header, 3);

        let mut chain = HeaderChain::new(fixture.set.clone(), genesis);
        let error = chain.advance(&header, &certificate).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::HeaderMismatch);
    }

    #[test]
    fn a_skipped_height_is_refused() {
        let fixture = fixture();
        let genesis = fixture.genesis();
        let mut header = fixture.next(&genesis, 8);
        header.height = 7;
        let certificate = fixture.certify(&header, 3);

        let mut chain = HeaderChain::new(fixture.set.clone(), genesis);
        let error = chain.advance(&header, &certificate).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::HeaderMismatch);
    }

    #[test]
    fn a_header_cannot_be_replayed_at_the_next_height() {
        let fixture = fixture();
        let genesis = fixture.genesis();
        let first = fixture.next(&genesis, 8);
        let first_certificate = fixture.certify(&first, 3);

        let mut chain = HeaderChain::new(fixture.set.clone(), genesis);
        chain.advance(&first, &first_certificate).unwrap();

        // The same header and certificate again: the height no longer follows.
        let error = chain.advance(&first, &first_certificate).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::HeaderMismatch);
        assert_eq!(chain.head().height, 1);
    }
}
