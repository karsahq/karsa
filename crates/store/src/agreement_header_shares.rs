//! Bounded durable completed header shares, pinned to existing pre-sign intents.

use super::*;
use crypto::scheme::{Ed25519Scheme, SignatureScheme};
use validator::Share;

const FILE: &str = "agreement-header-shares";
const TEMPORARY_FILE: &str = "agreement-header-shares.tmp";
const DOMAIN: &[u8] = b"KARSA/STORE/AGREEMENT_HEADER_SHARES/v1";
// Whole-file replacement has a hard lifetime bound; records are never pruned.
const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Operation boundaries in the real share publication pipeline (test support only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharePublicationStage {
    /// Before writing the temporary file.
    Write,
    /// After writing, before syncing the temporary file.
    FileSync,
    /// After syncing, before renaming the temporary file.
    Rename,
    /// After rename, before each directory durability barrier.
    DirectorySync,
}

struct Journal {
    bootstrap: Vec<u8>,
    anchor: Header,
    shares: Vec<Share>,
}

impl Journal {
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if self.shares.is_empty() || self.shares.len() > MAX_EVENTS {
            return Err(invalid("invalid header share count"));
        }
        let mut e = Encoder::new();
        e.put_bytes(DOMAIN)?;
        e.put_bytes(&self.bootstrap)?;
        e.put_bytes(&self.anchor.encode()?)?;
        e.put_u32(self.shares.len() as u32);
        for share in &self.shares {
            e.put_bytes(&share.header.encode()?)?;
            e.put_u64(share.signer as u64);
            e.put_bytes(&share.signature)?;
            e.put_u64(share.at);
        }
        let checksum = digest(&[0; 32], 0, e.as_slice());
        e.put_raw(&checksum);
        if e.as_slice().len() as u64 > MAX_BYTES {
            return Err(invalid("header shares exceed byte bound"));
        }
        Ok(e.finish())
    }

    fn validate(
        &self,
        bootstrap: &[u8],
        intents: &header_intents::Journal,
    ) -> Result<(), StoreError> {
        if self.bootstrap != bootstrap || self.anchor != intents.anchor {
            return Err(invalid("header share bootstrap or anchor mismatch"));
        }
        let bootstrap = AuthenticatedSlotAgreementBootstrap::decode(bootstrap)?;
        let set = &bootstrap.agreement.set;
        let mut previous = None;
        for share in &self.shares {
            let identity = (share.header.height, share.signer);
            if previous.is_some_and(|old| old >= identity) {
                return Err(invalid("header shares are not uniquely ordered"));
            }
            previous = Some(identity);
            let index = usize::try_from(share.header.height)
                .ok()
                .and_then(|height| height.checked_sub(1))
                .ok_or_else(|| invalid("invalid header share height"))?;
            if intents.intents.get(index).map(|intent| intent.header()) != Some(&share.header) {
                return Err(invalid("header share has no exact reserved intent"));
            }
            if share.header.epoch != set.epoch || share.signature.len() != 64 {
                return Err(invalid("invalid header share epoch or signature size"));
            }
            let signer = set
                .validators
                .get(share.signer)
                .ok_or_else(|| invalid("header share signer outside pinned set"))?;
            let key = signer.active_key(share.header.epoch)?;
            if key.algorithm_id != crypto::registry::ALG_ED25519 {
                return Err(invalid("header shares require an active Ed25519 key"));
            }
            Ed25519Scheme.verify(
                &key.public_key,
                &validator::signing_payload(&share.header)?,
                &share.signature,
            )?;
        }
        Ok(())
    }
}

fn read_shares(root: &Path) -> Result<Option<Journal>, StoreError> {
    let path = root.join(FILE);
    validate_pointer_file(&path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_BYTES {
        return Err(invalid("header shares exceed byte bound"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() < 32 || bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("invalid header share journal size"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if checksum != digest(&[0; 32], 0, body) {
        return Err(invalid("header share checksum mismatch"));
    }
    let mut d = Decoder::new(body);
    if d.read_bytes()? != DOMAIN {
        return Err(invalid("unknown header share version"));
    }
    let bootstrap = d.read_bytes()?.to_vec();
    let anchor = Header::decode(d.read_bytes()?)?;
    let count = d.read_u32()? as usize;
    if count == 0 || count > MAX_EVENTS {
        return Err(invalid("invalid header share count"));
    }
    let mut shares = Vec::with_capacity(count);
    for _ in 0..count {
        shares.push(Share {
            header: Header::decode(d.read_bytes()?)?,
            signer: usize::try_from(d.read_u64()?).map_err(|_| invalid("share signer overflow"))?,
            signature: d.read_bytes()?.to_vec(),
            at: d.read_u64()?,
        });
    }
    d.finish()?;
    let journal = Journal {
        bootstrap,
        anchor,
        shares,
    };
    if journal.encode()? != bytes {
        return Err(invalid("noncanonical header share journal"));
    }
    Ok(Some(journal))
}

impl AuthenticatedSlotAgreement {
    /// Loads completed shares verified against exact intents and the pinned bootstrap set.
    /// Missing journals return an empty list; absence does not prove no share was signed.
    /// Reads validate visible records but do not repeat publication durability barriers.
    /// This is not a finality certificate or execution/finalizer recovery checkpoint.
    /// # Errors
    /// Rejects stale/uncertain ownership, corruption, invalid signatures and incompatible history.
    pub fn header_shares(&self) -> Result<Vec<Share>, StoreError> {
        let snapshot = self.ordering_snapshot()?;
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        self.check_checkpoint_owner(&root)?;
        let Some(journal) = read_shares(&root)? else {
            return Ok(Vec::new());
        };
        let intents = header_intents::read_intents(&root)?
            .ok_or_else(|| invalid("header shares require existing intents"))?;
        intents.validate(&self.header, &snapshot)?;
        journal.validate(&self.header, &intents)?;
        Ok(journal.shares)
    }

    /// Durably records an Ed25519 share for an exact existing header intent.
    /// The genesis anchor is caller-trusted, as with `reserve_header`; signatures are
    /// verified using the pinned bootstrap set. Unsupported keys are rejected, not trusted.
    /// Exact duplicates (including timestamp) repeat all durability barriers. Conflicts
    /// at the same height/signer are rejected. Records are bounded and never pruned.
    /// # Errors
    /// Rejects invalid records, missing intents, conflicts, exhaustion and stale ownership.
    /// Publication failure makes this owner uncertain and requires recovery.
    pub fn reserve_header_share(
        &mut self,
        anchor: &Header,
        share: &Share,
    ) -> Result<(), StoreError> {
        #[cfg(feature = "test-support")]
        {
            let fault = match self.share_publication_fault.as_mut() {
                Some((_, remaining)) if *remaining > 0 => {
                    *remaining -= 1;
                    None
                }
                Some(_) => self.share_publication_fault.take().map(|(stage, _)| stage),
                None => None,
            };
            self.reserve_header_share_with_io(anchor, share, |root, bytes| {
                publish_with(root, bytes, |stage| {
                    if Some(stage) == fault {
                        return Err(std::io::Error::other(format!(
                            "injected share publication {stage:?} failure"
                        ))
                        .into());
                    }
                    Ok(())
                })
            })
        }
        #[cfg(not(feature = "test-support"))]
        self.reserve_header_share_with_io(anchor, share, publish)
    }

    /// Arms a one-shot owner-local fault after `skip` share publication calls.
    /// Only available with `test-support`; does not repair an uncertain owner.
    #[cfg(feature = "test-support")]
    pub fn fail_share_publication(&mut self, stage: SharePublicationStage, skip: usize) {
        self.share_publication_fault = Some((stage, skip));
    }

    fn reserve_header_share_with_io(
        &mut self,
        anchor: &Header,
        share: &Share,
        publish: impl FnOnce(&Path, &[u8]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let snapshot = self.ordering_snapshot()?;
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        self.check_checkpoint_owner(&root)?;
        let intents = header_intents::read_intents(&root)?
            .ok_or_else(|| invalid("header shares require existing intents"))?;
        intents.validate(&self.header, &snapshot)?;
        let mut journal = read_shares(&root)?.unwrap_or_else(|| Journal {
            bootstrap: self.header.clone(),
            anchor: anchor.clone(),
            shares: Vec::new(),
        });
        journal.validate(&self.header, &intents)?;
        if &journal.anchor != anchor {
            return Err(invalid("header share genesis anchor changed"));
        }
        let identity = (share.header.height, share.signer);
        match journal
            .shares
            .binary_search_by_key(&identity, |old| (old.header.height, old.signer))
        {
            Ok(index) if journal.shares[index] != *share => {
                return Err(invalid("conflicting header share"));
            }
            Ok(_) => {} // Visible sibling publication may still lack its directory barrier.
            Err(index) => {
                if journal.shares.len() >= MAX_EVENTS {
                    return Err(invalid("header share count exceeds bound"));
                }
                journal.shares.insert(index, share.clone());
            }
        }
        journal.validate(&self.header, &intents)?;
        let bytes = journal.encode()?;
        validate_pointer_file(&root.join(TEMPORARY_FILE))?;
        let result = publish(&root, &bytes);
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
}

#[cfg(not(feature = "test-support"))]
fn publish(root: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    publish_with(root, bytes, |_| Ok(()))
}

fn publish_with(
    root: &Path,
    bytes: &[u8],
    mut before: impl FnMut(SharePublicationStage) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let temporary = root.join(TEMPORARY_FILE);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    before(SharePublicationStage::Write)?;
    file.write_all(bytes)?;
    before(SharePublicationStage::FileSync)?;
    file.sync_all()?;
    before(SharePublicationStage::Rename)?;
    fs::rename(&temporary, root.join(FILE))?;
    slot_decision_journal::sync_ancestors(root, |path| {
        before(SharePublicationStage::DirectorySync)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        File::open(path)?.sync_all()
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_application_tests::TempDir;

    fn share(header: Header) -> Share {
        let seed = [1; 32];
        let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
        let key = [seed.as_slice(), public.as_slice()].concat();
        let signature = Ed25519Scheme
            .sign(&key, &validator::signing_payload(&header).unwrap())
            .unwrap();
        Share {
            header,
            signer: 0,
            signature,
            at: 17,
        }
    }

    #[test]
    fn durable_shares_require_intents_and_reject_conflicts_and_corruption() {
        let dir = TempDir::new();
        let (mut store, mut owner, bootstrap, anchor, header) =
            header_intents::tests::fixture(&dir, true);
        let share = share(header.clone());
        assert!(owner.header_shares().unwrap().is_empty());
        assert!(owner.reserve_header_share(&anchor, &share).is_err());
        owner
            .reserve_header(
                &anchor,
                &header,
                owner.ordering_snapshot().unwrap().order().len(),
            )
            .unwrap();
        let mut bad = share.clone();
        bad.signature[0] ^= 1;
        assert!(owner.reserve_header_share(&anchor, &bad).is_err());
        owner.reserve_header_share(&anchor, &share).unwrap();
        owner.reserve_header_share(&anchor, &share).unwrap();
        bad = share.clone();
        bad.at += 1;
        assert!(owner.reserve_header_share(&anchor, &bad).is_err());
        let staged = store.stage().unwrap();
        assert!(!staged.store().root.join(FILE).exists());
        staged.activate().unwrap();
        drop(owner);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(owner.header_shares().unwrap(), vec![share]);
        let path = dir.0.join(FILE);
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(owner.header_shares().is_err());
    }

    #[test]
    fn driver_forwarding_rejects_invalid_anchors_and_missing_intents() {
        let dir = TempDir::new();
        let (_store, mut owner, _, anchor, header) = header_intents::tests::fixture(&dir, true);
        owner
            .reserve_header(
                &anchor,
                &header,
                owner.ordering_snapshot().unwrap().order().len(),
            )
            .unwrap();
        let mut driver = crate::SlotAgreementDriver::new(owner);
        let share = share(header);
        assert!(driver.header_shares().unwrap().is_empty());
        let mut wrong_anchor = anchor.clone();
        wrong_anchor.state_root[0] ^= 1;
        assert!(driver.reserve_header_share(&wrong_anchor, &share).is_err());
        assert!(!dir.0.join(FILE).exists());
        driver.reserve_header_share(&anchor, &share).unwrap();
        assert!(driver.reserve_header_share(&wrong_anchor, &share).is_err());
        assert_eq!(driver.header_shares().unwrap(), vec![share.clone()]);
        let intents_path = dir.0.join("agreement-header-intents");
        let intents = fs::read(&intents_path).unwrap();
        fs::remove_file(&intents_path).unwrap();
        assert!(driver.header_shares().is_err());
        assert!(driver.reserve_header_share(&anchor, &share).is_err());
        fs::write(intents_path, intents).unwrap();
        assert_eq!(driver.header_shares().unwrap(), vec![share]);
    }

    #[test]
    fn publication_failures_poison_owner_and_duplicates_repeat_sibling_barrier() {
        for failure in [
            SharePublicationStage::Write,
            SharePublicationStage::FileSync,
            SharePublicationStage::Rename,
            SharePublicationStage::DirectorySync,
        ] {
            let dir = TempDir::new();
            let (store, mut owner, bootstrap, anchor, header) =
                header_intents::tests::fixture(&dir, true);
            owner
                .reserve_header(
                    &anchor,
                    &header,
                    owner.ordering_snapshot().unwrap().order().len(),
                )
                .unwrap();
            let share = share(header);
            let mut sibling = store
                .recover_authenticated_slot_agreement(bootstrap)
                .unwrap();
            assert!(
                owner
                    .reserve_header_share_with_io(&anchor, &share, |root, bytes| {
                        publish_with(root, bytes, |stage| {
                            if stage == failure {
                                Err(std::io::Error::other("injected publication failure").into())
                            } else {
                                Ok(())
                            }
                        })
                    })
                    .is_err()
            );
            assert_eq!(
                dir.0.join(FILE).exists(),
                failure == SharePublicationStage::DirectorySync
            );
            assert!(owner.header_shares().is_err());
            assert!(owner.reserve_header_share(&anchor, &share).is_err());
            let mut stages = Vec::new();
            sibling
                .reserve_header_share_with_io(&anchor, &share, |root, bytes| {
                    publish_with(root, bytes, |stage| {
                        stages.push(stage);
                        Ok(())
                    })
                })
                .unwrap();
            assert_eq!(
                &stages[..3],
                &[
                    SharePublicationStage::Write,
                    SharePublicationStage::FileSync,
                    SharePublicationStage::Rename
                ]
            );
            assert!(
                stages[3..]
                    .iter()
                    .all(|stage| *stage == SharePublicationStage::DirectorySync)
            );
            assert!(stages.len() > 3);
            assert!(owner.reserve_header_share(&anchor, &share).is_err());
            assert_eq!(sibling.header_shares().unwrap(), vec![share]);
        }
    }
}
