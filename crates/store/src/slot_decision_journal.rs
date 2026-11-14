//! Irreversible local signing intents, independent of adopted state generations.
//!
//! Durability relies on honored filesystem sync barriers, not resistance to rollback
//! or deletion. A complete-record-boundary truncation cannot be detected.

use super::*;
use validator::SlotDecision;

pub(super) const FILE: &str = "slot-decision-locks";

fn malformed(message: &str) -> StoreError {
    CryptoError::new(crypto::CryptoErrorKind::MalformedCertificate, message).into()
}

pub(super) fn read(root: &Path) -> Result<Vec<SlotDecision>, StoreError> {
    let path = root.join(FILE);
    // Best effort against symlinks, like the store's other layout checks. The
    // directory must remain under the owner's control (not hostile replacement).
    validate_pointer_file(&path)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut locks = BTreeMap::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let header = bytes
            .get(cursor..cursor + 4)
            .ok_or_else(|| malformed("torn slot decision journal length"))?;
        let length = u32::from_le_bytes(header.try_into().expect("four-byte length")) as usize;
        cursor += 4;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| malformed("slot decision journal length overflow"))?;
        let body = bytes
            .get(cursor..end)
            .ok_or_else(|| malformed("torn slot decision journal body"))?;
        let checksum_end = end
            .checked_add(32)
            .ok_or_else(|| malformed("slot decision journal checksum overflow"))?;
        let checksum = bytes
            .get(end..checksum_end)
            .ok_or_else(|| malformed("torn slot decision journal checksum"))?;
        let decision = SlotDecision::decode(body)?;
        if decision.id()?.as_slice() != checksum {
            return Err(malformed("corrupt slot decision journal checksum"));
        }
        let key = (decision.chain_id.clone(), decision.round);
        if let Some(previous) = locks.insert(key, decision.clone()) {
            if previous != decision {
                return Err(malformed("conflicting slot decision journal entries"));
            }
        }
        cursor = checksum_end;
    }
    Ok(locks.into_values().collect())
}

// Persist each newly provisioned directory's entry in its parent, bottom-up.
// Canonicalization also makes relative roots walk all the way to the filesystem root.
pub(super) fn sync_ancestors(
    root: &Path,
    mut sync: impl FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let absolute = fs::canonicalize(root)?;
    for directory in absolute.ancestors() {
        sync(directory)?;
    }
    Ok(())
}

impl Store {
    /// Durably reserves an exact decision before the caller produces any signature.
    ///
    /// This is not a signing API and provides no live consensus safety integration
    /// until callers use it before signing. The logical root's local signing identity
    /// must be fixed externally. Conflicts are keyed only by chain and round: changing
    /// set, epoch, or predecessor cannot bypass a promise. No unlock is provided.
    /// Only encoding structure is checked; set authorization, semantic validity and
    /// predecessor continuity remain the caller's responsibility.
    ///
    /// # Durability assumptions
    /// Success requires the filesystem and storage hardware to honor file and directory
    /// `sync_all` barriers across power loss. After syncing the journal, this syncs the
    /// canonical logical root and every ancestor bottom-up, including the filesystem
    /// root, to persist even a freshly created directory hierarchy. Unsupported directory
    /// syncing is an error, not permission to sign. The directory hierarchy must remain
    /// under the owner's control during these operations.
    ///
    /// This is not protection against storage rollback, deletion of the whole journal,
    /// or truncation at a complete record boundary: those can erase promises without
    /// leaving detectable corruption. Backups/restores and local signing identity must
    /// preserve the journal; filesystem snapshots must not roll it back.
    ///
    /// # Errors
    /// Rejects conflicting decisions, malformed journals (including torn tails), and
    /// filesystem failures. After an I/O error the intent may already exist; callers
    /// must not sign on error. An exact retry revalidates and syncs the entire journal
    /// and all directory ancestors, even if the prior append completed but a sync failed.
    pub fn lock_slot_decision(&self, decision: &SlotDecision) -> Result<(), StoreError> {
        let root = self
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        slot_agreement_journal::exclude_legacy(&root, decision)?;
        let body = decision.encode()?;
        SlotDecision::decode(&body)?;
        let locks = read(&root)?;
        let existing = locks
            .iter()
            .find(|old| old.chain_id == decision.chain_id && old.round == decision.round);
        if existing.is_some_and(|old| old != decision) {
            return Err(malformed("conflicting slot decision intent"));
        }
        let length = u32::try_from(body.len())
            .map_err(|_| malformed("slot decision journal body too large"))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join(FILE))?;
        if existing.is_none() {
            file.write_all(&length.to_le_bytes())?;
            file.write_all(&body)?;
            file.write_all(&decision.id()?)?;
        }
        file.sync_all()?;
        sync_ancestors(&root, |directory| File::open(directory)?.sync_all())?;
        Ok(())
    }

    /// Reads all irreversible local slot-decision intents in chain/round order.
    ///
    /// # Errors
    /// Returns filesystem or decode errors, including any torn or corrupt tail.
    pub fn slot_decision_locks(&self) -> Result<Vec<SlotDecision>, StoreError> {
        let root = self
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        read(&root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_decision_sync_ancestors_are_absolute_and_bottom_up() {
        let canonical = fs::canonicalize(".").unwrap();
        let mut visited = Vec::new();
        sync_ancestors(Path::new("."), |directory| {
            assert!(directory.is_absolute());
            visited.push(directory.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(visited.first(), Some(&canonical));
        for pair in visited.windows(2) {
            assert_eq!(pair[0].parent(), Some(pair[1].as_path()));
        }
        assert!(visited.last().unwrap().parent().is_none());
    }

    #[test]
    fn slot_decision_sync_ancestors_propagates_io_failure() {
        let mut calls = 0;
        let error = sync_ancestors(Path::new("."), |_| {
            calls += 1;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "directory sync unsupported",
            ))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(calls, 1, "must stop at the failed durability barrier");
    }
}
