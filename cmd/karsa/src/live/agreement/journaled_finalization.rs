//! Inactive genesis replay with mandatory durable pre-sign header reservations.

use std::collections::{BTreeMap, BTreeSet};

use exec::State;
use tx::batch::Batch;
use validator::{Build, Certified, Finalizer, Header, Share};

use super::{Adapter, CertifiedFinalization, Membership};

#[path = "local_authoring.rs"]
pub mod local_authoring;

/// Owns the agreement handle so header production cannot bypass durable reservation.
/// Opening rebuilds execution from trusted genesis, not an execution checkpoint. Payloads
/// and control classification remain caller-trusted inputs. Use isolated signing keys.
/// Old reservations must all replay exactly before any rebuilt output is released.
/// Completed local and accepted peer shares are persisted before release or collection.
/// Replay preserves local timestamps and restores authenticated durable quorum state only
/// after every reserved header matches execution. Certificates and delivery acknowledgements
/// are not persisted; recovered certificates may be delivered again. Per-share timestamps
/// are preserved, but certificate metadata is reconstructed from the deterministic earliest
/// quorum over all durable records, including post-certification shares, and may therefore
/// differ from historically emitted certificate metadata.
/// This bounded offline owner has no live transport, pruning or epoch-transition authority.
pub struct JournaledFinalization {
    adapter: Adapter,
    authoring: Option<local_authoring::LocalAuthoring>,
    coordinator: CertifiedFinalization,
    anchor: Header,
    outbox: Build,
    failed: bool,
}

impl JournaledFinalization {
    #[cfg(test)]
    pub(super) fn fail_share_publication(
        &mut self,
        stage: store::SharePublicationStage,
        skip: usize,
    ) {
        self.adapter.driver.fail_share_publication(stage, skip);
    }
    /// Opens new or recovered durable agreement history with a pristine genesis finalizer.
    /// No execution or signing occurs until [`Self::build_ready`]. A missing intent journal
    /// means no prior reservation; a corrupt journal is an error, never a fresh start.
    /// # Errors
    /// Rejects incompatible genesis, non-pristine finalizers, stale owners and corrupt history.
    pub fn open(
        mut adapter: Adapter,
        genesis: State,
        finalizer: Finalizer,
    ) -> Result<Self, String> {
        let snapshot = adapter.ordering_snapshot()?;
        let intents = adapter.header_intents()?;
        adapter.header_shares()?;
        let anchor = finalizer.head().clone();
        let anchor_id = anchor.id().map_err(|error| error.to_string())?;
        if anchor
            != Header::genesis(
                anchor.chain_id.clone(),
                anchor.epoch,
                genesis.state_root(),
                anchor.dag_root,
            )
            || intents
                .first()
                .is_some_and(|intent| intent.header().previous != anchor_id)
        {
            return Err("journaled finalization genesis differs from reserved history".into());
        }
        let coordinator = CertifiedFinalization::begin(snapshot, genesis, finalizer)?;
        Ok(Self {
            adapter,
            authoring: None,
            coordinator,
            anchor,
            outbox: Build::default(),
            failed: false,
        })
    }

    /// Re-executes durable applications and durably reserves exact headers before signing.
    /// Missing payloads can advance a partial prefix, but output stays buffered until all
    /// preexisting reserved headers have been rebuilt. A later call resumes that prefix.
    /// Matching reservations are re-synced; a conflicting replay cannot overwrite them.
    /// # Errors
    /// Batch errors permit retry with corrected payloads. Ownership, journal and reservation
    /// failures require opening a new owner; any earlier signatures remain constrained by
    /// their durable intents. This is not an external exactly-once delivery guarantee.
    pub fn build_ready(
        &mut self,
        membership: &Membership,
        batches: &BTreeMap<[u8; 32], Batch>,
        authenticated_controls: &BTreeSet<[u8; 32]>,
        at: u64,
    ) -> Result<Build, String> {
        self.ensure_usable()?;
        self.refresh()?;
        let adapter = std::cell::RefCell::new(&mut self.adapter);
        let anchor = &self.anchor;
        let mut canonicalize = |share: Share| {
            Self::persist_with(&mut adapter.borrow_mut(), anchor, &share).map_err(|error| {
                crypto::CryptoError::new(crypto::CryptoErrorKind::InvalidVertex, error)
            })
        };
        let result = self.coordinator.build_with_hooks(
            membership,
            batches,
            authenticated_controls,
            at,
            |header, coverage| {
                adapter
                    .borrow_mut()
                    .reserve_header(anchor, header, coverage)
                    .map_err(|error| {
                        crypto::CryptoError::new(crypto::CryptoErrorKind::InvalidVertex, error)
                    })
            },
            Some(&mut canonicalize),
        );
        // Execution errors are retryable; durable callback errors poison the coordinator.
        let mut build = result?;
        self.outbox.shares.append(&mut build.shares);
        self.outbox.certified.append(&mut build.certified);
        let reserved = self.refresh()?;
        if self.coordinator.finalizer().built_headers() < reserved {
            return Ok(Build::default());
        }
        let result = self.restore_shares(membership);
        if result.is_err() {
            self.failed = true;
        }
        self.outbox.certified.extend(result?);
        Ok(std::mem::take(&mut self.outbox))
    }

    /// Accepts authenticated peer shares only after every durable reservation has replayed.
    /// Returned certificates are volatile and must not authorize durable publication or pruning.
    /// # Errors
    /// Rejects incomplete replay, invalid shares, stale owners and corrupt intent history.
    pub fn receive_share(
        &mut self,
        membership: &Membership,
        share: Share,
    ) -> Result<Vec<Certified>, String> {
        self.ensure_usable()?;
        let reserved = self.refresh()?;
        if self.coordinator.finalizer().built_headers() < reserved {
            return Err("journaled finalization must replay all reserved headers first".into());
        }
        self.coordinator.validate_share(membership, &share)?;
        let share = self.persist_share(&share)?;
        self.coordinator.receive_share(membership, share)
    }

    /// Receives decoded wire evidence without applying a slot or executing payloads.
    /// # Errors
    /// Invalid messages retain the adapter's retry semantics; stale ownership and durable
    /// failures close this owner. No legacy agreement path is used.
    pub fn receive_agreement_message(&mut self, message: net::wire::Message) -> Result<(), String> {
        self.ensure_usable()?;
        let result = self.adapter.receive_message(message);
        self.refresh()?;
        result
    }

    /// Explicitly applies the certified slot, leaving execution to [`Self::build_ready`].
    /// # Errors
    /// An undecided slot is retryable. Adapter or durable refresh failures close this owner.
    pub fn advance_certified_slot(&mut self) -> Result<(), String> {
        self.ensure_usable()?;
        self.refresh()?;
        // Avoid sending a known-invalid local request into Adapter's fail-closed apply path.
        let output = self.adapter.driver.output().map_err(|error| {
            self.failed = true;
            error.to_string()
        })?;
        if !output
            .transition
            .is_some_and(|transition| transition.decision.is_some())
        {
            return Err("cannot advance an undecided slot".into());
        }
        let result = self
            .adapter
            .apply(store::AuthenticatedSlotAgreementRequest::AdvanceSlot);
        self.refresh()?;
        result?;
        // The owned causal Node must continue from the prefix the durable binding now
        // covers, not from whatever it held when the slot was still undecided.
        self.sync_local_order()
    }

    fn sync_local_order(&mut self) -> Result<(), String> {
        if self.authoring.is_none() {
            return Ok(());
        }
        let snapshot = self.adapter.ordering_snapshot().inspect_err(|_| {
            self.failed = true;
        })?;
        if let Some(local) = self.authoring.as_mut() {
            local.node.seed_order(snapshot.order().to_vec());
        }
        Ok(())
    }

    /// Read-only execution and finalizer diagnostics; mutation cannot bypass reservation.
    pub fn finalization(&self) -> &CertifiedFinalization {
        &self.coordinator
    }

    fn persist_share(&mut self, share: &Share) -> Result<Share, String> {
        let result = Self::persist_with(&mut self.adapter, &self.anchor, share);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn persist_with(
        adapter: &mut Adapter,
        anchor: &Header,
        share: &Share,
    ) -> Result<Share, String> {
        let stored = adapter.header_shares()?;
        let canonical = match stored
            .iter()
            .find(|old| old.header.height == share.header.height && old.signer == share.signer)
        {
            Some(old) if old.header == share.header && old.signature == share.signature => {
                old.clone()
            }
            Some(_) => return Err("conflicting completed header share".into()),
            None => share.clone(),
        };
        // Re-publish even an old share: a sibling may have observed a rename
        // whose directory durability barrier failed in another owner.
        adapter.reserve_header_share(anchor, &canonical)?;
        Ok(canonical)
    }

    fn restore_shares(&mut self, membership: &Membership) -> Result<Vec<Certified>, String> {
        let shares = self.adapter.header_shares()?;
        // Validate and re-publish every visible record before allowing any quorum advance.
        for share in &shares {
            self.coordinator.validate_share(membership, share)?;
            self.adapter.reserve_header_share(&self.anchor, share)?;
        }
        self.coordinator.restore_shares(membership, shares)
    }

    fn refresh(&mut self) -> Result<usize, String> {
        let result = (|| {
            let snapshot = self.adapter.ordering_snapshot()?;
            let intents = self.adapter.header_intents()?;
            self.adapter.header_shares()?;
            self.coordinator.update(snapshot)?;
            Ok(intents.len())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Checks owner/coordinator poison state without interpreting diagnostic strings.
    pub(super) fn check_health(&mut self) -> Result<(), String> {
        self.ensure_usable()?;
        self.refresh().map(|_| ())
    }

    fn ensure_usable(&self) -> Result<(), String> {
        if self.failed {
            return Err(
                "journaled finalization requires reopening after durable history failure".into(),
            );
        }
        Ok(())
    }
}
