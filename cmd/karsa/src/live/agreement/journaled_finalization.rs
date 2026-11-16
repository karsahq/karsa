//! Inactive genesis replay with mandatory durable pre-sign header reservations.

use std::collections::{BTreeMap, BTreeSet};

use exec::State;
use tx::batch::Batch;
use validator::{Build, Certified, Finalizer, Header, Share};

use super::{Adapter, CertifiedFinalization, Membership};

/// Owns the agreement handle so header production cannot bypass durable reservation.
/// Opening rebuilds execution from trusted genesis, not an execution checkpoint. Payloads
/// and control classification remain caller-trusted inputs. Use isolated signing keys.
/// Old reservations must all replay exactly before any rebuilt output is released.
/// Returned shares may repeat across restart with new timestamps; signatures, peer shares,
/// certificates and delivery acknowledgements are not persisted or restored by this path.
/// This bounded offline owner has no live transport, pruning or epoch-transition authority.
pub struct JournaledFinalization {
    adapter: Adapter,
    coordinator: CertifiedFinalization,
    anchor: Header,
    outbox: Build,
    failed: bool,
}

impl JournaledFinalization {
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
        let adapter = &mut self.adapter;
        let anchor = &self.anchor;
        let mut build = self.coordinator.build_ready_with_reservation(
            membership,
            batches,
            authenticated_controls,
            at,
            |header, coverage| {
                adapter
                    .reserve_header(anchor, header, coverage)
                    .map_err(|error| {
                        crypto::CryptoError::new(crypto::CryptoErrorKind::InvalidVertex, error)
                    })
            },
        )?;
        self.outbox.shares.append(&mut build.shares);
        self.outbox.certified.append(&mut build.certified);
        let reserved = self.refresh()?;
        if self.coordinator.finalizer().built_headers() < reserved {
            return Ok(Build::default());
        }
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
        self.coordinator.receive_share(membership, share)
    }

    /// Read-only execution and finalizer diagnostics; mutation cannot bypass reservation.
    pub fn finalization(&self) -> &CertifiedFinalization {
        &self.coordinator
    }

    fn refresh(&mut self) -> Result<usize, String> {
        let result = (|| {
            let snapshot = self.adapter.ordering_snapshot()?;
            let intents = self.adapter.header_intents()?;
            self.coordinator.update(snapshot)?;
            Ok(intents.len())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
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
