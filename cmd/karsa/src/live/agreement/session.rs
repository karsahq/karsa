//! Opt-in trusted-genesis start for an isolated certified session.
//!
//! A live node currently opens no agreement session: the legacy commit loop
//! decides slots and builds headers. This module supplies the missing entry
//! point, so a caller that already owns the chain identity, the committee and
//! the genesis header can open the certified owner on the same store instead of
//! inventing a test fixture.
//!
//! What this establishes:
//! - one deterministic `SlotDecisionTip` every validator derives identically,
//!   with the genesis header id as the trusted predecessor and the empty commit
//!   tree as the starting order root;
//! - an authenticated WAL created (or recovered) for that exact checkpoint;
//! - a finalizer anchored at the genesis header, ready to number certified
//!   applications from height one.
//!
//! What this does not establish: live transport, proposal/view authoring,
//! slot application, execution publication, or authority replacement. Receiving
//! a carrier still requires the caller to authenticate and deliver it, and a
//! decided slot still requires an explicit `AdvanceSlot`. The two histories are
//! mutually exclusive on disk: a store that already carries a legacy genesis
//! state or header is refused here, and the legacy startup guard refuses a store
//! that already holds this session.

use exec::State;
use store::{AuthenticatedSlotAgreementBootstrap, SlotAgreementBootstrap, Store};
use validator::{EpochSchedule, Finalizer, Header, SetSchedule, SlotDecisionTip, commit_root};

use super::{Adapter, JournaledFinalization, Membership};

/// The trusted checkpoint every validator must derive from the same genesis.
///
/// The genesis header is the anchor, so its id is the predecessor of the first
/// decision and its `dag_root` is the order root of an empty committed prefix.
/// `first_round` is one, matching a chain whose round zero only establishes
/// authorship. The caller remains responsible for the header being the one the
/// whole committee agreed on.
///
/// # Errors
/// Rejects a non-genesis header, a chain or epoch that differs from the pinned
/// membership, a nonempty order root, and a validator index without a consensus
/// key or without a matching record in the set.
pub fn genesis_bootstrap(
    membership: &Membership,
    index: usize,
    chain_id: &[u8],
    genesis: &Header,
) -> Result<AuthenticatedSlotAgreementBootstrap, String> {
    let identity = membership
        .consensus
        .get(index)
        .ok_or("no consensus key for this validator index")?;
    if genesis.height != 0
        || genesis.round != 0
        || genesis.applied != 0
        || genesis.previous != [0u8; 32]
    {
        return Err("certified session requires a genesis header".into());
    }
    if genesis.chain_id.as_slice() != chain_id {
        return Err("genesis header chain differs from the pinned chain".into());
    }
    if genesis.epoch != membership.set.epoch {
        return Err("genesis header epoch differs from the pinned set epoch".into());
    }
    if genesis.dag_root != commit_root(&[]) {
        return Err("genesis header order root is not the empty commit tree".into());
    }
    if membership.set.validator(&identity.id).is_none() {
        return Err("local validator is absent from the pinned set".into());
    }
    let previous = genesis.id().map_err(|error| error.to_string())?;
    let context = SlotDecisionTip::from_checkpoint(
        chain_id.to_vec(),
        &membership.set,
        1,
        previous,
        0,
        genesis.dag_root,
    )
    .map_err(|error| error.to_string())?;
    Ok(AuthenticatedSlotAgreementBootstrap {
        agreement: SlotAgreementBootstrap {
            context,
            set: membership.set.clone(),
            local_validator: identity.id.clone(),
        },
        predecessor: None,
        order: Vec::new(),
        vertices: Vec::new(),
    })
}

/// Creates a new authenticated session at genesis and anchors header production.
///
/// The finalizer uses a single-set schedule: this bounded owner does not support
/// epoch transitions, so a schedule that advances would poison the coordinator
/// at the first boundary. The caller may pass any schedule whose epoch of round
/// zero is the header epoch.
///
/// # Errors
/// Rejects an incompatible state root, epoch schedule or genesis bootstrap, a
/// store that already holds a legacy chain, an existing authenticated journal,
/// and every error from building the finalizer or opening the journaled owner.
pub fn open_at_genesis(
    store: &Store,
    membership: &Membership,
    index: usize,
    genesis: &Header,
    genesis_state: State,
    epoch_schedule: EpochSchedule,
) -> Result<JournaledFinalization, String> {
    checked_store(store)?;
    let bootstrap = checked_bootstrap(membership, index, genesis, &genesis_state, epoch_schedule)?;
    let adapter = Adapter::begin(store, bootstrap, membership, index)?;
    let finalizer = anchored_finalizer(membership, index, genesis, epoch_schedule)?;
    JournaledFinalization::open(adapter, genesis_state, finalizer)
}

/// Recovers the exact session [`open_at_genesis`] created.
///
/// Recovery reauthenticates the complete WAL and repeats its durability
/// barriers; it cannot invent missing history or a different checkpoint. The
/// returned owner is fresh, so any previous in-process owner must be dropped.
///
/// # Errors
/// Rejects the same incompatible inputs as [`open_at_genesis`], a missing or
/// different authenticated journal, and every replay or owner failure.
pub fn recover_at_genesis(
    store: &Store,
    membership: &Membership,
    index: usize,
    genesis: &Header,
    genesis_state: State,
    epoch_schedule: EpochSchedule,
) -> Result<JournaledFinalization, String> {
    checked_store(store)?;
    let bootstrap = checked_bootstrap(membership, index, genesis, &genesis_state, epoch_schedule)?;
    let adapter = Adapter::recover(store, bootstrap, membership, index)?;
    let finalizer = anchored_finalizer(membership, index, genesis, epoch_schedule)?;
    JournaledFinalization::open(adapter, genesis_state, finalizer)
}

/// A genesis session starts a new history, so the same store cannot already carry one.
///
/// The legacy live node writes a genesis state and header before it decides anything.
/// Opening a certified session over that chain would put two orderings on one disk and
/// make recovery depend on which one a caller happened to read. The session is refused
/// instead. The store's authenticated-journal absence is checked by `Adapter::begin`.
fn checked_store(store: &Store) -> Result<(), String> {
    if store
        .genesis_header()
        .map_err(|error| error.to_string())?
        .is_some()
        || store
            .genesis_state()
            .map_err(|error| error.to_string())?
            .is_some()
    {
        return Err("certified session refuses a store that already holds a legacy chain".into());
    }
    Ok(())
}

fn checked_bootstrap(
    membership: &Membership,
    index: usize,
    genesis: &Header,
    genesis_state: &State,
    epoch_schedule: EpochSchedule,
) -> Result<AuthenticatedSlotAgreementBootstrap, String> {
    if genesis_state.state_root() != genesis.state_root {
        return Err("session genesis state does not match the header".into());
    }
    if epoch_schedule.epoch_of(0) != genesis.epoch {
        return Err("session epoch schedule does not start at the header epoch".into());
    }
    genesis_bootstrap(membership, index, genesis.chain_id.as_slice(), genesis)
}

fn anchored_finalizer(
    membership: &Membership,
    index: usize,
    genesis: &Header,
    epoch_schedule: EpochSchedule,
) -> Result<Finalizer, String> {
    let identity = membership
        .consensus
        .get(index)
        .ok_or("no consensus key for this validator index")?;
    Finalizer::new(
        SetSchedule::single(membership.set.clone()),
        epoch_schedule,
        genesis.chain_id.clone(),
        identity.id.clone(),
        identity.private_key.clone(),
        genesis.clone(),
        0,
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "karsa-agreement-session-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn genesis(chain_id: &[u8], membership: &Membership, state: &State) -> Header {
        Header::genesis(
            chain_id.to_vec(),
            membership.set.epoch,
            state.state_root(),
            commit_root(&[]),
        )
    }

    #[test]
    fn every_validator_derives_the_same_trusted_genesis_checkpoint() {
        let membership = chain::membership(4, None).unwrap();
        let chain_id = b"karsa-agreement-session".to_vec();
        let state = chain::genesis_state(&membership.accounts).unwrap();
        let genesis = genesis(&chain_id, &membership, &state);
        let expected_previous = genesis.id().unwrap();

        let first = genesis_bootstrap(&membership, 0, &chain_id, &genesis).unwrap();
        assert_eq!(first.agreement.context.previous_id(), &expected_previous);
        assert_eq!(first.agreement.context.next_round(), 1);
        assert_eq!(first.agreement.context.order_len(), 0);
        assert_eq!(first.agreement.context.order_root(), &commit_root(&[]));
        assert!(first.order.is_empty());
        assert!(first.vertices.is_empty());
        assert!(first.predecessor.is_none());

        for index in 0..4 {
            let bootstrap = genesis_bootstrap(&membership, index, &chain_id, &genesis).unwrap();
            assert_eq!(
                bootstrap.agreement.context, first.agreement.context,
                "every validator must derive one checkpoint"
            );
            assert_eq!(bootstrap.agreement.set, first.agreement.set);
            assert_eq!(
                bootstrap.agreement.local_validator, membership.consensus[index].id,
                "only the local identity differs"
            );
        }
    }

    #[test]
    fn a_genesis_session_opens_recovers_and_keeps_the_trusted_anchor() {
        let membership = chain::membership(4, None).unwrap();
        let chain_id = b"karsa-agreement-session".to_vec();
        let state = chain::genesis_state(&membership.accounts).unwrap();
        let genesis = genesis(&chain_id, &membership, &state);
        let schedule = validator::EpochSchedule::single(membership.set.epoch);
        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();

        let mut session =
            open_at_genesis(&store, &membership, 0, &genesis, state.clone(), schedule).unwrap();
        {
            let snapshot = session.finalization().execution().snapshot();
            assert_eq!(
                snapshot.checkpoint_binding().tip(),
                &genesis_bootstrap(&membership, 0, &chain_id, &genesis)
                    .unwrap()
                    .agreement
                    .context
            );
            assert!(snapshot.applications().is_empty());
            assert!(snapshot.order().is_empty());
        }
        let finalizer = session.finalization().finalizer();
        assert_eq!(finalizer.head(), &genesis);
        assert_eq!(finalizer.built_headers(), 0);
        assert_eq!(finalizer.next_height(), 1);
        assert_eq!(finalizer.last_built_order(), 0);
        assert!(!finalizer.has_pending_work());

        let build = session
            .build_ready(
                &membership,
                &std::collections::BTreeMap::new(),
                &std::collections::BTreeSet::new(),
                0,
            )
            .unwrap();
        assert!(build.shares.is_empty());
        assert!(build.certified.is_empty());
        drop(session);

        let recovered =
            recover_at_genesis(&store, &membership, 0, &genesis, state, schedule).unwrap();
        assert_eq!(recovered.finalization().finalizer().head(), &genesis);
        assert_eq!(
            recovered
                .finalization()
                .execution()
                .snapshot()
                .checkpoint_binding()
                .tip(),
            &genesis_bootstrap(&membership, 0, &chain_id, &genesis)
                .unwrap()
                .agreement
                .context,
            "recovery must not move the trusted checkpoint"
        );
    }

    #[test]
    fn a_certified_session_store_refuses_legacy_live_startup() {
        let membership = chain::membership(4, None).unwrap();
        let chain_id = b"karsa-agreement-session".to_vec();
        let state = chain::genesis_state(&membership.accounts).unwrap();
        let genesis = genesis(&chain_id, &membership, &state);
        let schedule = validator::EpochSchedule::single(membership.set.epoch);
        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(!store.has_authenticated_slot_agreement().unwrap());
        assert!(
            super::super::disabled_guard(&store).is_ok(),
            "a store without a session is a valid legacy start"
        );

        let session = open_at_genesis(&store, &membership, 0, &genesis, state, schedule).unwrap();
        assert!(store.has_authenticated_slot_agreement().unwrap());
        let refused = super::super::disabled_guard(&store).unwrap_err();
        assert!(
            refused.contains("certified agreement session"),
            "the legacy loop must be refused by name: {refused}"
        );
        drop(session);
    }

    #[test]
    fn a_session_refuses_a_store_that_already_holds_a_legacy_chain() {
        let membership = chain::membership(4, None).unwrap();
        let chain_id = b"karsa-agreement-session".to_vec();
        let state = chain::genesis_state(&membership.accounts).unwrap();
        let genesis = genesis(&chain_id, &membership, &state);
        let schedule = validator::EpochSchedule::single(membership.set.epoch);
        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();
        store.put_genesis_state(&state.encode().unwrap()).unwrap();
        store.put_genesis_header(&genesis).unwrap();
        assert!(!store.has_authenticated_slot_agreement().unwrap());

        let error = open_at_genesis(&store, &membership, 0, &genesis, state, schedule)
            .err()
            .expect("a legacy chain store cannot open a certified session");
        assert!(
            error.contains("legacy chain"),
            "two histories must not share one store: {error}"
        );
        assert!(
            !store.has_authenticated_slot_agreement().unwrap(),
            "a refused start must not create an authenticated journal"
        );
    }

    #[test]
    fn a_genesis_session_rejects_untrusted_starting_points() {
        let membership = chain::membership(4, None).unwrap();
        let chain_id = b"karsa-agreement-session".to_vec();
        let state = chain::genesis_state(&membership.accounts).unwrap();
        let genesis = genesis(&chain_id, &membership, &state);

        let mut non_genesis = genesis.clone();
        non_genesis.height = 1;
        assert!(genesis_bootstrap(&membership, 0, &chain_id, &non_genesis).is_err());

        let mut other_chain = genesis.clone();
        other_chain.chain_id = b"another-chain".to_vec();
        assert!(genesis_bootstrap(&membership, 0, &chain_id, &other_chain).is_err());

        let mut other_epoch = genesis.clone();
        other_epoch.epoch = membership.set.epoch.saturating_add(1);
        assert!(genesis_bootstrap(&membership, 0, &chain_id, &other_epoch).is_err());

        let mut other_root = genesis.clone();
        other_root.dag_root = [1; 32];
        assert!(genesis_bootstrap(&membership, 0, &chain_id, &other_root).is_err());

        assert!(
            genesis_bootstrap(&membership, 4, &chain_id, &genesis).is_err(),
            "an index without a consensus key cannot open a session"
        );

        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();
        let schedule = validator::EpochSchedule::single(membership.set.epoch);
        assert!(
            open_at_genesis(
                &store,
                &membership,
                0,
                &genesis,
                exec::State::default(),
                schedule
            )
            .is_err(),
            "state that did not produce the header root cannot execute its prefix"
        );

        let late_schedule = validator::EpochSchedule::advancing(membership.set.epoch + 1, 10);
        assert!(
            open_at_genesis(&store, &membership, 0, &genesis, state, late_schedule).is_err(),
            "a schedule whose round zero is another epoch rejects the header"
        );
    }
}
