//! Explicit local scheduling only: no clock persistence, certificates, signing, or transport.

use std::time::{Duration, Instant};
use validator::slot_agreement::{AgreementPhase, AgreementView};

/// Fixed phase waits and bounded publication opportunity; no backoff or delivery requirement.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    prevote: Duration,
    precommit: Duration,
    grace: Duration,
}

impl Policy {
    /// Configures fixed waits (an operational bound, not a benchmark).
    /// # Errors
    /// Rejects zero waits or waits exceeding one day.
    pub fn new(prevote: Duration, precommit: Duration, grace: Duration) -> Result<Self, String> {
        let max = Duration::from_secs(86_400);
        if [prevote, precommit, grace]
            .iter()
            .any(|d| d.is_zero() || *d > max)
        {
            return Err("phase waits must be positive and at most one day".into());
        }
        Ok(Self {
            prevote,
            precommit,
            grace,
        })
    }
}

/// A local request, not evidence of a quorum or delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Request nil only in a phase with no durable local vote.
    Timeout {
        /// Exact current view.
        view: AgreementView,
        /// Unvoted phase whose deadline expired.
        phase: AgreementPhase,
    },
    /// Local one-view step after publication grace, not remote evidence or a nil certificate.
    AdvanceView {
        /// Exact current view.
        from: AgreementView,
    },
}

/// Adapter-authenticated durable snapshot, never caller-supplied signing authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub slot: validator::SlotDecisionTip,
    pub view: AgreementView,
    pub prevote: bool,
    pub precommit: bool,
    pub decided: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    AwaitPrevote,
    AwaitPrecommit,
    PublicationGrace,
}

/// Constant-space planner. Construct a new instance on recovery; elapsed time is not durable.
#[derive(Debug)]
pub struct Pacemaker {
    policy: Policy,
    timer: Option<(validator::SlotDecisionTip, AgreementView, Stage, Instant)>,
    last_now: Option<Instant>,
}

impl Pacemaker {
    /// Starts without a timer; the first observed active snapshot arms it.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            timer: None,
            last_now: None,
        }
    }

    pub(super) fn plan(
        &mut self,
        state: &Snapshot,
        now: Instant,
    ) -> Result<Option<Action>, String> {
        if self.last_now.is_some_and(|last| now < last) {
            return Err("pacemaker now moved backwards".into());
        }
        self.last_now = Some(now);
        if state.decided {
            self.timer = None;
            return Ok(None);
        }
        let stage = if state.precommit {
            Stage::PublicationGrace
        } else if state.prevote {
            Stage::AwaitPrecommit
        } else {
            Stage::AwaitPrevote
        };
        let changed = self
            .timer
            .as_ref()
            .is_none_or(|(slot, view, old_phase, _)| {
                slot != &state.slot || *view != state.view || *old_phase != stage
            });
        if changed {
            self.timer = Some((state.slot.clone(), state.view, stage, now));
        }
        let start = self.timer.as_ref().expect("active timer initialized").3;
        let wait = match stage {
            Stage::AwaitPrevote => self.policy.prevote,
            Stage::AwaitPrecommit => self.policy.precommit,
            Stage::PublicationGrace => self.policy.grace,
        };
        let deadline = start
            .checked_add(wait)
            .ok_or("pacemaker deadline overflow")?;
        if now < deadline {
            return Ok(None);
        }
        if stage == Stage::PublicationGrace {
            state
                .view
                .0
                .checked_add(1)
                .ok_or("agreement view exhausted")?;
            Ok(Some(Action::AdvanceView { from: state.view }))
        } else {
            Ok(Some(Action::Timeout {
                view: state.view,
                phase: match stage {
                    Stage::AwaitPrevote => AgreementPhase::Prevote,
                    Stage::AwaitPrecommit => AgreementPhase::Precommit,
                    Stage::PublicationGrace => unreachable!("grace handled above"),
                },
            }))
        }
    }
}

#[cfg(test)]
mod tests;
