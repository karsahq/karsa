//! A deterministic account state machine over committed batches.
//!
//! Execution has to agree, not just ordering. Two nodes that apply the same
//! committed batches in the same order must reach the same state root, so this
//! crate reads nothing outside its inputs: no clock, no environment, no hash-map
//! iteration order. Balances and sequences live in `BTreeMap`s precisely so the
//! root cannot depend on insertion order.
//!
//! Rejections are values, not errors. A batch whose transaction number three is
//! unaffordable still commits; it just produces [`Outcome::Rejected`] for that
//! transaction, and every other node rejects it identically.

mod merkle;
mod transfer;

pub use merkle::{MerkleProof, MerkleTree, ProofStep};
pub use transfer::Transfer;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use tx::batch::Batch;
use tx::envelope::Transaction;

/// Why one transaction was rejected.
///
/// Rejections are deterministic: the same state and the same transaction always
/// produce the same reason, in the same order of checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The sender account does not exist.
    UnknownSender,
    /// The transaction sequence is not the sender's next one.
    BadSequence,
    /// The transfer names its own sender as recipient.
    SelfTransfer,
    /// The recipient account does not exist.
    UnknownRecipient,
    /// The sender cannot cover amount plus fee.
    InsufficientFunds,
    /// The payload is not a well-formed transfer.
    MalformedPayload,
}

impl RejectReason {
    /// Returns the snake_case name used in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownSender => "unknown_sender",
            Self::BadSequence => "bad_sequence",
            Self::SelfTransfer => "self_transfer",
            Self::UnknownRecipient => "unknown_recipient",
            Self::InsufficientFunds => "insufficient_funds",
            Self::MalformedPayload => "malformed_payload",
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What happened to one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The transfer was applied.
    Applied {
        /// Recipient.
        to: Vec<u8>,
        /// Amount credited.
        amount: u64,
        /// Fee debited from the sender and burned.
        fee: u64,
    },
    /// The transfer was refused; state is unchanged.
    Rejected(RejectReason),
}

impl Outcome {
    /// Returns whether the transaction changed state.
    #[must_use]
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }

    /// Returns why the transaction was rejected, if it was.
    #[must_use]
    pub fn reason(&self) -> Option<RejectReason> {
        match self {
            Self::Applied { .. } => None,
            Self::Rejected(reason) => Some(*reason),
        }
    }
}

/// A failure that is not a per-transaction rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    /// A balance or sequence would not fit in `u64`.
    Overflow,
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("balance or sequence overflowed u64"),
        }
    }
}

impl Error for ExecError {}

/// Account balances and per-sender sequences.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    balances: BTreeMap<Vec<u8>, u64>,
    sequences: BTreeMap<Vec<u8>, u64>,
}

impl State {
    /// Creates an empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an account with a starting balance.
    ///
    /// # Errors
    ///
    /// [`ExecError::Overflow`] when the balance would exceed `u64`.
    pub fn credit(&mut self, account: &[u8], amount: u64) -> Result<u64, ExecError> {
        let balance = self
            .balances
            .get(account)
            .copied()
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(ExecError::Overflow)?;
        self.balances.insert(account.to_vec(), balance);
        Ok(balance)
    }

    /// Returns an account's balance, or zero when it does not exist.
    #[must_use]
    pub fn balance(&self, account: &[u8]) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    /// Returns an account's next expected sequence, or zero before its first
    /// transaction.
    #[must_use]
    pub fn sequence(&self, account: &[u8]) -> u64 {
        self.sequences.get(account).copied().unwrap_or(0)
    }

    /// Every account and its balance, ordered by account.
    #[must_use]
    pub fn balances(&self) -> &BTreeMap<Vec<u8>, u64> {
        &self.balances
    }

    /// Applies a batch in order, returning one outcome per transaction.
    #[must_use]
    pub fn apply(&mut self, batch: &Batch) -> Vec<Outcome> {
        batch
            .transactions
            .iter()
            .map(|transaction| self.apply_one(transaction))
            .collect()
    }

    fn apply_one(&mut self, transaction: &Transaction) -> Outcome {
        let Ok(transfer) = Transfer::decode(&transaction.payload) else {
            return Outcome::Rejected(RejectReason::MalformedPayload);
        };
        let sender = transaction.sender.as_slice();
        if !self.balances.contains_key(sender) {
            return Outcome::Rejected(RejectReason::UnknownSender);
        }
        let expected = self.sequence(sender) + 1;
        if transaction.sequence != expected {
            return Outcome::Rejected(RejectReason::BadSequence);
        }
        if transfer.to.as_slice() == sender {
            return Outcome::Rejected(RejectReason::SelfTransfer);
        }
        if !self.balances.contains_key(transfer.to.as_slice()) {
            return Outcome::Rejected(RejectReason::UnknownRecipient);
        }
        let Some(total) = transfer.amount.checked_add(transaction.fee) else {
            return Outcome::Rejected(RejectReason::InsufficientFunds);
        };
        if self.balance(sender) < total {
            return Outcome::Rejected(RejectReason::InsufficientFunds);
        }

        // Both accounts were checked above, so these lookups are present.
        if let Some(balance) = self.balances.get_mut(sender) {
            *balance -= total;
        }
        if let Some(balance) = self.balances.get_mut(transfer.to.as_slice()) {
            *balance += transfer.amount;
        }
        if let Some(sequence) = self.sequences.get_mut(sender) {
            *sequence += 1;
        } else {
            self.sequences.insert(transaction.sender.clone(), 1);
        }

        Outcome::Applied {
            to: transfer.to,
            amount: transfer.amount,
            fee: transaction.fee,
        }
    }

    /// The commitment to the whole state, as a Merkle root over account leaves.
    ///
    /// Two nodes with the same accounts produce the same root regardless of the
    /// order they credited them in, because leaves are taken from a `BTreeMap`.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        self.tree().root()
    }

    /// Builds an inclusion proof for one account.
    ///
    /// Returns `None` when the account does not exist: there is no leaf to prove.
    #[must_use]
    pub fn proof(&self, account: &[u8]) -> Option<AccountProof> {
        let index = self
            .balances
            .keys()
            .position(|candidate| candidate == account)?;
        let proof = self.tree().proof(index)?;
        Some(AccountProof {
            account: account.to_vec(),
            balance: self.balance(account),
            sequence: self.sequence(account),
            proof,
        })
    }

    fn leaves(&self) -> Vec<[u8; 32]> {
        self.balances
            .iter()
            .map(|(account, balance)| merkle::hash_leaf(account, *balance, self.sequence(account)))
            .collect()
    }

    fn tree(&self) -> MerkleTree {
        MerkleTree::from_leaves(self.leaves())
    }
}

/// An account leaf plus the path that binds it to a state root.
///
/// A light client holds only the root. Given this proof it can read one balance
/// without trusting the node that served it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProof {
    /// The account the proof is about.
    pub account: Vec<u8>,
    /// Claimed balance.
    pub balance: u64,
    /// Claimed next sequence.
    pub sequence: u64,
    /// Siblings from the account leaf to the root.
    pub proof: MerkleProof,
}

impl AccountProof {
    /// Returns whether the claim is bound to `root`.
    #[must_use]
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        let leaf = merkle::hash_leaf(&self.account, self.balance, self.sequence);
        MerkleTree::verify(root, &leaf, &self.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tx::envelope::PROTOCOL_VERSION_V1;

    const NOW: u64 = 1_000;

    fn transaction(sender: &[u8], sequence: u64, to: &[u8], amount: u64) -> Transaction {
        Transaction {
            protocol_version: PROTOCOL_VERSION_V1,
            chain_id: b"karsa-exec-1".to_vec(),
            sender: sender.to_vec(),
            sequence,
            fee: 1,
            expiration: NOW,
            policy_version: 1,
            payload: Transfer::new(to.to_vec(), amount).encode().unwrap(),
            authorization: Vec::new(),
        }
    }

    fn genesis() -> State {
        let mut state = State::new();
        state.credit(b"alice", 1_000).unwrap();
        state.credit(b"bob", 1_000).unwrap();
        state
    }

    #[test]
    fn a_transfer_moves_value_and_burns_the_fee() {
        let mut state = genesis();
        let outcomes = state.apply(&Batch::new(vec![transaction(b"alice", 1, b"bob", 250)]));

        assert!(outcomes[0].is_applied());
        assert_eq!(state.balance(b"alice"), 1_000 - 250 - 1);
        assert_eq!(state.balance(b"bob"), 1_000 + 250);
        assert_eq!(state.sequence(b"alice"), 1);
    }

    #[test]
    fn a_replayed_sequence_is_rejected_and_changes_nothing() {
        let mut state = genesis();
        let batch = Batch::new(vec![transaction(b"alice", 1, b"bob", 250)]);
        let _ = state.apply(&batch);
        let root = state.state_root();

        let outcomes = state.apply(&batch);
        assert_eq!(outcomes[0].reason(), Some(RejectReason::BadSequence));
        assert_eq!(state.state_root(), root);
    }

    #[test]
    fn an_unaffordable_transfer_is_rejected() {
        let mut state = genesis();
        let outcomes = state.apply(&Batch::new(vec![transaction(b"alice", 1, b"bob", 5_000)]));
        assert_eq!(outcomes[0].reason(), Some(RejectReason::InsufficientFunds));
        assert_eq!(state.balance(b"alice"), 1_000);
        assert_eq!(state.sequence(b"alice"), 0);
    }

    #[test]
    fn unknown_accounts_are_rejected() {
        let mut state = genesis();
        assert_eq!(
            state.apply(&Batch::new(vec![transaction(b"mallory", 1, b"bob", 1)]))[0].reason(),
            Some(RejectReason::UnknownSender)
        );
        assert_eq!(
            state.apply(&Batch::new(vec![transaction(b"alice", 1, b"nobody", 1)]))[0].reason(),
            Some(RejectReason::UnknownRecipient)
        );
    }

    #[test]
    fn a_self_transfer_is_rejected() {
        let mut state = genesis();
        assert_eq!(
            state.apply(&Batch::new(vec![transaction(b"alice", 1, b"alice", 1)]))[0].reason(),
            Some(RejectReason::SelfTransfer)
        );
    }

    #[test]
    fn a_malformed_payload_is_rejected() {
        let mut state = genesis();
        let mut broken = transaction(b"alice", 1, b"bob", 1);
        broken.payload = b"not a transfer".to_vec();
        assert_eq!(
            state.apply(&Batch::new(vec![broken]))[0].reason(),
            Some(RejectReason::MalformedPayload)
        );
    }

    #[test]
    fn the_same_batches_produce_the_same_root() {
        let batches = vec![
            Batch::new(vec![transaction(b"alice", 1, b"bob", 10)]),
            Batch::new(vec![transaction(b"bob", 1, b"alice", 3)]),
        ];
        let run = || {
            let mut state = genesis();
            for batch in &batches {
                let _ = state.apply(batch);
            }
            state.state_root()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn order_matters() {
        let first = Batch::new(vec![transaction(b"alice", 1, b"bob", 10)]);
        let second = Batch::new(vec![transaction(b"alice", 2, b"bob", 20)]);

        let mut forward = genesis();
        let _ = forward.apply(&first);
        let _ = forward.apply(&second);
        let mut backward = genesis();
        let _ = backward.apply(&second);
        let _ = backward.apply(&first);

        assert_ne!(
            forward.state_root(),
            backward.state_root(),
            "a consensus that orders differently must not produce the same state"
        );
    }

    #[test]
    fn an_account_proof_verifies_against_the_root() {
        let mut state = genesis();
        let _ = state.apply(&Batch::new(vec![
            transaction(b"alice", 1, b"bob", 250),
            transaction(b"bob", 1, b"alice", 10),
        ]));
        let root = state.state_root();

        for account in [b"alice".as_slice(), b"bob".as_slice()] {
            let proof = state.proof(account).expect("the account exists");
            assert!(
                proof.verify(&root),
                "{} did not verify",
                String::from_utf8_lossy(account)
            );
            assert_eq!(proof.balance, state.balance(account));
        }
        assert!(state.proof(b"nobody").is_none());
    }

    #[test]
    fn a_proof_with_a_tampered_balance_does_not_verify() {
        let state = genesis();
        let root = state.state_root();
        let mut proof = state.proof(b"alice").unwrap();
        proof.balance += 1;
        assert!(!proof.verify(&root));
    }

    #[test]
    fn the_root_does_not_depend_on_insertion_order() {
        let mut forward = State::new();
        forward.credit(b"alice", 10).unwrap();
        forward.credit(b"bob", 20).unwrap();

        let mut backward = State::new();
        backward.credit(b"bob", 20).unwrap();
        backward.credit(b"alice", 10).unwrap();

        assert_eq!(forward.state_root(), backward.state_root());
    }

    #[test]
    fn the_empty_state_root_is_defined() {
        let state = State::new();
        assert_eq!(
            state.state_root(),
            MerkleTree::from_leaves(Vec::new()).root()
        );
        assert!(state.proof(b"alice").is_none());
    }

    #[test]
    fn the_root_changes_when_only_the_sequence_changes() {
        let mut state = genesis();
        let before = state.state_root();
        let _ = state.apply(&Batch::new(vec![
            transaction(b"alice", 1, b"bob", 1),
            transaction(b"bob", 1, b"alice", 1),
        ]));
        assert_ne!(state.state_root(), before);
    }
}
