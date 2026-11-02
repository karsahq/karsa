//! A deterministic Merkle tree over account leaves.
//!
//! A flat hash of the whole state proves nothing to anyone who does not have the
//! whole state. A Merkle root does: a light client that holds only the root can be
//! shown one account and a short path, and can check it without trusting the
//! prover.
//!
//! Three details make the tree safe rather than merely present:
//!
//! - **Domain separation.** Leaves, internal nodes, and the empty tree hash under
//!   different tags, so no leaf can be replayed as an internal node and the empty
//!   root cannot collide with a real one.
//! - **Sorted by account.** Leaves come from a `BTreeMap`, so the tree shape is a
//!   function of the account set, never of insertion order.
//! - **No duplicated last node.** An odd node is promoted unchanged. Duplicating it
//!   would make two different account sets share a root, which is the classic
//!   Merkle malleability bug.
//!
//! A proof carries each sibling with its side, so verification is a fold and does
//! not have to reconstruct the level sizes.

use sha2::{Digest, Sha256};

/// Tag hashed in front of a leaf.
const LEAF_DOMAIN: u8 = 0x00;
/// Tag hashed in front of an internal node.
const NODE_DOMAIN: u8 = 0x01;
/// Tag hashed for a tree with no leaves.
const EMPTY_DOMAIN: u8 = 0x02;

/// The bound on proof length, so verifying hostile input cannot loop without end.
const MAX_PROOF_STEPS: usize = 64;

/// The leaf commitment for one account.
pub(crate) fn hash_leaf(account: &[u8], balance: u64, sequence: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN]);
    let length = u32::try_from(account.len()).unwrap_or(u32::MAX);
    hasher.update(length.to_le_bytes());
    hasher.update(account);
    hasher.update(balance.to_le_bytes());
    hasher.update(sequence.to_le_bytes());
    hasher.finalize().into()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_DOMAIN]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn empty_root() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([EMPTY_DOMAIN]);
    hasher.finalize().into()
}

/// One sibling on the path from a leaf to the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    /// Whether the sibling is the left child of the pair.
    pub sibling_is_left: bool,
    /// The sibling's hash.
    pub hash: [u8; 32],
}

/// A Merkle inclusion proof.
///
/// `leaf_index` and `leaf_count` are carried for diagnostics and range checking;
/// they are not needed to verify, because every step states its own side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Position of the leaf among the sorted leaves.
    pub leaf_index: usize,
    /// Number of leaves in the tree.
    pub leaf_count: usize,
    /// Siblings from the leaf upwards.
    pub steps: Vec<ProofStep>,
}

impl MerkleProof {
    /// Returns the tree height the proof claims.
    #[must_use]
    pub fn height(&self) -> usize {
        self.steps.len()
    }
}

/// A binary Merkle tree kept as one vector per level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Builds a tree over `leaves`, in the order given.
    #[must_use]
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        let mut levels = vec![leaves];
        while levels.last().is_some_and(|level| level.len() > 1) {
            let previous = levels.last().expect("a level was just checked");
            let mut next = Vec::with_capacity(previous.len().div_ceil(2));
            for pair in previous.chunks(2) {
                match pair {
                    [left, right] => next.push(hash_node(left, right)),
                    // An odd node is promoted, never paired with itself.
                    [only] => next.push(*only),
                    _ => {}
                }
            }
            levels.push(next);
        }
        Self { levels }
    }

    /// The root, or the empty-tree constant when there are no leaves.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or_else(empty_root)
    }

    /// Number of leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// Whether the tree has no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Builds an inclusion proof for `index`.
    #[must_use]
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        let leaf_count = self.len();
        if index >= leaf_count {
            return None;
        }
        let mut steps = Vec::new();
        let mut cursor = index;
        // Every level except the last, which holds the root.
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sibling = cursor ^ 1;
            if sibling < level.len() {
                steps.push(ProofStep {
                    sibling_is_left: sibling < cursor,
                    hash: level[sibling],
                });
            }
            // A promoted node has no sibling at this level and climbs unchanged.
            cursor /= 2;
        }
        Some(MerkleProof {
            leaf_index: index,
            leaf_count,
            steps,
        })
    }

    /// Verifies a proof against a root.
    #[must_use]
    pub fn verify(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
        if proof.steps.len() > MAX_PROOF_STEPS || proof.leaf_index >= proof.leaf_count {
            return false;
        }
        // A single-leaf tree has a root equal to its leaf and no steps.
        if proof.leaf_count == 1 && !proof.steps.is_empty() {
            return false;
        }
        let mut current = *leaf;
        for step in &proof.steps {
            current = if step.sibling_is_left {
                hash_node(&step.hash, &current)
            } else {
                hash_node(&current, &step.hash)
            };
        }
        current == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(count: usize) -> Vec<[u8; 32]> {
        (0..count)
            .map(|index| hash_leaf(format!("acct-{index}").as_bytes(), index as u64 + 1, 0))
            .collect()
    }

    #[test]
    fn an_empty_tree_has_a_domain_separated_root() {
        let tree = MerkleTree::from_leaves(Vec::new());
        assert_eq!(tree.root(), empty_root());
        assert!(tree.is_empty());
        assert!(tree.proof(0).is_none());
    }

    #[test]
    fn a_single_leaf_is_its_own_root() {
        let leaf = leaves(1);
        let tree = MerkleTree::from_leaves(leaf.clone());
        assert_eq!(tree.root(), leaf[0]);
        let proof = tree.proof(0).unwrap();
        assert!(proof.steps.is_empty());
        assert!(MerkleTree::verify(&tree.root(), &leaf[0], &proof));
    }

    #[test]
    fn every_leaf_of_every_small_tree_has_a_verifying_proof() {
        for count in 1..=17 {
            let leaf_hashes = leaves(count);
            let tree = MerkleTree::from_leaves(leaf_hashes.clone());
            let root = tree.root();
            for (index, leaf) in leaf_hashes.iter().enumerate() {
                let proof = tree.proof(index).expect("index is in range");
                assert!(
                    MerkleTree::verify(&root, leaf, &proof),
                    "leaf {index} of {count} did not verify"
                );
            }
        }
    }

    #[test]
    fn a_tampered_leaf_does_not_verify() {
        let leaves = leaves(9);
        let tree = MerkleTree::from_leaves(leaves);
        let proof = tree.proof(4).unwrap();
        let tampered = hash_leaf(b"acct-4", 1_000_000, 0);
        assert!(!MerkleTree::verify(&tree.root(), &tampered, &proof));
    }

    #[test]
    fn a_proof_does_not_verify_against_another_root() {
        let five = leaves(5);
        let tree = MerkleTree::from_leaves(five.clone());
        let other = MerkleTree::from_leaves(leaves(6));
        let proof = tree.proof(2).unwrap();
        assert!(!MerkleTree::verify(&other.root(), &five[2], &proof));
    }

    #[test]
    fn an_out_of_range_proof_is_refused() {
        let leaves = leaves(3);
        let tree = MerkleTree::from_leaves(leaves.clone());
        let mut proof = tree.proof(0).unwrap();
        proof.leaf_count = 0;
        assert!(!MerkleTree::verify(&tree.root(), &leaves[0], &proof));
        assert!(tree.proof(3).is_none());
    }

    #[test]
    fn the_same_leaves_produce_the_same_root() {
        let first = MerkleTree::from_leaves(leaves(11));
        let second = MerkleTree::from_leaves(leaves(11));
        assert_eq!(first.root(), second.root());
    }

    #[test]
    fn a_promoted_leaf_differs_from_a_duplicated_one() {
        let three = leaves(3);
        let tree = MerkleTree::from_leaves(three.clone());
        // Duplicating the odd node is the malleability bug: it would make this
        // equal to a four-leaf tree over the same three leaves.
        let duplicated = MerkleTree::from_leaves(vec![three[0], three[1], three[2], three[2]]);
        assert_ne!(tree.root(), duplicated.root());
    }

    #[test]
    fn proofs_of_different_leaves_are_not_interchangeable() {
        let leaves = leaves(8);
        let tree = MerkleTree::from_leaves(leaves.clone());
        let first = tree.proof(1).unwrap();
        assert!(!MerkleTree::verify(&tree.root(), &leaves[2], &first));
    }
}
