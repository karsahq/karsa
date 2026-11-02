//! A deterministic Merkle tree, and the leaf commitment that feeds it.
//!
//! A flat hash of a whole set proves nothing to anyone who does not hold the whole
//! set. A Merkle root does: a holder of only the root can be shown one element and
//! a short path, and can check it without trusting the prover.
//!
//! Three details make the tree safe rather than merely present:
//!
//! - **Domain separation, in two layers.** Leaves, internal nodes, and the empty
//!   tree hash under different structural tags, so no leaf can be replayed as an
//!   internal node and the empty root cannot collide with a real one. On top of
//!   that, [`leaf`] prefixes a caller-supplied domain, so an account leaf can never
//!   be confused with a commit leaf.
//! - **Caller-defined order.** Leaves are hashed in the order given. Callers that
//!   need an order-independent root must sort their elements first; the tree does
//!   not guess.
//! - **No duplicated last node.** An odd node is promoted unchanged. Duplicating it
//!   would let two different sets share a root, which is the classic Merkle
//!   malleability bug.
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

/// The leaf commitment for one element.
///
/// `domain` names what kind of leaf this is, and every `part` is length-prefixed,
/// so `["ab", "c"]` and `["a", "bc"]` produce different leaves.
#[must_use]
pub fn leaf(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN]);
    hasher.update(
        u32::try_from(domain.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    hasher.update(domain);
    for part in parts {
        hasher.update(u32::try_from(part.len()).unwrap_or(u32::MAX).to_le_bytes());
        hasher.update(part);
    }
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
    /// Position of the leaf in the order the tree was built from.
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

    /// The root of this tree, or the empty-tree constant when it has no leaves.
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
            .map(|index| {
                leaf(
                    b"KARSA/TEST/v1",
                    &[format!("acct-{index}").as_bytes(), &[0, 1]],
                )
            })
            .collect()
    }

    #[test]
    fn a_leaf_is_bound_to_its_domain_and_its_part_boundaries() {
        assert_ne!(leaf(b"a", &[b"bc"]), leaf(b"a", &[b"b", b"c"]));
        assert_ne!(leaf(b"a", &[b"bc"]), leaf(b"b", &[b"bc"]));
        assert_eq!(leaf(b"a", &[b"bc"]), leaf(b"a", &[b"bc"]));
    }

    #[test]
    fn an_empty_tree_has_a_domain_separated_root() {
        let tree = MerkleTree::from_leaves(Vec::new());
        assert_eq!(tree.root(), empty_root());
        assert!(tree.is_empty());
        assert!(tree.proof(0).is_none());
        assert_ne!(empty_root(), leaf(b"anything", &[]));
    }

    #[test]
    fn a_single_leaf_is_its_own_root() {
        let leaf_hashes = leaves(1);
        let tree = MerkleTree::from_leaves(leaf_hashes.clone());
        assert_eq!(tree.root(), leaf_hashes[0]);
        let proof = tree.proof(0).unwrap();
        assert!(proof.steps.is_empty());
        assert!(MerkleTree::verify(&tree.root(), &leaf_hashes[0], &proof));
    }

    #[test]
    fn every_leaf_of_every_small_tree_has_a_verifying_proof() {
        for count in 1..=17 {
            let leaf_hashes = leaves(count);
            let tree = MerkleTree::from_leaves(leaf_hashes.clone());
            let root = tree.root();
            for (index, hash) in leaf_hashes.iter().enumerate() {
                let proof = tree.proof(index).expect("index is in range");
                assert!(
                    MerkleTree::verify(&root, hash, &proof),
                    "leaf {index} of {count} did not verify"
                );
            }
        }
    }

    #[test]
    fn a_tampered_leaf_does_not_verify() {
        let leaf_hashes = leaves(9);
        let tree = MerkleTree::from_leaves(leaf_hashes.clone());
        let proof = tree.proof(4).unwrap();
        let tampered = leaf(b"KARSA/TEST/v1", &[b"acct-4-tampered", &[0, 1]]);
        assert_ne!(tampered, leaf_hashes[4]);
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
        let leaf_hashes = leaves(3);
        let tree = MerkleTree::from_leaves(leaf_hashes.clone());
        let mut proof = tree.proof(0).unwrap();
        proof.leaf_count = 0;
        assert!(!MerkleTree::verify(&tree.root(), &leaf_hashes[0], &proof));
        assert!(tree.proof(3).is_none());
    }

    #[test]
    fn a_promoted_leaf_differs_from_a_duplicated_one() {
        let three = leaves(3);
        let tree = MerkleTree::from_leaves(three.clone());
        let duplicated = MerkleTree::from_leaves(vec![three[0], three[1], three[2], three[2]]);
        assert_ne!(tree.root(), duplicated.root());
    }

    #[test]
    fn a_truncated_proof_fails_rather_than_looping() {
        let leaf_hashes = leaves(8);
        let tree = MerkleTree::from_leaves(leaf_hashes.clone());
        let mut proof = tree.proof(1).unwrap();
        proof.steps.truncate(1);
        assert!(!MerkleTree::verify(&tree.root(), &leaf_hashes[1], &proof));
    }

    #[test]
    fn the_tree_reports_its_own_length() {
        assert_eq!(MerkleTree::from_leaves(leaves(7)).len(), 7);
        assert_eq!(MerkleTree::from_leaves(Vec::new()).len(), 0);
    }
}
