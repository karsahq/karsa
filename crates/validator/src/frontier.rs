//! A compact commitment to a committed order prefix.
//!
//! A header's `dag_root` commits every entry in the committed order, so a node
//! that restarts from a checkpoint would otherwise have to persist the whole
//! prefix. The prefix below a DAG floor does not need to be replayed or re-executed;
//! its only remaining job is to contribute to the next root. This module keeps that
//! contribution as the peaks of the promoted Merkle tree: the roots of the perfect
//! subtrees the binary length decomposes into.
//!
//! The peaks are exactly the nodes a standard binary counter would carry: appending
//! a leaf merges the trailing one-bits of the old length from right to left. The
//! root is the same fold those peaks give the full tree, so a header built from
//! `frontier + tail` cannot drift from a header built from the whole order.

use crypto::merkle::{MerkleProof, ProofStep, combine};
use crypto::{CryptoError, CryptoErrorKind};
use std::collections::BTreeMap;

use crate::dag::{commit_leaf, commit_root};
use crate::vertex::VertexId;

/// The peaks of the promoted Merkle tree over a committed order prefix.
///
/// `len` is the number of leaves covered; `peaks` are the perfect-subtree roots
/// from left to right, in descending subtree size. For example, a prefix of 13
/// entries has peaks of sizes 8, 4, and 1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitFrontier {
    len: usize,
    peaks: Vec<[u8; 32]>,
}

impl CommitFrontier {
    /// An empty prefix.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            len: 0,
            peaks: Vec::new(),
        }
    }

    /// Summarizes a whole committed order.
    #[must_use]
    pub fn from_order(order: &[VertexId]) -> Self {
        let mut frontier = Self::empty();
        frontier.extend(order);
        frontier
    }

    /// Rebuilds a frontier from persisted peaks.
    ///
    /// The count must match the set bits of `len`; a peak list that does not is a
    /// corrupt or misaligned record, not a frontier with a different shape.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::InvalidVertex`] when the peak count does not match `len`.
    pub fn from_peaks(len: usize, peaks: Vec<[u8; 32]>) -> Result<Self, CryptoError> {
        let expected = len.count_ones() as usize;
        if peaks.len() != expected {
            return Err(CryptoError::new(
                CryptoErrorKind::InvalidVertex,
                format!(
                    "a committed prefix of {len} entries has {expected} peaks, not {}",
                    peaks.len()
                ),
            ));
        }
        Ok(Self { len, peaks })
    }

    /// Entries covered by this prefix.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether this prefix covers no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The perfect-subtree roots, left to right.
    #[must_use]
    pub fn peaks(&self) -> &[[u8; 32]] {
        &self.peaks
    }

    /// Appends one committed vertex.
    pub fn push(&mut self, id: &VertexId) {
        self.push_leaf(commit_leaf(id));
    }

    /// Appends a whole committed suffix.
    pub fn extend(&mut self, order: &[VertexId]) {
        for id in order {
            self.push(id);
        }
    }

    /// Appends one already-hashed leaf.
    pub fn push_leaf(&mut self, leaf: [u8; 32]) {
        let mut node = leaf;
        let mut size = 1usize;
        while (self.len & size) != 0 {
            let left = self
                .peaks
                .pop()
                .expect("a set bit of the length names a peak");
            node = combine(&left, &node);
            size = size.checked_shl(1).unwrap_or(0);
            if size == 0 {
                break;
            }
        }
        self.peaks.push(node);
        self.len = self.len.saturating_add(1);
    }

    /// The Merkle root over this prefix.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        root_of(self.len, &self.peaks)
    }

    /// The root after appending the first `count` entries of `tail`.
    ///
    /// Returns `None` when `count` is longer than `tail`; callers use that as a
    /// consistency error instead of silently covering a shorter prefix.
    #[must_use]
    pub fn root_at(&self, tail: &[VertexId], count: usize) -> Option<[u8; 32]> {
        if count > tail.len() {
            return None;
        }
        let mut peaks = self.peaks.clone();
        let mut len = self.len;
        for id in &tail[..count] {
            push_leaf_into(&mut peaks, &mut len, commit_leaf(id));
        }
        Some(root_of(len, &peaks))
    }

    /// Builds an inclusion proof for a leaf in `tail`.
    ///
    /// Only leaves above the retained prefix can be proven this way: the prefix's
    /// leaves are gone, and its peaks supply exactly the siblings a tail path
    /// needs. An old leaf below the floor has no proof because the node no longer
    /// holds the data to produce one.
    #[must_use]
    pub fn proof_for(&self, tail: &[VertexId], index: usize) -> Option<MerkleProof> {
        if index >= tail.len() {
            return None;
        }
        let leaf_index = self.len.checked_add(index)?;
        let leaf_count = self.len.checked_add(tail.len())?;
        let mut steps = Vec::new();
        let mut cursor = leaf_index;
        let mut level_len = leaf_count;
        let mut size = 1usize;
        while level_len > 1 {
            let sibling = cursor ^ 1;
            if sibling < level_len {
                let start = sibling.checked_mul(size)?;
                steps.push(ProofStep {
                    sibling_is_left: sibling < cursor,
                    hash: self.node_root(tail, start, size)?,
                });
            }
            cursor /= 2;
            level_len = level_len.div_ceil(2);
            size = size.checked_shl(1)?;
        }
        Some(MerkleProof {
            leaf_index,
            leaf_count,
            steps,
        })
    }

    /// The root of the aligned subtree `[start, start + size)` in the full tree.
    ///
    /// The range is covered by whole prefix peaks and a suffix of the tail. Those
    /// segments are placed at the levels their subtree size names, then merged
    /// level by level with the same promotion rule the full tree uses. A range
    /// that overlaps a peak without containing it cannot be reconstructed from the
    /// frontier, so it reports `None` rather than a wrong sibling.
    fn node_root(&self, tail: &[VertexId], start: usize, size: usize) -> Option<[u8; 32]> {
        let leaf_count = self.len.checked_add(tail.len())?;
        if start >= leaf_count || !size.is_power_of_two() {
            return None;
        }
        let end = start.saturating_add(size).min(leaf_count);
        let level_count = size.trailing_zeros() as usize;
        let mut levels: Vec<BTreeMap<usize, (usize, [u8; 32])>> =
            (0..=level_count).map(|_| BTreeMap::new()).collect();

        let mut position = 0usize;
        for (index, peak) in self.peaks.iter().enumerate() {
            let peak_size = peak_size_at(self.len, index)?;
            let peak_end = position.checked_add(peak_size)?;
            if position >= start && peak_end <= end {
                let level = peak_size.trailing_zeros() as usize;
                if level > level_count {
                    return None;
                }
                if levels[level]
                    .insert(position / peak_size, (peak_size, *peak))
                    .is_some()
                {
                    return None;
                }
            } else if position < end && peak_end > start {
                return None;
            }
            position = peak_end;
        }

        let tail_from = start.max(self.len);
        if tail_from < end {
            for (offset, id) in tail[tail_from - self.len..end - self.len]
                .iter()
                .enumerate()
            {
                if levels[0]
                    .insert(tail_from + offset, (1, commit_leaf(id)))
                    .is_some()
                {
                    return None;
                }
            }
        }

        for level in 0..level_count {
            let nodes = std::mem::take(&mut levels[level]);
            let mut next = BTreeMap::new();
            let mut nodes = nodes.into_iter().peekable();
            while let Some((index, node)) = nodes.next() {
                if index % 2 == 1 {
                    return None;
                }
                if let Some((right_index, right)) = nodes.peek()
                    && *right_index == index + 1
                {
                    let right = *right;
                    nodes.next();
                    next.insert(index / 2, (node.0 + right.0, combine(&node.1, &right.1)));
                    continue;
                }
                next.insert(index / 2, node);
            }
            for (index, node) in next {
                if levels[level + 1].insert(index, node).is_some() {
                    return None;
                }
            }
        }

        let (_, (_, root)) = levels[level_count].iter().next()?;
        if levels[level_count].len() != 1 {
            return None;
        }
        Some(*root)
    }
}

/// The root of `len` leaves summarized by `peaks`, folded right to left.
fn root_of(len: usize, peaks: &[[u8; 32]]) -> [u8; 32] {
    if len == 0 {
        return commit_root(&[]);
    }
    let mut root = *peaks.last().expect("a non-empty prefix has a peak");
    for peak in peaks.iter().rev().skip(1) {
        root = combine(peak, &root);
    }
    root
}

fn push_leaf_into(peaks: &mut Vec<[u8; 32]>, len: &mut usize, leaf: [u8; 32]) {
    let mut node = leaf;
    let mut size = 1usize;
    while (*len & size) != 0 {
        let left = peaks.pop().expect("a set bit of the length names a peak");
        node = combine(&left, &node);
        size = size.checked_shl(1).unwrap_or(0);
        if size == 0 {
            break;
        }
    }
    peaks.push(node);
    *len = len.saturating_add(1);
}

/// The size of the `index`-th peak of a prefix, from the set bits of its length.
fn peak_size_at(len: usize, index: usize) -> Option<usize> {
    (0..usize::BITS)
        .rev()
        .filter(|bit| (len >> bit) & 1 == 1)
        .nth(index)
        .map(|bit| 1usize << bit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::merkle::MerkleTree;

    fn id(round: u64) -> VertexId {
        VertexId {
            round,
            author: b"val-0".to_vec(),
            digest: [u8::try_from(round % 256).unwrap(); 32],
        }
    }

    fn order(count: usize) -> Vec<VertexId> {
        (0..u64::try_from(count).unwrap()).map(id).collect()
    }

    #[test]
    fn a_frontier_root_matches_the_full_commit_root_at_every_length() {
        let order = order(70);
        let mut frontier = CommitFrontier::empty();
        assert_eq!(frontier.root(), commit_root(&[]));
        for (index, id) in order.iter().enumerate() {
            frontier.push(id);
            assert_eq!(
                frontier.root(),
                commit_root(&order[..=index]),
                "root after {} entries",
                index + 1
            );
        }
    }

    #[test]
    fn a_split_frontier_roots_like_the_whole_order() {
        let order = order(96);
        for prefix in 0..=64 {
            let frontier = CommitFrontier::from_order(&order[..prefix]);
            for tail in 0..=24 {
                let total = prefix + tail;
                let tail_slice = &order[prefix..total];
                assert_eq!(
                    frontier.root_at(tail_slice, tail),
                    Some(commit_root(&order[..total])),
                    "prefix {prefix}, tail {tail}"
                );
            }
        }
    }

    #[test]
    fn persisted_peaks_rebuild_the_same_root() {
        for count in 0..=32usize {
            let frontier = CommitFrontier::from_order(&order(count));
            let rebuilt = CommitFrontier::from_peaks(frontier.len(), frontier.peaks().to_vec())
                .expect("the recorded peaks are consistent");
            assert_eq!(rebuilt, frontier);
            assert_eq!(rebuilt.root(), frontier.root());
        }
    }

    #[test]
    fn a_peak_count_that_does_not_match_the_length_is_refused() {
        let error = CommitFrontier::from_peaks(3, vec![[1u8; 32]]).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidVertex);
    }

    #[test]
    fn every_tail_leaf_has_a_verifying_proof() {
        let order = order(160);
        for prefix in 0..=64usize {
            for tail_len in 0..=24usize {
                let total = prefix + tail_len;
                let frontier = CommitFrontier::from_order(&order[..prefix]);
                let tail = &order[prefix..total];
                let root = commit_root(&order[..total]);
                for index in 0..tail.len() {
                    let proof = frontier.proof_for(tail, index).unwrap_or_else(|| {
                        panic!("no proof for prefix {prefix}, tail {tail_len}, index {index}")
                    });
                    assert!(
                        MerkleTree::verify(&root, &commit_leaf(&tail[index]), &proof),
                        "prefix {prefix}, tail {tail_len}, index {index}"
                    );
                }
            }
        }
    }
}
