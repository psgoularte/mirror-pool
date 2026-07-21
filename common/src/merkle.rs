//! Off-chain reference Merkle tree (fixed-depth, Poseidon two-to-one).
//!
//! This is the prover-side / client-side tree: the CLI builds it to produce the
//! `path_elements` / `path_indices` witness the circuit consumes, and tests use
//! it as the reference the on-chain incremental tree (milestone 4) must match
//! root-for-root. It is intentionally simple (recompute from stored leaves)
//! rather than incremental — clarity over speed off-chain.
//!
//! Leaf and node hashing uses [`crate::poseidon`], so this tree hashes
//! identically to the circuit gadget and the on-chain hasher.

use crate::poseidon::hash_pair;
use crate::{CommonError, Result, TREE_DEPTH};
use ark_bn254::Fr;
use ark_ff::AdditiveGroup;

/// An authentication path from a leaf to the root.
///
/// `path_elements[i]` is the sibling hash at level `i` (0 = leaf level), and
/// `path_indices[i]` is `true` iff the current node is the **right** child at
/// that level (so the parent is `Poseidon(sibling, current)`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub path_elements: Vec<Fr>,
    pub path_indices: Vec<bool>,
}

/// Precomputed "empty subtree" hashes: `zeros[0]` is the empty-leaf value and
/// `zeros[i] = Poseidon(zeros[i-1], zeros[i-1])`. Index `i` is the value of a
/// node at level `i` whose entire subtree is empty. There are `depth + 1`
/// entries (`zeros[depth]` is the empty-tree root).
pub fn zero_hashes(depth: usize) -> Vec<Fr> {
    let mut zeros = Vec::with_capacity(depth + 1);
    zeros.push(Fr::ZERO); // empty leaf
    for i in 1..=depth {
        let prev = zeros[i - 1];
        zeros.push(hash_pair(prev, prev));
    }
    zeros
}

/// A fixed-depth Merkle tree over Poseidon, filled left to right.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    depth: usize,
    zeros: Vec<Fr>,
    leaves: Vec<Fr>,
}

impl MerkleTree {
    /// Create an empty tree of the given depth.
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            zeros: zero_hashes(depth),
            leaves: Vec::new(),
        }
    }

    /// Create an empty tree at the protocol's canonical [`TREE_DEPTH`].
    pub fn with_protocol_depth() -> Self {
        Self::new(TREE_DEPTH)
    }

    /// Number of leaves currently in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append a leaf, returning its index. Fails if the tree is full.
    pub fn insert(&mut self, leaf: Fr) -> Result<usize> {
        let capacity = 1usize << self.depth;
        if self.leaves.len() >= capacity {
            return Err(CommonError::MerklePathLength {
                got: self.leaves.len(),
                expected: capacity,
            });
        }
        let index = self.leaves.len();
        self.leaves.push(leaf);
        Ok(index)
    }

    /// Hash one level into the next, padding a missing right sibling with the
    /// level's empty-subtree hash.
    fn next_level(nodes: &[Fr], zero_at_level: Fr) -> Vec<Fr> {
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut i = 0;
        while i < nodes.len() {
            let left = nodes[i];
            let right = nodes.get(i + 1).copied().unwrap_or(zero_at_level);
            next.push(hash_pair(left, right));
            i += 2;
        }
        next
    }

    /// The current root. An empty tree returns the all-zero-subtree root.
    pub fn root(&self) -> Fr {
        if self.leaves.is_empty() {
            return self.zeros[self.depth];
        }
        let mut level = self.leaves.clone();
        for depth_level in 0..self.depth {
            level = Self::next_level(&level, self.zeros[depth_level]);
        }
        level[0]
    }

    /// Produce the authentication path for the leaf at `index`.
    pub fn proof(&self, index: usize) -> Result<MerkleProof> {
        if index >= self.leaves.len() {
            return Err(CommonError::MerklePathLength {
                got: index,
                expected: self.leaves.len(),
            });
        }
        let mut path_elements = Vec::with_capacity(self.depth);
        let mut path_indices = Vec::with_capacity(self.depth);
        let mut level = self.leaves.clone();
        let mut cur = index;
        for depth_level in 0..self.depth {
            let is_right = cur & 1 == 1;
            let sibling_index = if is_right { cur - 1 } else { cur + 1 };
            let sibling = level
                .get(sibling_index)
                .copied()
                .unwrap_or(self.zeros[depth_level]);
            path_elements.push(sibling);
            path_indices.push(is_right);
            level = Self::next_level(&level, self.zeros[depth_level]);
            cur >>= 1;
        }
        Ok(MerkleProof {
            path_elements,
            path_indices,
        })
    }
}

/// Recompute a root from a leaf and its authentication path — the native
/// analogue of the circuit's Merkle-inclusion constraint.
pub fn root_from_proof(leaf: Fr, proof: &MerkleProof) -> Result<Fr> {
    if proof.path_elements.len() != proof.path_indices.len() {
        return Err(CommonError::MerklePathLength {
            got: proof.path_indices.len(),
            expected: proof.path_elements.len(),
        });
    }
    let mut cur = leaf;
    for (sibling, is_right) in proof.path_elements.iter().zip(proof.path_indices.iter()) {
        cur = if *is_right {
            hash_pair(*sibling, cur)
        } else {
            hash_pair(cur, *sibling)
        };
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::commitment;

    #[test]
    fn proof_recomputes_root() {
        let mut tree = MerkleTree::new(TREE_DEPTH);
        let leaves: Vec<Fr> = (0..17u64).map(|i| commitment(Fr::from(i + 1))).collect();
        for l in &leaves {
            tree.insert(*l).unwrap();
        }
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert_eq!(proof.path_elements.len(), TREE_DEPTH);
            assert_eq!(root_from_proof(*leaf, &proof).unwrap(), root, "leaf {i}");
        }
    }

    #[test]
    fn empty_tree_root_is_zero_subtree() {
        let tree = MerkleTree::new(TREE_DEPTH);
        assert_eq!(tree.root(), zero_hashes(TREE_DEPTH)[TREE_DEPTH]);
    }

    #[test]
    fn single_leaf_root_matches_manual_fold() {
        let mut tree = MerkleTree::new(3);
        let leaf = commitment(Fr::from(99u64));
        tree.insert(leaf).unwrap();
        let zeros = zero_hashes(3);
        // leaf is left child at every level, siblings are empty subtrees.
        let mut expected = leaf;
        for z in zeros.iter().take(3) {
            expected = hash_pair(expected, *z);
        }
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn wrong_leaf_fails_verification() {
        let mut tree = MerkleTree::new(TREE_DEPTH);
        for i in 0..8u64 {
            tree.insert(commitment(Fr::from(i + 1))).unwrap();
        }
        let proof = tree.proof(3).unwrap();
        let wrong = commitment(Fr::from(999u64));
        assert_ne!(root_from_proof(wrong, &proof).unwrap(), tree.root());
    }
}
