//! On-chain account state.
//!
//! Milestone 4 introduces [`PoolConfig`]: the incremental Merkle tree (filled
//! subtrees + current root), the root-history ring buffer, and administrative
//! fields. Later milestones extend it with the epoch schedule, fee params, and
//! the compliance-authority registry.
//!
//! `PoolConfig` is a zero-copy [`bytemuck::Pod`] type: the program casts it
//! directly out of the account buffer and mutates it in place, so the 3.4 KB
//! struct never lands on the 4 KB BPF stack (borsh-deserializing it by value
//! overflows the frame). To keep alignment at 1 — account data is only
//! byte-aligned — the `u64` counters are stored as little-endian `[u8; 8]`.

use crate::error::MirrorPoolError;
use crate::merkle::{hash_pair, zero_hashes};
use crate::verifier::VK_SERIALIZED_LEN;
use borsh::{BorshDeserialize, BorshSerialize};
use bytemuck::{Pod, Zeroable};
use mirror_pool_common::{ROOT_HISTORY_SIZE, TREE_DEPTH};
use solana_program::program_error::ProgramError;

/// PDA seed prefix for a pool config account.
pub const POOL_SEED: &[u8] = b"pool";
/// PDA seed prefix for a per-commitment viewing-key disclosure record.
pub const VIEWING_SEED: &[u8] = b"viewing";

/// A selective-disclosure record: a member's commitment, the auditor they
/// designated, and the member's `secret` sealed to that auditor's viewing key.
///
/// Stored on-chain so disclosure is persistent and auditable. The ciphertext is
/// public but only the named auditor can open it (see
/// `mirror_pool_common::compliance`); it reveals nothing to anyone else and
/// nothing about non-disclosing members.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct DisclosureRecord {
    pub commitment: [u8; 32],
    pub auditor: [u8; 32],
    pub sealed_secret: Vec<u8>,
}

impl DisclosureRecord {
    /// Cap on the sealed ciphertext, so account sizing is bounded. An ECIES
    /// blob for a 32-byte secret is `32 + 12 + 48 = 92` bytes; 128 is ample.
    pub const MAX_SEALED_LEN: usize = 128;

    /// Serialized length for this record (borsh: 32 + 32 + 4 + len).
    pub fn serialized_len(&self) -> usize {
        32 + 32 + 4 + self.sealed_secret.len()
    }
}

/// Pool configuration + incremental Merkle tree state (zero-copy, `align = 1`).
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct PoolConfig {
    /// 1 once initialized, 0 otherwise.
    pub is_initialized: u8,
    /// PDA bump for this pool account.
    pub bump: u8,
    /// Tree depth (must equal [`TREE_DEPTH`]).
    pub depth: u8,
    /// Admin / upgrade authority (raw pubkey bytes).
    pub authority: [u8; 32],
    /// Number of leaves inserted so far; also the next leaf index (LE bytes;
    /// use [`Self::next_index`]).
    pub next_index: [u8; 8],
    /// Index of the most recently written slot in `root_history` (LE bytes;
    /// use [`Self::root_history_index`]).
    pub root_history_index: [u8; 8],
    /// Current Merkle root.
    pub current_root: [u8; 32],
    /// Ring buffer of recent roots so proofs survive concurrent deposits.
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    /// Rightmost filled node at each level (incremental-tree state).
    pub filled_subtrees: [[u8; 32]; TREE_DEPTH],
    /// Empty-subtree hash at each level (constant after init).
    pub zeros: [[u8; 32]; TREE_DEPTH],
    /// Current epoch id (LE bytes; use [`Self::current_epoch`]). Actions are
    /// valid only inside their epoch window (advanced by the crank in M6).
    pub current_epoch: [u8; 8],
    /// The membership circuit's Groth16 verifying key, in the flat on-chain
    /// layout parsed by [`crate::verifier::ParsedVerifyingKey`].
    pub verifying_key: [u8; VK_SERIALIZED_LEN],
    /// 1 while an epoch window is open (actions allowed), 0 otherwise.
    pub epoch_active: u8,
    /// Deposit-screening authority. All-zero means screening is **off** (the
    /// default). When set, every deposit must be co-signed by this key — a
    /// pluggable hook: point it at an allowlist/attestation program's authority
    /// to gate entry. Documented as opt-in.
    pub screening_authority: [u8; 32],
    /// Minimum guaranteed anonymity set (`k_min`, LE bytes; use [`Self::k_min`]).
    /// `execute_action` rejects unless the on-chain lower bound
    /// `members - actions_this_epoch >= k_min`.
    pub k_min: [u8; 8],
    /// Successful actions in the current epoch (LE bytes; use
    /// [`Self::epoch_actions`]). Reset to 0 by `open_epoch`.
    pub epoch_actions: [u8; 8],
    /// Anti-Sybil entry fee in lamports charged on every `deposit` (LE bytes;
    /// use [`Self::entry_fee`]). `0` disables the fee, reproducing the original
    /// permissionless-deposit behavior exactly. When non-zero, each deposit must
    /// pay this fee into the pool PDA (the fee vault), so inflating the anonymity
    /// set with Sybil commitments costs real lamports per fake identity. This
    /// **prices** Sybil inflation; it does not make it impossible.
    ///
    /// Appended at the tail of the struct so existing field offsets are
    /// unchanged (additive layout change).
    pub entry_fee: [u8; 8],
}

impl PoolConfig {
    /// Exact account length (`= size_of::<PoolConfig>()`, no padding at align 1).
    pub const LEN: usize = 1
        + 1
        + 1
        + 32
        + 8
        + 8
        + 32
        + (ROOT_HISTORY_SIZE * 32)
        + (TREE_DEPTH * 32)
        + (TREE_DEPTH * 32)
        + 8
        + VK_SERIALIZED_LEN
        + 1
        + 32
        + 8
        + 8
        + 8;

    /// Reinterpret an account's bytes as a mutable `PoolConfig` (no copy).
    pub fn load_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        bytemuck::try_from_bytes_mut(data)
            .map_err(|_| MirrorPoolError::InvalidInstructionData.into())
    }

    /// Reinterpret an account's bytes as a shared `PoolConfig` (no copy).
    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        bytemuck::try_from_bytes(data).map_err(|_| MirrorPoolError::InvalidInstructionData.into())
    }

    pub fn next_index(&self) -> u64 {
        u64::from_le_bytes(self.next_index)
    }

    pub fn root_history_index(&self) -> u64 {
        u64::from_le_bytes(self.root_history_index)
    }

    pub fn current_epoch(&self) -> u64 {
        u64::from_le_bytes(self.current_epoch)
    }

    pub fn k_min(&self) -> u64 {
        u64::from_le_bytes(self.k_min)
    }

    pub fn epoch_actions(&self) -> u64 {
        u64::from_le_bytes(self.epoch_actions)
    }

    /// The anti-Sybil entry fee in lamports (`0` = disabled).
    pub fn entry_fee(&self) -> u64 {
        u64::from_le_bytes(self.entry_fee)
    }

    /// The on-chain lower bound on the anonymity set for the *next* action this
    /// epoch: the number of deposited members who provably have not acted yet
    /// (`members - actions_this_epoch`). This is a conservative floor — an
    /// observer, unable to link nullifiers to commitments, generally sees the
    /// full membership as candidates; this bound is what the program can prove
    /// from its own state.
    pub fn anonymity_lower_bound(&self) -> u64 {
        self.next_index().saturating_sub(self.epoch_actions())
    }

    /// Record one successful action this epoch (increments the counter).
    pub fn record_action(&mut self) {
        self.epoch_actions = self.epoch_actions().saturating_add(1).to_le_bytes();
    }

    /// Initialize an empty pool in place. Fails if already initialized or the
    /// depth is unsupported.
    pub fn initialize(
        &mut self,
        authority: [u8; 32],
        bump: u8,
        depth: u8,
        k_min: u64,
        entry_fee: u64,
        verifying_key: &[u8; VK_SERIALIZED_LEN],
    ) -> Result<(), ProgramError> {
        if self.is_initialized != 0 {
            return Err(MirrorPoolError::AlreadyInitialized.into());
        }
        if depth as usize != TREE_DEPTH {
            return Err(MirrorPoolError::InvalidTreeDepth.into());
        }
        // zeros_full has TREE_DEPTH + 1 entries; the last is the empty-tree root.
        let zeros_full = zero_hashes(TREE_DEPTH)?;

        self.is_initialized = 1;
        self.authority = authority;
        self.bump = bump;
        self.depth = depth;
        self.next_index = 0u64.to_le_bytes();
        self.root_history_index = 0u64.to_le_bytes();
        self.current_epoch = 0u64.to_le_bytes();
        self.current_root = zeros_full[TREE_DEPTH];
        self.root_history = [[0u8; 32]; ROOT_HISTORY_SIZE];
        self.root_history[0] = zeros_full[TREE_DEPTH];
        self.zeros.copy_from_slice(&zeros_full[..TREE_DEPTH]);
        self.filled_subtrees
            .copy_from_slice(&zeros_full[..TREE_DEPTH]);
        self.verifying_key.copy_from_slice(verifying_key);
        self.epoch_active = 0;
        self.screening_authority = [0u8; 32]; // screening off by default
        self.k_min = k_min.to_le_bytes();
        self.epoch_actions = 0u64.to_le_bytes();
        self.entry_fee = entry_fee.to_le_bytes();
        Ok(())
    }

    /// Whether deposit screening is enabled (a non-zero authority is set).
    pub fn screening_enabled(&self) -> bool {
        self.screening_authority != [0u8; 32]
    }

    /// Open a new epoch window (crank). Advances `current_epoch` and marks it
    /// active, so actions proved against it are accepted. Fails if one is open.
    pub fn open_epoch(&mut self) -> Result<u64, ProgramError> {
        if self.epoch_active != 0 {
            return Err(MirrorPoolError::EpochAlreadyOpen.into());
        }
        let next = self
            .current_epoch()
            .checked_add(1)
            .ok_or(ProgramError::from(MirrorPoolError::EpochAlreadyOpen))?;
        self.current_epoch = next.to_le_bytes();
        self.epoch_active = 1;
        self.epoch_actions = 0u64.to_le_bytes(); // reset the per-epoch action count
        Ok(next)
    }

    /// Close the current epoch window (crank). Actions are then rejected until
    /// the next `open_epoch`, forcing per-window crowd synchronization.
    pub fn close_epoch(&mut self) -> Result<(), ProgramError> {
        if self.epoch_active == 0 {
            return Err(MirrorPoolError::EpochNotActive.into());
        }
        self.epoch_active = 0;
        Ok(())
    }

    /// Whether `root` is the current root or one of the retained recent roots.
    pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
        if root.iter().all(|b| *b == 0) {
            return false; // all-zero is never a real tree root
        }
        self.current_root == *root || self.root_history.iter().any(|r| r == root)
    }

    /// Insert a leaf, advancing the tree and pushing the new root to history.
    /// Returns the leaf's index. Fails loudly if the tree is full.
    pub fn insert(&mut self, leaf: [u8; 32]) -> Result<u64, ProgramError> {
        let capacity: u64 = 1u64 << self.depth;
        let leaf_index = self.next_index();
        if leaf_index >= capacity {
            return Err(MirrorPoolError::TreeFull.into());
        }

        let mut idx = leaf_index;
        let mut cur = leaf;
        for level in 0..(self.depth as usize) {
            if idx & 1 == 0 {
                // Left child: right sibling is empty; record the filled subtree.
                self.filled_subtrees[level] = cur;
                cur = hash_pair(&cur, &self.zeros[level])?;
            } else {
                // Right child: hash against the stored left sibling.
                cur = hash_pair(&self.filled_subtrees[level], &cur)?;
            }
            idx >>= 1;
        }

        self.current_root = cur;
        let new_hist = (self.root_history_index() + 1) % (ROOT_HISTORY_SIZE as u64);
        self.root_history_index = new_hist.to_le_bytes();
        self.root_history[new_hist as usize] = cur;
        self.next_index = (leaf_index + 1).to_le_bytes();
        Ok(leaf_index)
    }
}
