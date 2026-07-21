# mirror-pool

**Compliant behavioral-anonymity for Solana.** mirror-pool is a shared
anonymity-set protocol — **not a fund mixer**. Members join a pool; when any
member triggers a protocol interaction (a swap, a stake, …), the action is
executed on-chain by the **pool program's PDA**, gated by a zero-knowledge proof
of pool membership. Observers see that *an* action happened but cannot attribute
it to a specific member. A larger pool and tighter per-epoch synchronization
mean stronger anonymity for everyone.

Architecturally this is an Elusiv/Tornado-style anonymity set (a Merkle tree of
commitments, epoch-scoped nullifiers, and a Groth16 membership proof),
generalized from "the right to withdraw funds" to "the right to trigger an
action this epoch." **The PDA — not the member — is the on-chain actor**, and
that indirection is the core unlinkability primitive.

> **Status:** under active construction as a milestone PR sequence (see
> [`SPEC.md`](./SPEC.md) and [`ARCHITECTURE.md`](./ARCHITECTURE.md)). Milestone 1
> (workspace, CI, pinned Poseidon parameters) is complete.

## Everything is Rust

On-chain program, ZK circuit + prover, relayer, and CLI are all Rust. The
circuit uses [arkworks](https://arkworks.rs) (Groth16 over BN254) — **not
Circom** — and on-chain proof verification uses
[`groth16-solana`](https://github.com/Lightprotocol/groth16-solana) via the
`alt_bn128` syscalls. There is no GUI; consumers are developers, agents, and
other programs.

## Threat model (summary)

Privacy here is *behavioral* and *probabilistic*: your anonymity is exactly the
set of members who could plausibly have triggered the same action in the same
epoch. mirror-pool is explicit about what it does and does not defend against
(full treatment in [`ARCHITECTURE.md`](./ARCHITECTURE.md)):

- **Fee-payer linkage** — if the member's own wallet paid the action fee, the
  action is trivially attributable. Mitigation: a mandatory fee-paying
  **relayer** (SPEC §4.4). Self-relaying defeats the protocol.
- **Single-member epochs** — an anonymity set of one is no anonymity. Mitigation:
  epoch windows that batch actions; the CLI `sim` reports the achieved set size,
  and thin epochs are surfaced, not hidden.
- **Timing correlation** — deposit→action timing and cross-epoch behavior can
  re-link a member. Mitigation: epoch batching; documented residual leakage.
- **Amount/dust correlation** — for value-carrying actions, unique amounts leak.
  Documented; denomination guidance provided per integration.

An overclaimed privacy guarantee is worse than an accurate one; the docs err
toward honesty about residual leakage.

## Compliance is first-class

- **Viewing keys / selective disclosure** — a member can grant a designated
  auditor the ability to learn which actions *they* initiated, without weakening
  anyone else's anonymity.
- **Deposit-screening hook** — pluggable, off by default, able to reject entries
  based on an attestation/allowlist.

The framing is **compliant behavioral privacy with selective disclosure**, not
evasion.

## Workspace

```
common/    # shared types + pinned Poseidon params (single source of truth)
circuit/   # arkworks membership circuit + prover
program/   # native Solana program (tree, nullifiers, epochs, PDA execution, compliance)
relayer/   # off-chain fee-paying relayer + epoch batcher
cli/       # keygen / deposit / prove / execute / disclose / sim
```

## Build & test

Toolchain (pinned; the versions this repo is developed and CI-tested against):

- Rust stable (see [`rust-toolchain.toml`](./rust-toolchain.toml))
- Solana/Agave CLI providing `cargo build-sbf` (platform-tools ≥ v1.54)

```sh
# Host build, lints, and the full test suite (includes the Poseidon
# circuit↔chain equality test).
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Compile the on-chain program to SBF bytecode.
cargo build-sbf --manifest-path program/Cargo.toml
```

## Quickstart

The end-to-end flow (deposit → epoch → relayed action → selective disclosure) on
a local validator lands with the CLI and `demo.sh` in later milestones. This
section will carry the copy-paste quickstart once `execute_action` and the
relayer are in place.

## License

MIT — see [`LICENSE`](./LICENSE).
