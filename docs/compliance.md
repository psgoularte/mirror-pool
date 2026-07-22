# Compliance: association sets & selective disclosure

mirror-pool is **compliant behavioral privacy** — privacy plus a *separating
equilibrium* where honest users can prove clean provenance and illicit ones
cannot (Buterin, Illum, Nadler, Schär & Soleimani, *Blockchain Privacy and
Regulatory Compliance: Towards a Practical Equilibrium*, 2023). All of it is
optional and off by default.

## Association sets

An **association set** is a curated Merkle tree of deposit commitments with clean
provenance, published by an **Association Set Provider (ASP)**. `circuit::
association` implements two proofs.

### Inclusion — real ZK

"My deposit is in this good set." Implemented by **reusing the membership
circuit** against the association-set root (no new circuit): a valid proof
against `set_root` proves knowledge of a secret whose commitment is a leaf of
that set, revealing nothing else. It binds to an action via the shared
`nullifier_hash = Poseidon(secret, epoch)` — the inclusion proof and the
pool-membership proof carry the same nullifier, so a match proves the *same*
commitment is in both trees.

```sh
mirror-pool associate --proving-key keys/proving_key.bin --set approved.txt \
  --secret <HEX> --epoch 1     # produces + self-verifies an inclusion proof
```

A member in the set produces a verifying proof; an outsider cannot. Verified by
tests (`included_member_proves_inclusion_others_cannot`,
`inclusion_proof_rejected_against_wrong_root`).

**Enforcement status (unambiguous):** inclusion is verified **off-chain**
(ASP-side, before vouching). It is **not** wired into the on-chain
`execute_action`, and there is **no feature-gated code** for that in the program.
On-chain enforcement (a second bound Groth16 verify, ~2× the CU, with a
`nullifier_hash` match) is a **design note**, not implemented.

### Exclusion — off-chain reference (ZK is future work)

"My deposit is not in this sanctioned set." True ZK non-membership needs a
dedicated sorted-tree adjacency circuit — **future work**, not implemented. The
module provides the honest **off-chain reference** (`SanctionedSet::
exclusion_witness`: a sorted-set adjacency witness verified natively) that an ASP
uses to attest exclusion. It is explicitly **not** a zero-knowledge on-chain
proof.

## Deposit-screening hook

`PoolConfig.screening_authority` is all-zero by default (screening off). When
set, every `deposit` must be co-signed by that authority (`ScreeningRequired`
otherwise) — a pluggable gate you can point at an allowlist/attestation program.

## Viewing keys / selective disclosure

A member can grant a designated auditor the ability to learn which actions *they*
initiated, without weakening anyone else's anonymity: the member seals their
secret to the auditor's X25519 viewing key (`seal_disclosure`, ECIES +
ChaCha20-Poly1305); the on-chain `RegisterViewingKey` stores the record; the
auditor opens it (`open_disclosure`) and attributes the on-chain nullifier
(`verify_disclosure`). Per-member, per-auditor: no master key, no way to
enumerate non-disclosing members.

## Exact guarantee (no overclaim)

Inclusion attests association-set **membership**; the exclusion reference attests
**non-membership** of a sanctioned set; disclosure reveals a consenting member's
*own* actions to *their* auditor. Nothing about identity, balance, or behavior
beyond that. Association sets **narrow** the Sybil gap (they make effective-k
measurable over attested members) but do **not** eliminate it — a corrupt ASP
re-introduces it. See [`docs/security.md`](./security.md).
