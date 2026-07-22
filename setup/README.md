# setup/ — Groth16 trusted setup

Groth16 requires a **per-circuit trusted setup**. The setup produces a proving
key and a verifying key from secret randomness ("toxic waste"); anyone who
retains that randomness can forge membership proofs. This directory holds the
**development** verifying key and documents how a **production** key must be
produced.

## What is committed here

- `verifying_key.solana.bin` — the on-chain verifying key (769 bytes, the flat
  layout `program::verifier::ParsedVerifyingKey` parses), for the **dev** setup.

This key is produced by `mirror_pool_circuit::prover::dev_setup()`, a
**deterministic, single-party** setup seeded from a public constant
(`DEV_SETUP_SEED`). It is reproducible on purpose so it can be regenerated and
diffed in CI:

```sh
# Verify the committed key is reproducible (runs in CI):
cargo test -p mirror-pool-circuit --test setup_reproducible

# Regenerate it (only if the circuit legitimately changed):
cargo test -p mirror-pool-circuit --test setup_reproducible -- --ignored write_dev_vk
```

The CLI writes the same key set (`proving_key.bin`, `verifying_key.bin`,
`vk_solana.bin`) with:

```sh
cargo run -p mirror-pool-cli -- setup --out-dir setup
```

## ⚠ This dev key is NOT production-trusted

Because the seed is public, anyone can reconstruct the toxic waste and forge
proofs. **Do not deploy a pool whose value you care about with this key.**

## Producing a production key (Phase-2 ceremony)

The full ceremony path — Phase-1 powers-of-tau reuse, the multi-party Phase-2
protocol, contribution transcripts, and verification — is documented in
[`../SECURITY.md`](../SECURITY.md#trusted-setup). In short: never trust a setup
run by a single party; run a multi-contributor ceremony, publish the transcript,
and have independent parties verify it before committing the resulting key here.
