# setup/ — Groth16 trusted setup (multi-contributor Phase-2)

Groth16 needs a per-circuit setup whose secret randomness ("toxic waste") must
be destroyed. A **single-party** setup is only as trustworthy as that one party.
mirror-pool uses a **multi-contributor Phase-2 ceremony** (`circuit::ceremony`):
each contributor re-randomizes the `delta` trapdoor with fresh entropy and
publishes a proof-of-contribution. The key is secure **if at least one
contributor discarded their randomness**.

## Committed artifacts (a real, verifiable ceremony)

- `verifying_key.bin` — the arkworks verifying key (the ceremony output).
- `verifying_key.solana.bin` — the same key in the on-chain byte layout (769 B).
- `transcript/transcript.bin` — the base `delta` + every contribution with its
  Schnorr proof-of-contribution and same-ratio consistency.

These come from one real 3-contribution ceremony. **The proving key is not
committed** (it is large; each operator generates their own — see below). The
committed key is a verifiable *reference*, not the key you deploy with.

## Verify the ceremony

```sh
cargo test -p mirror-pool-circuit --test trusted_setup
```

This (1) verifies the whole contribution chain, (2) checks the transcript
matches the hash pinned in the test, and (3) confirms `verifying_key.solana.bin`
is exactly the transcript's output. Verification is fully public.

## Run your own ceremony

```sh
cargo run -p mirror-pool-cli -- setup --out-dir my-setup --contributions 3
```

Writes `proving_key.bin`, `verifying_key.bin`, `vk_solana.bin`, and
`transcript.bin`. Use `vk_solana.bin` for `init-pool --verifying-key` and
`proving_key.bin` for `prove` / `associate`.

## ⚠ Honest scope

- **This CLI runs all contributions on one machine**, so it is only as honest as
  that single operator. A real deployment coordinates contributions across
  **independent** parties, each on their own machine, publishing the transcript
  for public verification.
- **Phase-2 only.** The ceremony re-randomizes `delta`; `alpha, beta, gamma, tau`
  come from the base setup, which rests on that base's entropy being discarded.
  A production deployment adds a public **Phase-1** powers-of-tau (the arkworks
  stack does not ingest an external `.ptau`; this is noted in `docs/security.md`).

The committed key is therefore suitable for review and testnets, not for
securing real value with a single-operator base.
