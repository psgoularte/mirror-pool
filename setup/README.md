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

The committed key has **1 independent contributor** (a single operator, one
machine): `mirror-pool-maintainer (single operator, one machine, 2026-07)`.
**The proving key is not committed** (it is large; each operator generates their
own — see below). The committed key is a verifiable *reference*, not the key you
deploy with.

## Verify the ceremony (anyone, public data only)

```sh
cargo run -p mirror-pool-cli -- verify-setup      # transcript + verifying_key.bin
# or the pinned-hash test:
cargo test -p mirror-pool-circuit --test trusted_setup
```

`verify-setup` runs every same-ratio + Schnorr check, confirms the chain produces
the committed key, and prints each contributor + the **independent-contributor
count** + the transcript hash. The test additionally pins that hash and asserts
the independent count. Verification is fully public.

## Run the ceremony distributably (independent operators)

```sh
cli ceremony-init --out-dir ceremony                       # base params + empty transcript
cli ceremony-contribute --params ceremony/params.bin \     # each INDEPENDENT operator, in turn
    --transcript ceremony/transcript.bin --contributor "alice" --out-dir ceremony
cli ceremony-finalize --params ceremony/params.bin \       # derive + verify the key
    --transcript ceremony/transcript.bin --out-dir setup
```

Only public data (`params.bin` + `transcript.bin`) passes between operators; each
operator's entropy lives in their process and is discarded on exit. A single-shot
convenience path (`cli setup --contributions N`) exists too, but N self-run steps
are still one independent contributor.

## ⚠ Honest scope

- **The shipped key is single-operator (1 independent contributor).** The tooling
  above *can* be run by independent parties — that is what makes the "≥1 honest"
  guarantee real — but the committed key was not, so its assurance is "trust that
  one operator." Running more self-steps does **not** change this.
- **Phase-2 only.** The ceremony re-randomizes `delta`; `alpha, beta, gamma, tau`
  come from the base setup, which rests on that base's entropy being discarded.
  A production deployment adds a public **Phase-1** powers-of-tau (the arkworks
  stack does not ingest an external `.ptau`; this is noted in `docs/security.md`).

The committed key is therefore suitable for review and testnets, not for
securing real value with a single-operator base.
