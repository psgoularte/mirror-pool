# Live devnet proof of execution

This document records the deployed mirror-pool program running the full protocol
**end-to-end against Solana devnet**, with real, on-chain-verifiable transaction
signatures. Every signature below is `Finalized` on devnet — follow any explorer
link to check it yourself.

## Scope & honesty note (read first)

**What this proves.** The program at
[`4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe`](https://explorer.solana.com/address/4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe?cluster=devnet)
— running on a live cluster, not litesvm — accepts the real instruction flow
(initialize → deposit → open epoch → relayer-paid `execute_action` with on-chain
Groth16 verification and a PDA-signed action → close epoch), and **enforces the
documented negative cases** (nullifier reuse and the `k_min` anonymity-set floor)
by rejecting them on-chain.

**What this does NOT prove.**

- **Not a real anonymity crowd.** This is a functional run with three deposits
  and a single operator scripting every step. It demonstrates the *mechanism*,
  not a large, independent, honest membership set. The anonymity analysis and its
  Sybil caveat live in [`anonymity.md`](./anonymity.md) and [`security.md`](./security.md).
- **Not a production trusted setup.** The verifying key comes from a
  single-operator multi-contributor Phase-2 ceremony with no external Phase-1 —
  testnet-grade, as stated in [`security.md`](./security.md).
- **Not an audit.** No third-party audit or formal verification has been done.
- **Devnet is devnet.** These results are a live-cluster functional proof. They
  are **not** "mainnet-proven" and nothing here should be read as securing real
  value.

No signature in this document is fabricated. Where a step is a negative case that
is rejected at simulation (so no transaction is committed), it is recorded as an
**RPC error with the program logs**, not as a committed signature.

## Environment

| | |
|---|---|
| **Cluster** | Solana **devnet** (`https://api.devnet.solana.com`) |
| **Program id** | [`4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe`](https://explorer.solana.com/address/4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe?cluster=devnet) |
| **Pool PDA** (`["pool", authority]`) | [`93YtLyRDq6Ssg8pGYA5myqmdvMBjnTm5akVo5EBABNN`](https://explorer.solana.com/address/93YtLyRDq6Ssg8pGYA5myqmdvMBjnTm5akVo5EBABNN?cluster=devnet) |
| **Authority / relayer** (fee payer) | `G4mGDVSdYsfnRFagyjB5BQN6V3z1StprQfskZ2ayNmUR` |
| **Pool params** | `k_min = 2`, tree depth 20, 3 deposits, epoch 1 |
| **Action** | `NoOpAction` (selector 0) — a PDA self-CPI proving the pool, not the member, is the actor |
| **CLI commit** | `41f66df` (branch `chore/hardening-v2`), Agave CLI v4.1.1 |
| **Date** | 2026-07-22 |

The authority and the relayer are the **same** keypair in this run (one operator
scripting the demo). That is fine for a functional proof and does not weaken the
unlinkability property being shown: **members have no keypair at all** — a member
is a secret, never a Solana signer — so no member wallet appears in any action
transaction regardless of who relays.

## End-to-end run

Every row is a `Finalized` devnet transaction.

| # | Instruction | Signature (explorer) | On-chain effect verified |
|---|---|---|---|
| 0 | *(funding)* transfer 1.2 SOL → relayer | [`2GH3ku…Btmsn`](https://explorer.solana.com/tx/2GH3kuBF38nua9yjtDjdbA1G5DdKxCJvSzMrieFwkQ3f4G5JXRiPm96zmbzobvGa2HL7HBPR2sJ41siiydXBtmsn?cluster=devnet) | relayer keypair funded (setup, not part of the protocol) |
| 1 | `InitializePool` (k_min 2) | [`38t5th…zgHtw`](https://explorer.solana.com/tx/38t5thjJnuyc9cgfccjfNysqpFZj7uszkvuofqc4nPDVfnw5M8P5nUnRapsTTNWT2BAxUmNbqyEaUpaeJT8zgHtw?cluster=devnet) | pool PDA created; ceremony VK stored in the account |
| 2 | `Deposit` (member 1) | [`3VaVg9…wNmVW`](https://explorer.solana.com/tx/3VaVg94AU2Aa95KniSmYKarXKRm4TvtyN1P2h6W2skGykPDT7DGHqjJ4rqxLps22nRheCTXnCinpg2b82aqwNmVW?cluster=devnet) | commitment inserted; incremental root advanced |
| 3 | `Deposit` (member 2) | [`3hzPaQ…5W57rc`](https://explorer.solana.com/tx/3hzPaQ6kyesvfPsNq79TFc2P7A7M5uTewQYB8ZsKpbpugBhMhpxkgDTUaWEyoN9BigsPxim53Z3WM97gb15W57rc?cluster=devnet) | commitment inserted; root advanced |
| 4 | `Deposit` (member 3) | [`1qQFMj…demdd`](https://explorer.solana.com/tx/1qQFMjqbxDdekug94Ez3GaLeF9sPhKfLgeWdUnCSvqRDb9casBMPwCbMB64sTrDCpHP4dK5NxBuNCVEGGbdemdd?cluster=devnet) | commitment inserted; root advanced (3 leaves) |
| 5 | `OpenEpoch` (crank) | [`5hDYnm…rSATh`](https://explorer.solana.com/tx/5hDYnmQtfk9ykNNz9nP3G6e4FykE9u5mCBhdAYbZRo8SscxYe7Nvc85SSuCgxND62zmaFuDKXDnGLUjjqpqrSATh?cluster=devnet) | `current_epoch → 1`, `epoch_active = 1` |
| 6 | `ExecuteAction` (member 1, relayer-paid) | [`39r6wb…YduFv`](https://explorer.solana.com/tx/39r6wb7rc58nqrTfKxZoKkbzCWAyd4WbrXz9xECr8MvAZgfVoa6VwNnbBRZgeVVUYcsgQ3pV4D6H6GYm1G9YduFv?cluster=devnet) | **on-chain Groth16 verify passed**; nullifier PDA created; NoOp CPI signed by the pool PDA. Fee payer = relayer, **member never signed** |
| 7 | `ExecuteAction` (member 2, relayer-paid) | [`4Gn66i…SijWQ`](https://explorer.solana.com/tx/4Gn66ii7gpfGWRRR3U7bGx1qgh7KULL2qCdq4ST6vgSaB3Wo7MS7sQRsYhFryj6cdZhasLj238LRutSSRduSijWQ?cluster=devnet) | second distinct member acts in the same epoch (crowd of 2); its own nullifier PDA created |
| 8 | `CloseEpoch` (crank) | [`38TjRo…4rEM`](https://explorer.solana.com/tx/38TjRoHW7wZsMxysbS9frmckGfcKqzyxtyqirMmDPHSG547ggcj6LdHkvQZhdcqPxexPQMr92sEzKEzZWth4rEM?cluster=devnet) | `epoch_active = 0`; further actions rejected until reopen |

The root was not printed by a dedicated instruction, but its correctness is
proven transitively: `execute_action`'s on-chain `is_known_root` check (step 6/7)
only passes if the on-chain incremental root **equals** the root the prover
rebuilt from the three deposited leaves off-chain. A wrong root would have been
rejected with `UnknownRoot` (`Custom(13)`) before verification.

Nullifiers created on-chain (epoch-scoped, `Poseidon(secret, epoch)`):
member 1 `0b4c4fd7…dae134`, member 2 `22c82695…e00aea`.

## Negative cases (rejected live on-chain)

Both were rejected during transaction simulation, so **no transaction was
committed** — recorded here as the RPC error and the program's own logs. Error
codes are `ProgramError::Custom(n)` from
[`program/src/error.rs`](../program/src/error.rs).

### Nullifier reuse → `NullifierAlreadyUsed` (`Custom(16)` = `0x10`)

Re-submitting member 1's exact relay job (same nullifier) inside the open epoch:

```
custom program error: 0x10
Program 4YrUSMP…xYPe consumed 102078 of 299850 compute units
Program 4YrUSMP…xYPe failed: custom program error: 0x10
```

The k_min guard passed (`3 − 1 = 2 ≥ 2`), so the program ran the full Groth16
verification (~102k CU) and then rejected at the nullifier-existence check — the
double-action prevention working on-chain.

### Below the anonymity floor → `AnonymitySetTooSmall` (`Custom(25)` = `0x19`)

After two distinct actions the lower bound is `3 − 2 = 1 < k_min = 2`. A third
distinct member's action (member 3) was rejected:

```
custom program error: 0x19
Program 4YrUSMP…xYPe consumed 2236 of 299850 compute units
Program 4YrUSMP…xYPe failed: custom program error: 0x19
```

Note the **2,236 CU**: the `k_min` guard short-circuits *before* the expensive
proof verification, so an under-floor action is rejected cheaply.

## Compute units observed on-chain

Measured on devnet (not litesvm) for this run:

| Path | CU | Source |
|---|---|---|
| `execute_action` (success, full verify + nullifier + CPI) | **108,367** (tx total; 108,217 in-program) | `solana confirm -v 39r6wb…YduFv` |
| verify path before nullifier reject (replay) | 102,078 | replay simulation logs |
| `k_min` early reject | 2,236 | simulation logs |

These agree with the litesvm-measured figure in [`testing.md`](./testing.md)
(VerifyMembership ≈ 98,627 CU; `execute_action` ≈ 108–116k) — the on-chain
numbers confirm the benchmark, they do not replace it.

## Reproduce

You must fund your own devnet keypair first (the operator pays fees; members
never do). Then, from the repo root:

```sh
PID=4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe
URL=https://api.devnet.solana.com
cargo build -p mirror-pool-cli --release
BIN=target/release/mirror-pool

# A devnet keypair, funded (web faucet or `solana airdrop`), used as authority + relayer.
solana-keygen new --no-bip39-passphrase --outfile auth.json
solana airdrop 2 "$(solana address -k auth.json)" --url $URL
AUTH=$(solana address -k auth.json)

# Ceremony keys for this pool (proving_key.bin + matching vk_solana.bin).
$BIN setup --out-dir keys --contributions 2

# 3 members: keep the secrets, collect commitments into leaves.txt.
for i in 1 2 3; do
  $BIN keygen | tee /tmp/m$i
  awk '/commitment:/{print $2}' /tmp/m$i >> leaves.txt
done

$BIN init-pool --rpc-url $URL --keypair auth.json --program-id $PID \
  --verifying-key keys/vk_solana.bin --k-min 2
while read C; do
  $BIN deposit --rpc-url $URL --keypair auth.json --program-id $PID \
    --pool-authority $AUTH --commitment "$C"
done < leaves.txt
$BIN crank --rpc-url $URL --keypair auth.json --program-id $PID --action open

# Prove membership offline, then a relayer submits it (member never signs).
SECRET=$(awk '/secret:/{print $2}' /tmp/m1)
$BIN prove --proving-key keys/proving_key.bin --leaves leaves.txt \
  --secret $SECRET --epoch 1 --selector 0 --out jobA.job
$BIN execute --rpc-url $URL --keypair auth.json --program-id $PID \
  --pool-authority $AUTH --job jobA.job

# Negative: replay the same job → NullifierAlreadyUsed (Custom 16).
$BIN execute --rpc-url $URL --keypair auth.json --program-id $PID \
  --pool-authority $AUTH --job jobA.job

$BIN crank --rpc-url $URL --keypair auth.json --program-id $PID --action close
```

Because the trusted-setup ceremony is non-deterministic, your pool's VK (and
thus its address, if you use a different authority) will differ from the ones
above; the flow and the enforced checks are identical.
