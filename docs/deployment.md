# Deployment

## Live devnet deployment

mirror-pool is deployed and live on Solana devnet:

| | |
|---|---|
| **Program id** | `4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe` |
| **Deploy signature** | `2k8D9wUAKJhYAnRWFMRk9yUogw4R6YfGaZhs4wD1U81iq4NsYEmoxKq4Lh1GFgQ1Xkx6Y9tdbXNuwq3PGtfoE2zQ` |
| **Explorer** | <https://explorer.solana.com/address/4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe?cluster=devnet> |

## Building the deployable artifact

The program compiles to SBF bytecode with a specific **sBPF architecture**. Note
that `--arch` is an argument to **`cargo build-sbf`**, not to `solana program
deploy`:

```sh
cargo build-sbf --manifest-path program/Cargo.toml --arch v3
```

`--arch v3` matches the sBPF version enabled on current Agave clusters (devnet
and a stock `solana-test-validator`). The default `v0` is not yet feature-gated
on-chain and is rejected by `program deploy` with
`Detected sbpf_version ... not enabled`.

The default-feature build is the **deployed** artifact — it does **not** contain
the benchmark-only `VerifyMembership` instruction (that is `#[cfg(feature =
"bench")]`, used only by the compute-unit benchmark).

## Deploy

```sh
solana program deploy target/deploy/mirror_pool_program.so   # prints the Program Id
```

Toolchain used: Solana/Agave CLI **v4.1.1** (platform-tools v1.54), Rust stable
(see `rust-toolchain.toml`).

## Driving the protocol over RPC (localhost or devnet)

The full flow runs against the deployed program via the CLI:

```sh
PID=4YrUSMP2gG9v9SJAgQPNYpzvUSxqWVBBQwdc7g52xYPe
URL=https://api.devnet.solana.com    # or http://127.0.0.1:8899

# 1. Trusted setup (multi-contributor Phase-2 ceremony) → keys for this pool.
cargo run -p mirror-pool-cli -- setup --out-dir keys --contributions 3

# 2. Create the pool (signer becomes the authority); k_min is the min anonymity floor.
mirror-pool init-pool --rpc-url $URL --keypair auth.json --program-id $PID \
  --verifying-key keys/vk_solana.bin --k-min 2

# 3. Members deposit commitments (from `keygen`).
mirror-pool deposit --rpc-url $URL --keypair payer.json --program-id $PID \
  --pool-authority <AUTH> --commitment <HEX>

# 4. Open the epoch window (authority crank).
mirror-pool crank --rpc-url $URL --keypair auth.json --program-id $PID --action open

# 5. A member proves membership (offline) → a relay job.
mirror-pool prove --proving-key keys/proving_key.bin --leaves leaves.txt \
  --secret <HEX> --epoch 1 --out action.job

# 6. A relayer submits it, paying the fee (the member never signs).
mirror-pool execute --rpc-url $URL --keypair relayer.json --program-id $PID \
  --pool-authority <AUTH> --job action.job
```

This exact sequence was validated end-to-end against a local
`solana-test-validator` (a real Agave 4.1.1 validator): initialize → deposits →
open epoch → relayer-paid `execute_action` (on-chain Groth16 verification +
PDA-signed CPI), each a confirmed transaction.

## Local iteration

Reserve devnet SOL for the final deploy; iterate against a local validator:

```sh
solana-test-validator --reset
solana config set --url localhost
solana airdrop 5
solana program deploy target/deploy/mirror_pool_program.so
```

## Keys

Never commit keypairs. Generate a devnet key **outside** the repo and fund it via
the CLI faucet (or a web faucet if the CLI is rate-limited):

```sh
solana-keygen new --no-bip39-passphrase --outfile ~/.config/solana/mirror-pool-devnet.json
solana config set --url devnet --keypair ~/.config/solana/mirror-pool-devnet.json
solana airdrop 2
```

`*.json` keypairs and `keys/` are git-ignored.
