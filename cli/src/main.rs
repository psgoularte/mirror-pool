//! `mirror-pool` developer CLI (SPEC §4.5).
//!
//! Subcommands:
//! * `setup`    — run the (dev) Groth16 trusted setup; write proving/verifying keys.
//! * `keygen`   — generate a member secret, or an auditor viewing keypair.
//! * `deposit`  — submit a commitment to a pool (on-chain).
//! * `prove`    — build a membership proof and write a relay job.
//! * `execute`  — hand a relay job to a relayer (submit `execute_action`).
//! * `disclose` — seal a member's secret to an auditor (selective disclosure).
//! * `sim`      — simulate N members over epochs; report the anonymity-set size.
//!
//! The offline commands (`setup`, `keygen`, `prove`, `disclose`, `sim`) need no
//! network. The on-chain commands (`deposit`, `execute`) take an RPC endpoint.

use anyhow::{anyhow, Context, Result};
use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use clap::{Parser, Subcommand};
use mirror_pool_circuit::prover::{build_witness, prove, setup, PublicInputs};
use mirror_pool_circuit::solana::{proof_to_solana, vk_to_solana};
use mirror_pool_common::compliance::{seal_disclosure, ViewingKeypair};
use mirror_pool_common::merkle::MerkleTree;
use mirror_pool_common::poseidon::{action_binding, commitment, nullifier_hash};
use mirror_pool_common::{fr_from_bytes_be, fr_to_bytes_be, TREE_DEPTH};
use mirror_pool_relayer::{pool_pda, relay, RelayJob};
use rand::rngs::OsRng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "mirror-pool", about = "mirror-pool developer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dev Groth16 trusted setup. Writes proving_key.bin, verifying_key.bin, and
    /// vk_solana.bin (the on-chain VK bytes for `initialize_pool`).
    Setup {
        #[arg(long, default_value = "artifacts")]
        out_dir: PathBuf,
    },
    /// Generate a member secret, or (with --auditor) a viewing keypair.
    Keygen {
        #[arg(long)]
        auditor: bool,
    },
    /// Build a membership proof and write a relay job (`.job`).
    Prove {
        #[arg(long)]
        proving_key: PathBuf,
        /// File of commitment hex strings (one per line) — the pool's leaves.
        #[arg(long)]
        leaves: PathBuf,
        /// The member's secret (hex, 32 bytes big-endian).
        #[arg(long)]
        secret: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long, default_value_t = 0)]
        selector: u8,
        /// Action params as hex (e.g. transfer: amount_le(8) || recipient(32)).
        #[arg(long, default_value = "")]
        params: String,
        #[arg(long, default_value = "action.job")]
        out: PathBuf,
    },
    /// Seal a secret to an auditor's viewing key (selective disclosure).
    Disclose {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        auditor_pubkey: String,
    },
    /// Simulate N members over E epochs and report the anonymity set per epoch.
    Sim {
        #[arg(long, default_value_t = 64)]
        members: u64,
        #[arg(long, default_value_t = 8)]
        actors: u64,
        #[arg(long, default_value_t = 3)]
        epochs: u64,
    },
    /// Submit a commitment (on-chain).
    Deposit {
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: String,
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        pool_authority: String,
        #[arg(long)]
        commitment: String,
    },
    /// Submit a relay job via a relayer (on-chain `execute_action`).
    Execute {
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: String,
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        pool_authority: String,
        #[arg(long)]
        job: PathBuf,
    },
}

fn parse_fr(hex_str: &str) -> Result<Fr> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).context("hex decode")?;
    fr_from_bytes_be(&bytes).map_err(|e| anyhow!("not a field element: {e}"))
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Setup { out_dir } => cmd_setup(&out_dir),
        Command::Keygen { auditor } => cmd_keygen(auditor),
        Command::Prove {
            proving_key,
            leaves,
            secret,
            epoch,
            selector,
            params,
            out,
        } => cmd_prove(
            &proving_key,
            &leaves,
            &secret,
            epoch,
            selector,
            &params,
            &out,
        ),
        Command::Disclose {
            secret,
            auditor_pubkey,
        } => cmd_disclose(&secret, &auditor_pubkey),
        Command::Sim {
            members,
            actors,
            epochs,
        } => cmd_sim(members, actors, epochs),
        Command::Deposit {
            rpc_url,
            keypair,
            program_id,
            pool_authority,
            commitment,
        } => cmd_deposit(
            &rpc_url,
            &keypair,
            &program_id,
            &pool_authority,
            &commitment,
        ),
        Command::Execute {
            rpc_url,
            keypair,
            program_id,
            pool_authority,
            job,
        } => cmd_execute(&rpc_url, &keypair, &program_id, &pool_authority, &job),
    }
}

fn cmd_setup(out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir).context("create out dir")?;
    eprintln!("running dev Groth16 setup (depth {TREE_DEPTH})…");
    let mut rng = OsRng;
    let (pk, vk) = setup(TREE_DEPTH, &mut rng).map_err(|e| anyhow!("setup: {e}"))?;

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| anyhow!("serialize pk: {e}"))?;
    std::fs::write(out_dir.join("proving_key.bin"), &pk_bytes)?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| anyhow!("serialize vk: {e}"))?;
    std::fs::write(out_dir.join("verifying_key.bin"), &vk_bytes)?;

    std::fs::write(out_dir.join("vk_solana.bin"), vk_to_solana(&vk).to_bytes())?;
    println!(
        "wrote proving_key.bin, verifying_key.bin, vk_solana.bin to {}",
        out_dir.display()
    );
    println!("NOTE: this is a DEV setup. Production keys must come from a multi-party ceremony.");
    Ok(())
}

fn cmd_keygen(auditor: bool) -> Result<()> {
    let mut rng = OsRng;
    if auditor {
        let kp = ViewingKeypair::generate(&mut rng);
        println!("auditor_secret: {}", hex::encode(kp.secret_bytes()));
        println!("auditor_public: {}", hex::encode(kp.public_bytes()));
    } else {
        let secret = Fr::rand(&mut rng);
        let c = commitment(secret);
        println!("secret:     {}", hex::encode(fr_to_bytes_be(&secret)));
        println!("commitment: {}", hex::encode(fr_to_bytes_be(&c)));
        println!("(deposit the commitment; keep the secret private)");
    }
    Ok(())
}

fn cmd_prove(
    pk_path: &Path,
    leaves_path: &Path,
    secret_hex: &str,
    epoch: u64,
    selector: u8,
    params_hex: &str,
    out: &Path,
) -> Result<()> {
    let pk_bytes = std::fs::read(pk_path).context("read proving key")?;
    let pk = CanonicalDeserialize::deserialize_compressed(&pk_bytes[..])
        .map_err(|e| anyhow!("deserialize pk: {e}"))?;

    let secret = parse_fr(secret_hex)?;
    let my_commitment = commitment(secret);

    // Rebuild the tree from the pool's leaves and find our index.
    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut my_index = None;
    for (i, line) in std::fs::read_to_string(leaves_path)
        .context("read leaves")?
        .lines()
        .enumerate()
    {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let leaf = parse_fr(line)?;
        if leaf == my_commitment {
            my_index = Some(i);
        }
        tree.insert(leaf).map_err(|e| anyhow!("insert leaf: {e}"))?;
    }
    let idx =
        my_index.ok_or_else(|| anyhow!("this secret's commitment is not in the leaves file"))?;

    let params = hex::decode(params_hex.trim_start_matches("0x")).context("params hex")?;
    let binding = action_binding(selector, &params);
    let path = tree.proof(idx).map_err(|e| anyhow!("merkle proof: {e}"))?;
    let assignment = build_witness(secret, &path, Fr::from(epoch), binding)
        .map_err(|e| anyhow!("witness: {e}"))?;
    let public: PublicInputs = assignment.public_inputs.clone();

    let mut rng = OsRng;
    let proof = prove(&pk, assignment.circuit, &mut rng).map_err(|e| anyhow!("prove: {e}"))?;

    let sol = proof_to_solana(&proof).to_bytes();
    let mut proof_arr = [0u8; 256];
    proof_arr.copy_from_slice(&sol);
    let pi = public.to_bytes();
    let mut public_inputs = [[0u8; 32]; 4];
    for (i, l) in pi.iter().enumerate() {
        public_inputs[i] = *l;
    }
    let job = RelayJob {
        proof: proof_arr,
        public_inputs,
        action_selector: selector,
        action_params: params,
    };
    job.save(out).map_err(|e| anyhow!("save job: {e}"))?;
    println!(
        "wrote relay job to {} (nullifier {})",
        out.display(),
        hex::encode(job.nullifier_hash())
    );
    Ok(())
}

fn cmd_disclose(secret_hex: &str, auditor_pubkey_hex: &str) -> Result<()> {
    let secret = parse_fr(secret_hex)?;
    let pk_bytes =
        hex::decode(auditor_pubkey_hex.trim_start_matches("0x")).context("pubkey hex")?;
    let auditor: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| anyhow!("auditor pubkey must be 32 bytes"))?;
    let mut rng = OsRng;
    let sealed = seal_disclosure(secret, &auditor, &mut rng);
    println!(
        "commitment:    {}",
        hex::encode(fr_to_bytes_be(&commitment(secret)))
    );
    println!("sealed_secret: {}", hex::encode(&sealed));
    println!("(register with the pool's register_viewing_key; only the auditor can open it)");
    Ok(())
}

fn cmd_sim(members: u64, actors: u64, epochs: u64) -> Result<()> {
    if actors > members {
        return Err(anyhow!(
            "actors ({actors}) cannot exceed members ({members})"
        ));
    }
    // Deterministic simulation of the anonymity set achieved per epoch.
    let mut rng = StdRng::seed_from_u64(0x51_A1);
    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut secrets = Vec::new();
    for _ in 0..members {
        let s = Fr::rand(&mut rng);
        tree.insert(commitment(s))
            .map_err(|e| anyhow!("insert: {e}"))?;
        secrets.push(s);
    }
    println!("mirror-pool sim: {members} members, {actors} actors/epoch, {epochs} epochs");
    println!("pool root: {}", hex::encode(fr_to_bytes_be(&tree.root())));
    let mut total_actions = 0u64;
    for epoch in 1..=epochs {
        // The anonymity set for this window is the number of distinct members
        // who acted: each produces a unique nullifier, indistinguishable among
        // the `members`-strong set.
        use std::collections::HashSet;
        let mut nullifiers = HashSet::new();
        for a in 0..actors {
            let member = ((epoch.wrapping_mul(31).wrapping_add(a)) % members) as usize;
            let nh = nullifier_hash(secrets[member], Fr::from(epoch));
            nullifiers.insert(fr_to_bytes_be(&nh));
        }
        total_actions += nullifiers.len() as u64;
        let k = nullifiers.len();
        // The cryptographic anonymity set is the whole pool (any member could
        // have produced any action). The practical risk is timing: a window
        // with a single action is easier to correlate across epochs.
        let warn = if k <= 1 {
            "  ⚠ single action this window — vulnerable to timing correlation; widen the window"
        } else {
            ""
        };
        println!(
            "  epoch {epoch}: {k} action(s), anonymity set = {members} members (1-in-{members}){warn}"
        );
    }
    println!(
        "total {total_actions} actions. Cryptographic anonymity set per action = pool size \
         ({members}). Realized privacy also requires >1 action per window (timing) and a \
         relayer paying fees (fee-payer linkage) — see the threat model."
    );
    Ok(())
}

fn rpc_and_pool(
    rpc_url: &str,
    program_id: &str,
    pool_authority: &str,
) -> Result<(RpcClient, Pubkey, Pubkey)> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program_id = Pubkey::from_str(program_id).context("program id")?;
    let authority = Pubkey::from_str(pool_authority).context("pool authority")?;
    let pool = pool_pda(&program_id, &authority);
    Ok((rpc, program_id, pool))
}

fn cmd_deposit(
    rpc_url: &str,
    keypair: &Path,
    program_id: &str,
    pool_authority: &str,
    commitment_hex: &str,
) -> Result<()> {
    let (rpc, program_id, pool) = rpc_and_pool(rpc_url, program_id, pool_authority)?;
    let payer = read_keypair_file(keypair).map_err(|e| anyhow!("read keypair: {e}"))?;
    let c = parse_fr(commitment_hex)?;
    let data = mirror_pool_program::instruction::Instruction::Deposit {
        commitment: fr_to_bytes_be(&c),
    }
    .pack()
    .map_err(|e| anyhow!("pack: {e:?}"))?;
    let ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new(pool, false)],
        data,
    };
    let bh = rpc.get_latest_blockhash().context("blockhash")?;
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .context("submit deposit")?;
    println!("deposited: {sig}");
    Ok(())
}

fn cmd_execute(
    rpc_url: &str,
    keypair: &Path,
    program_id: &str,
    pool_authority: &str,
    job: &Path,
) -> Result<()> {
    let (rpc, program_id, pool) = rpc_and_pool(rpc_url, program_id, pool_authority)?;
    let relayer = read_keypair_file(keypair).map_err(|e| anyhow!("read keypair: {e}"))?;
    let job = RelayJob::load(job).map_err(|e| anyhow!("load job: {e}"))?;
    let sig = relay(&rpc, &relayer, &program_id, &pool, &job)?;
    println!(
        "executed via relayer (fee payer {}): {sig}",
        relayer.pubkey()
    );
    Ok(())
}
