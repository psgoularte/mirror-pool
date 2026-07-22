//! `mirror-pool` developer CLI (SPEC §4.5).
//!
//! Subcommands:
//! * `setup`     — deterministic (dev) Groth16 setup; writes proving/verifying keys.
//! * `keygen`    — generate a member secret, or an auditor viewing keypair.
//! * `init-pool` — create a pool on-chain (signer = authority; uses the dev VK).
//! * `deposit`   — submit a commitment to a pool (on-chain).
//! * `crank`     — open/close the epoch window (authority only, on-chain).
//! * `prove`     — build a membership proof and write a relay job.
//! * `execute`   — hand a relay job to a relayer (submit `execute_action`).
//! * `associate` — ZK proof that a deposit is in an association set (compliance).
//! * `disclose`  — seal a member's secret to an auditor (selective disclosure).
//! * `sim`       — report min-entropy effective-k over the association set.
//!
//! The offline commands (`setup`, `keygen`, `prove`, `disclose`, `sim`) need no
//! network. `init-pool`, `deposit`, `crank`, and `execute` take an RPC endpoint.

use anyhow::{anyhow, Context, Result};
use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use clap::{Parser, Subcommand};
use mirror_pool_circuit::prover::{build_witness, dev_setup, prove, PublicInputs};
use mirror_pool_circuit::solana::{proof_to_solana, vk_to_solana};
use mirror_pool_common::compliance::{seal_disclosure, ViewingKeypair};
use mirror_pool_common::merkle::MerkleTree;
use mirror_pool_common::poseidon::{action_binding, commitment};
use mirror_pool_common::{fr_from_bytes_be, fr_to_bytes_be, TREE_DEPTH};
use mirror_pool_relayer::{pool_pda, relay, RelayJob};
use rand::rngs::OsRng;
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
    /// Prove (in ZK) that a member's deposit is in an association set — the
    /// Privacy-Pools inclusion proof. Reuses the membership circuit against the
    /// set's root; self-verifies. Guarantees association-set membership only.
    Associate {
        /// File of approved commitment hexes (one per line) — the association set.
        #[arg(long)]
        set: PathBuf,
        /// The member's secret (must correspond to a commitment in the set).
        #[arg(long)]
        secret: String,
        #[arg(long, default_value_t = 0)]
        epoch: u64,
    },
    /// Seal a secret to an auditor's viewing key (selective disclosure).
    Disclose {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        auditor_pubkey: String,
    },
    /// Simulate a pool and report **min-entropy effective-k** per epoch, over
    /// the association set and over all deposits (the delta is the Sybil
    /// exposure), plus the dominance-adjusted figure.
    Sim {
        /// Honest, independently-funded, associated members.
        #[arg(long, default_value_t = 64)]
        members: u64,
        /// Unassociated Sybil notes controlled by a single funder (inflate the
        /// naive count without adding honest anonymity).
        #[arg(long, default_value_t = 0)]
        sybils: u64,
        #[arg(long, default_value_t = 8)]
        actors: u64,
        #[arg(long, default_value_t = 3)]
        epochs: u64,
    },
    /// Create a pool on-chain (the signer becomes the pool authority). Uses the
    /// deterministic dev verifying key.
    InitPool {
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: String,
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        program_id: String,
        #[arg(long, default_value_t = 2)]
        k_min: u64,
    },
    /// Open or close the current epoch (authority-only crank).
    Crank {
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: String,
        #[arg(long)]
        keypair: PathBuf,
        #[arg(long)]
        program_id: String,
        /// `open` or `close`.
        #[arg(long)]
        action: String,
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
        Command::Associate { set, secret, epoch } => cmd_associate(&set, &secret, epoch),
        Command::Disclose {
            secret,
            auditor_pubkey,
        } => cmd_disclose(&secret, &auditor_pubkey),
        Command::Sim {
            members,
            sybils,
            actors,
            epochs,
        } => cmd_sim(members, sybils, actors, epochs),
        Command::InitPool {
            rpc_url,
            keypair,
            program_id,
            k_min,
        } => cmd_init_pool(&rpc_url, &keypair, &program_id, k_min),
        Command::Crank {
            rpc_url,
            keypair,
            program_id,
            action,
        } => cmd_crank(&rpc_url, &keypair, &program_id, &action),
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
    eprintln!("running the deterministic DEV Groth16 setup (depth {TREE_DEPTH})…");
    // Deterministic, fixed-seed DEV setup: reproduces the committed
    // `setup/verifying_key.solana.bin`. NOT production-trusted.
    let (pk, vk) = dev_setup().map_err(|e| anyhow!("setup: {e}"))?;

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
    println!(
        "⚠  DEV setup only — seeded from a public constant, so whoever runs it \
         can forge proofs. Production keys MUST come from a multi-party ceremony \
         (see SECURITY.md)."
    );
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

fn cmd_associate(set_path: &Path, secret_hex: &str, epoch: u64) -> Result<()> {
    use mirror_pool_circuit::association::{prove_inclusion, verify_inclusion, AssociationSet};
    let secret = parse_fr(secret_hex)?;
    // Build the association set from approved commitment hexes.
    let mut set = AssociationSet::new();
    for line in std::fs::read_to_string(set_path)
        .context("read set")?
        .lines()
    {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        set.approve_commitment(parse_fr(line)?)
            .map_err(|e| anyhow!("add to set: {e}"))?;
    }
    let root = set.root();
    // Dev keys (deterministic).
    let (pk, vk) = dev_setup().map_err(|e| anyhow!("setup: {e}"))?;
    let mut rng = OsRng;
    let incl = prove_inclusion(&pk, &set, secret, Fr::from(epoch), &mut rng)
        .map_err(|e| anyhow!("inclusion proof: {e} (is the commitment in the set?)"))?;
    let ok = verify_inclusion(&vk, &root, &incl).map_err(|e| anyhow!("verify: {e}"))?;
    println!("association set root: {}", hex::encode(root));
    println!("inclusion proof verifies: {ok}");
    println!(
        "(the ASP verifies this against its published root; it attests \
         association-set membership only — nothing about identity or balance)"
    );
    if !ok {
        return Err(anyhow!("inclusion proof did not verify"));
    }
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

fn cmd_sim(members: u64, sybils: u64, actors: u64, epochs: u64) -> Result<()> {
    use mirror_pool_anonymity::{measure, Bucket, Note};
    if actors > members {
        return Err(anyhow!(
            "actors ({actors}) cannot exceed honest members ({members})"
        ));
    }
    // Candidate notes: `members` honest, independently-funded, associated notes;
    // `sybils` unassociated notes all controlled by one funder (id 0).
    let mut notes: Vec<Note> = (0..members)
        .map(|i| Note {
            funder: i + 1,
            associated: true,
        })
        .collect();
    notes.extend((0..sybils).map(|_| Note {
        funder: 0,
        associated: false,
    }));

    // Observable buckets an actor might land in (denomination × action-type):
    // no-op (type 0, denom 0) and the three transfer denominations (type 1).
    let buckets = [
        Bucket {
            denomination: 0,
            action_type: 0,
        },
        Bucket {
            denomination: 100_000_000,
            action_type: 1,
        },
        Bucket {
            denomination: 1_000_000_000,
            action_type: 1,
        },
        Bucket {
            denomination: 10_000_000_000,
            action_type: 1,
        },
    ];

    println!(
        "mirror-pool sim: {members} honest members, {sybils} sybils, {actors} actors/epoch, {epochs} epochs"
    );
    println!(
        "metric: min-entropy effective-k = 1/max_i p_i (single-guess adversary; PET'02, FoSSaCS'09)\n"
    );

    let report = measure(&notes, &buckets);
    for epoch in 1..=epochs {
        // Every epoch draws from the same candidate set; the honest figure is
        // over the association set, the naive figure over all deposits.
        let assoc = report.over_associated.worst_uniform_effective_k;
        let all = report.over_all.worst_uniform_effective_k;
        let dom = report.over_all.worst_dominance_adjusted_effective_k;
        let warn = if actors <= 1 {
            "  ⚠ single action this window — timing-correlatable regardless of k"
        } else {
            ""
        };
        println!(
            "  epoch {epoch}: effective-k over associated = {assoc:.1}, over all deposits = {all:.1} \
             (Sybil gap {:.1}); dominance-adjusted = {dom:.1}{warn}",
            report.sybil_gap()
        );
    }
    println!(
        "\nWorst-bucket effective-k: {:.1} over the association set vs {:.1} over all deposits.",
        report.over_associated.worst_uniform_effective_k, report.over_all.worst_uniform_effective_k
    );
    println!(
        "The gap ({:.1}) is the Sybil exposure: effective-k over all deposits is inflatable by \
         unassociated notes, so only the association-set figure is an honest floor. A colluding \
         funder controlling a bucket reduces it further (dominance-adjusted above). See the \
         threat model; k_min on-chain bounds membership, NOT honest anonymity.",
        report.sybil_gap()
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

fn cmd_init_pool(rpc_url: &str, keypair: &Path, program_id: &str, k_min: u64) -> Result<()> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program_id = Pubkey::from_str(program_id).context("program id")?;
    let payer = read_keypair_file(keypair).map_err(|e| anyhow!("read keypair: {e}"))?;
    // The signer is the pool authority.
    let pool = pool_pda(&program_id, &payer.pubkey());

    // Dev verifying key (deterministic; reproduces setup/verifying_key.solana.bin).
    let (_pk, vk) = dev_setup().map_err(|e| anyhow!("setup: {e}"))?;
    let vk_bytes: [u8; mirror_pool_program::verifier::VK_SERIALIZED_LEN] = vk_to_solana(&vk)
        .to_bytes()
        .try_into()
        .map_err(|_| anyhow!("vk length"))?;

    let data = mirror_pool_program::instruction::Instruction::InitializePool {
        depth: TREE_DEPTH as u8,
        k_min,
        verifying_key: vk_bytes,
    }
    .pack()
    .map_err(|e| anyhow!("pack: {e:?}"))?;
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    };
    let bh = rpc.get_latest_blockhash().context("blockhash")?;
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).context("init pool")?;
    println!("pool {pool} initialized (k_min {k_min}): {sig}");
    Ok(())
}

fn cmd_crank(rpc_url: &str, keypair: &Path, program_id: &str, action: &str) -> Result<()> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program_id = Pubkey::from_str(program_id).context("program id")?;
    let payer = read_keypair_file(keypair).map_err(|e| anyhow!("read keypair: {e}"))?;
    let pool = pool_pda(&program_id, &payer.pubkey());
    let ix_data = match action {
        "open" => mirror_pool_program::instruction::Instruction::OpenEpoch,
        "close" => mirror_pool_program::instruction::Instruction::CloseEpoch,
        other => {
            return Err(anyhow!(
                "crank action must be 'open' or 'close', got '{other}'"
            ))
        }
    }
    .pack()
    .map_err(|e| anyhow!("pack: {e:?}"))?;
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
        data: ix_data,
    };
    let bh = rpc.get_latest_blockhash().context("blockhash")?;
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).context("crank")?;
    println!("epoch {action}: {sig}");
    Ok(())
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
