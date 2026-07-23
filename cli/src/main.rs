//! `mirror-pool` developer CLI (SPEC §4.5).
//!
//! Subcommands:
//! * `setup`     — multi-contributor Phase-2 Groth16 ceremony; writes keys + transcript.
//! * `keygen`    — generate a member secret, or an auditor viewing keypair.
//! * `init-pool` — create a pool on-chain (signer = authority; VK from `setup`).
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
use ark_bn254::{Bn254, Fr};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use clap::{Parser, Subcommand};
use mirror_pool_circuit::ceremony::{
    base_setup, contribute, contributor_id, run_ceremony, verify_transcript, Transcript,
};
use mirror_pool_circuit::prover::{build_witness, prove, PublicInputs};
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
    /// Run a multi-contributor Phase-2 Groth16 ceremony. Writes proving_key.bin,
    /// verifying_key.bin, vk_solana.bin, and the transcript.bin.
    Setup {
        #[arg(long, default_value = "artifacts")]
        out_dir: PathBuf,
        /// Number of Phase-2 contributions (≥ 1). Real deployments coordinate
        /// these across independent parties.
        #[arg(long, default_value_t = 3)]
        contributions: usize,
    },
    /// Ceremony (distributable) — step 1: create the base params + an empty
    /// transcript that independent operators then extend. Publishes
    /// `params.bin` + `transcript.bin` (public — they carry no secret).
    CeremonyInit {
        #[arg(long, default_value = "ceremony")]
        out_dir: PathBuf,
    },
    /// Ceremony (distributable) — step 2: as an **external** operator, add ONE
    /// contribution with fresh OS entropy (re-randomize delta, emit a Schnorr
    /// PoK) and publish the updated `params.bin` + `transcript.bin`. Needs no
    /// one else's secret; your entropy lives only in this process and is gone
    /// when it exits.
    CeremonyContribute {
        /// Current params from the previous step/contributor.
        #[arg(long)]
        params: PathBuf,
        /// Current transcript from the previous step/contributor.
        #[arg(long)]
        transcript: PathBuf,
        /// Your public identifier: a label, or a 64-char hex 32-byte pubkey.
        #[arg(long)]
        contributor: String,
        #[arg(long, default_value = "ceremony")]
        out_dir: PathBuf,
    },
    /// Ceremony (distributable) — step 3: finalize. Derive the verifying keys
    /// from the contributed params, verify the whole chain, and print the
    /// transcript hash to pin. Writes `verifying_key.bin`, `vk_solana.bin`, and
    /// `transcript/transcript.bin`.
    CeremonyFinalize {
        #[arg(long)]
        params: PathBuf,
        #[arg(long)]
        transcript: PathBuf,
        #[arg(long, default_value = "setup")]
        out_dir: PathBuf,
    },
    /// Verify a ceremony end-to-end from PUBLIC data only (transcript +
    /// verifying key): every same-ratio + Schnorr check, and that the chain
    /// produces the committed key. Prints each contributor and the independent
    /// count. Anyone can run this.
    VerifySetup {
        #[arg(long, default_value = "setup/transcript/transcript.bin")]
        transcript: PathBuf,
        #[arg(long, default_value = "setup/verifying_key.bin")]
        verifying_key: PathBuf,
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
        /// Ceremony proving key (`proving_key.bin` from `setup`).
        #[arg(long)]
        proving_key: PathBuf,
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
        /// Pool entry fee in lamports; used to price the cost of the simulated
        /// Sybil inflation (0 = fee off).
        #[arg(long, default_value_t = 0)]
        entry_fee: u64,
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
        /// On-chain verifying key (`vk_solana.bin` from `setup`).
        #[arg(long)]
        verifying_key: PathBuf,
        #[arg(long, default_value_t = 2)]
        k_min: u64,
        /// Anti-Sybil entry fee in lamports charged on every deposit (0 = off).
        /// Prices Sybil inflation (each fake identity costs a real fee); it does
        /// not make it impossible.
        #[arg(long, default_value_t = 0)]
        entry_fee: u64,
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
        Command::Setup {
            out_dir,
            contributions,
        } => cmd_setup(&out_dir, contributions),
        Command::CeremonyInit { out_dir } => cmd_ceremony_init(&out_dir),
        Command::CeremonyContribute {
            params,
            transcript,
            contributor,
            out_dir,
        } => cmd_ceremony_contribute(&params, &transcript, &contributor, &out_dir),
        Command::CeremonyFinalize {
            params,
            transcript,
            out_dir,
        } => cmd_ceremony_finalize(&params, &transcript, &out_dir),
        Command::VerifySetup {
            transcript,
            verifying_key,
        } => cmd_verify_setup(&transcript, &verifying_key),
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
        Command::Associate {
            proving_key,
            set,
            secret,
            epoch,
        } => cmd_associate(&proving_key, &set, &secret, epoch),
        Command::Disclose {
            secret,
            auditor_pubkey,
        } => cmd_disclose(&secret, &auditor_pubkey),
        Command::Sim {
            members,
            sybils,
            actors,
            epochs,
            entry_fee,
        } => cmd_sim(members, sybils, actors, epochs, entry_fee),
        Command::InitPool {
            rpc_url,
            keypair,
            program_id,
            verifying_key,
            k_min,
            entry_fee,
        } => cmd_init_pool(
            &rpc_url,
            &keypair,
            &program_id,
            &verifying_key,
            k_min,
            entry_fee,
        ),
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

fn cmd_setup(out_dir: &Path, contributions: usize) -> Result<()> {
    std::fs::create_dir_all(out_dir).context("create out dir")?;
    eprintln!(
        "running a {contributions}-contribution Phase-2 ceremony (depth {TREE_DEPTH}) with OS entropy…"
    );
    // Real multi-contributor Phase-2 with fresh entropy. Secure if ≥1
    // contribution's randomness was discarded.
    let mut rng = OsRng;
    let (pk, vk, transcript) =
        run_ceremony(contributions, &mut rng).map_err(|e| anyhow!("ceremony: {e}"))?;

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| anyhow!("serialize pk: {e}"))?;
    std::fs::write(out_dir.join("proving_key.bin"), &pk_bytes)?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| anyhow!("serialize vk: {e}"))?;
    std::fs::write(out_dir.join("verifying_key.bin"), &vk_bytes)?;
    std::fs::write(out_dir.join("vk_solana.bin"), vk_to_solana(&vk).to_bytes())?;
    std::fs::write(
        out_dir.join("transcript.bin"),
        transcript
            .to_bytes()
            .map_err(|e| anyhow!("transcript: {e}"))?,
    )?;

    println!(
        "wrote proving_key.bin, verifying_key.bin, vk_solana.bin, transcript.bin to {}",
        out_dir.display()
    );
    println!("transcript hash: {}", hex::encode(transcript.hash()));
    println!(
        "⚠  This ran all contributions on ONE machine, so it is only as honest as \
         this operator. A real deployment coordinates contributions across \
         INDEPENDENT parties (and adds a public Phase-1). See docs/security.md."
    );
    Ok(())
}

/// Parse a contributor identifier: a 64-char hex string is taken as a raw
/// 32-byte pubkey; anything else is hashed into a stable id via `contributor_id`.
fn parse_contributor(s: &str) -> [u8; 32] {
    let t = s.trim().trim_start_matches("0x");
    if t.len() == 64 {
        if let Ok(bytes) = hex::decode(t) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return arr;
            }
        }
    }
    contributor_id(s)
}

fn read_pk(path: &Path) -> Result<ProvingKey<Bn254>> {
    let bytes = std::fs::read(path).with_context(|| format!("read params {}", path.display()))?;
    ProvingKey::<Bn254>::deserialize_compressed(&bytes[..])
        .map_err(|e| anyhow!("deserialize params: {e}"))
}

fn write_params(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .map_err(|e| anyhow!("serialize params: {e}"))?;
    std::fs::write(path, &bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Ceremony step 1: base params + empty transcript for contributors to extend.
fn cmd_ceremony_init(out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir).context("create out dir")?;
    eprintln!("generating base params (depth {TREE_DEPTH}) with OS entropy…");
    let mut rng = OsRng;
    let (pk, _vk) = base_setup(&mut rng).map_err(|e| anyhow!("base setup: {e}"))?;
    let transcript = Transcript {
        base_delta_g1: pk.delta_g1,
        base_delta_g2: pk.vk.delta_g2,
        contributions: vec![],
    };
    write_params(&pk, &out_dir.join("params.bin"))?;
    std::fs::write(
        out_dir.join("transcript.bin"),
        transcript
            .to_bytes()
            .map_err(|e| anyhow!("transcript: {e}"))?,
    )?;
    println!(
        "wrote params.bin + transcript.bin to {} (0 contributions).",
        out_dir.display()
    );
    println!(
        "Publish both. Each INDEPENDENT operator runs `ceremony-contribute` in turn, \
         then `ceremony-finalize` derives the key. Independent parties are what make \
         the '≥1 honest' guarantee real."
    );
    Ok(())
}

/// Ceremony step 2: add one contribution as an external operator.
fn cmd_ceremony_contribute(
    params: &Path,
    transcript: &Path,
    contributor: &str,
    out_dir: &Path,
) -> Result<()> {
    std::fs::create_dir_all(out_dir).context("create out dir")?;
    let mut pk = read_pk(params)?;
    let bytes = std::fs::read(transcript).context("read transcript")?;
    let mut t = Transcript::from_bytes(&bytes).map_err(|e| anyhow!("parse transcript: {e}"))?;

    // The params must be exactly the transcript's current head, and the chain so
    // far must verify — otherwise we would be building on an inconsistent state.
    let (head_g1, head_g2) = t.head();
    if pk.delta_g1 != head_g1 || pk.vk.delta_g2 != head_g2 {
        return Err(anyhow!(
            "params do not match the transcript head — mismatched or corrupted inputs"
        ));
    }
    if !t.contributions.is_empty() && !verify_transcript(&t, &pk.vk) {
        return Err(anyhow!(
            "the transcript received does not verify; refusing to extend it"
        ));
    }

    let id = parse_contributor(contributor);
    eprintln!("contributing with fresh OS entropy (discarded on exit)…");
    let mut rng = OsRng;
    let c = contribute(&mut pk, id, &mut rng);
    t.contributions.push(c);

    write_params(&pk, &out_dir.join("params.bin"))?;
    std::fs::write(
        out_dir.join("transcript.bin"),
        t.to_bytes().map_err(|e| anyhow!("transcript: {e}"))?,
    )?;
    println!(
        "contribution added (contributor {}). Chain now has {} contribution(s), {} independent.",
        hex::encode(id),
        t.contributions.len(),
        t.independent_contributors()
    );
    println!("transcript hash: {}", hex::encode(t.hash()));
    println!("Pass params.bin + transcript.bin to the next INDEPENDENT operator, or finalize.");
    Ok(())
}

/// Ceremony step 3: derive + verify the verifying key from the contributed params.
fn cmd_ceremony_finalize(params: &Path, transcript: &Path, out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir.join("transcript")).context("create out dir")?;
    let pk = read_pk(params)?;
    let bytes = std::fs::read(transcript).context("read transcript")?;
    let t = Transcript::from_bytes(&bytes).map_err(|e| anyhow!("parse transcript: {e}"))?;

    if !verify_transcript(&t, &pk.vk) {
        return Err(anyhow!(
            "transcript does not verify against these params — refusing to finalize"
        ));
    }
    let vk = pk.vk.clone();
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| anyhow!("serialize vk: {e}"))?;
    std::fs::write(out_dir.join("verifying_key.bin"), &vk_bytes)?;
    std::fs::write(
        out_dir.join("verifying_key.solana.bin"),
        vk_to_solana(&vk).to_bytes(),
    )?;
    std::fs::write(
        out_dir.join("transcript").join("transcript.bin"),
        t.to_bytes().map_err(|e| anyhow!("transcript: {e}"))?,
    )?;
    println!(
        "finalized: wrote verifying_key.bin, verifying_key.solana.bin, transcript/transcript.bin to {}",
        out_dir.display()
    );
    println!(
        "contributions: {}, independent contributors: {}",
        t.contributions.len(),
        t.independent_contributors()
    );
    println!("transcript hash (pin this): {}", hex::encode(t.hash()));
    Ok(())
}

/// Verify a ceremony end-to-end from public data (transcript + verifying key).
fn cmd_verify_setup(transcript: &Path, verifying_key: &Path) -> Result<()> {
    let vk_bytes = std::fs::read(verifying_key).context("read verifying key")?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .map_err(|e| anyhow!("deserialize verifying key: {e}"))?;
    let bytes = std::fs::read(transcript).context("read transcript")?;
    let t = Transcript::from_bytes(&bytes).map_err(|e| anyhow!("parse transcript: {e}"))?;

    println!(
        "ceremony transcript: {} contribution(s)",
        t.contributions.len()
    );
    for (i, c) in t.contributions.iter().enumerate() {
        println!("  #{i}: contributor {}", hex::encode(c.contributor));
    }
    let ok = verify_transcript(&t, &vk);
    if !ok {
        return Err(anyhow!(
            "VERIFY FAILED: the transcript chain does not verify against this verifying key"
        ));
    }
    println!("chain verifies ✓ (every same-ratio + Schnorr PoK check passed)");
    println!("independent contributors: {}", t.independent_contributors());
    println!("transcript hash: {}", hex::encode(t.hash()));
    println!(
        "Assurance: secure iff ≥1 of the {} independent contributor(s) was honest and \
         discarded their entropy.",
        t.independent_contributors()
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

fn cmd_associate(proving_key: &Path, set_path: &Path, secret_hex: &str, epoch: u64) -> Result<()> {
    use ark_bn254::Bn254;
    use ark_groth16::ProvingKey;
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
    // Load the ceremony proving key (produced by `mirror-pool setup`); its
    // embedded verifying key is used for the self-check.
    let pk_bytes = std::fs::read(proving_key).context("read proving key")?;
    let pk: ProvingKey<Bn254> = CanonicalDeserialize::deserialize_compressed(&pk_bytes[..])
        .map_err(|e| anyhow!("deserialize pk: {e}"))?;
    let vk = pk.vk.clone();
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

fn cmd_sim(members: u64, sybils: u64, actors: u64, epochs: u64, entry_fee: u64) -> Result<()> {
    use mirror_pool_anonymity::{measure, sybil_inflation_cost, Bucket, Note};
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
        "headline: real-k = nominal − flagged (same-funder clustering), == dominance-adjusted \
         min-entropy effective-k (1/max_i p_i; PET'02, FoSSaCS'09). nominal shown as secondary.\n"
    );

    let report = measure(&notes, &buckets);
    for epoch in 1..=epochs {
        // Every epoch draws from the same candidate set. The headline is real-k
        // over all deposits (the observer's view, with flagged Sybils removed);
        // nominal is the naive, inflatable count shown as a labeled secondary.
        let real_k = report.over_all.real_k();
        let nominal = report.over_all.nominal_k;
        let assoc_real = report.over_associated.real_k();
        let warn = if actors <= 1 {
            "  ⚠ single action this window — timing-correlatable regardless of k"
        } else {
            ""
        };
        println!(
            "  epoch {epoch}: real-k = {real_k:.1} (nominal {nominal}, flagged {}); \
             real-k over associated set = {assoc_real:.1}{warn}",
            report.over_all.flagged
        );
    }
    println!(
        "\nHeadline real-k: {:.1} (nominal {} over all deposits; {:.1} over the association set).",
        report.over_all.real_k(),
        report.over_all.nominal_k,
        report.over_associated.real_k(),
    );
    println!(
        "real-k discounts the largest same-funder cluster — an estimate of honest anonymity, NOT \
         a cryptographic guarantee (an adversary splitting Sybils across many identities evades \
         the heuristic). k_min on-chain bounds program-visible membership, NOT honest anonymity."
    );
    if entry_fee > 0 {
        let cost = sybil_inflation_cost(members + sybils, members, entry_fee);
        println!(
            "entry fee: inflating to nominal {} with {} sybils costs {} × {} = {} lamports ({:.3} SOL) — \
             the fee prices Sybil inflation; it does not make it impossible.",
            members + sybils,
            sybils,
            sybils,
            entry_fee,
            cost,
            cost as f64 / 1e9,
        );
    } else {
        println!(
            "entry fee: OFF (--entry-fee 0). With a fee set, inflating to nominal {} would cost \
             {} × entry_fee lamports; run with --entry-fee to price it.",
            members + sybils,
            sybils,
        );
    }
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

fn cmd_init_pool(
    rpc_url: &str,
    keypair: &Path,
    program_id: &str,
    verifying_key: &Path,
    k_min: u64,
    entry_fee: u64,
) -> Result<()> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program_id = Pubkey::from_str(program_id).context("program id")?;
    let payer = read_keypair_file(keypair).map_err(|e| anyhow!("read keypair: {e}"))?;
    // The signer is the pool authority.
    let pool = pool_pda(&program_id, &payer.pubkey());

    // On-chain verifying key: the `vk_solana.bin` produced by `setup` (the
    // ceremony output). Loaded from a file — not hardcoded.
    let vk_bytes: [u8; mirror_pool_program::verifier::VK_SERIALIZED_LEN] =
        std::fs::read(verifying_key)
            .context("read verifying key")?
            .try_into()
            .map_err(|_| {
                anyhow!(
                    "verifying key must be {} bytes",
                    mirror_pool_program::verifier::VK_SERIALIZED_LEN
                )
            })?;

    let data = mirror_pool_program::instruction::Instruction::InitializePool {
        depth: TREE_DEPTH as u8,
        k_min,
        verifying_key: vk_bytes,
        entry_fee,
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
    println!("pool {pool} initialized (k_min {k_min}, entry_fee {entry_fee}): {sig}");
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
    // Pass the depositor (signer, writable) + system_program so the deposit
    // works whether or not the pool charges an entry fee: the program consumes
    // these only when `entry_fee > 0` (to CPI the fee into the pool vault), and
    // ignores the extra accounts when the fee is disabled.
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
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
