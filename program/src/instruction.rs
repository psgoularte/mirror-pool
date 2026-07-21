//! Instruction encoding for the mirror-pool program.
//!
//! Milestone 3 defines a single instruction, `VerifyMembership`, used to prove
//! on-chain that an arkworks-generated Groth16 proof verifies within the
//! compute budget. Later milestones fold this verification into
//! `execute_action` and add the deposit/epoch/compliance instructions; the
//! encoding here is deliberately minimal (a leading tag byte + fixed-width
//! payload) so it stays cheap to parse on BPF.

use crate::error::MirrorPoolError;
use crate::verifier::{NUM_PUBLIC_INPUTS, PROOF_LEN};
use solana_program::program_error::ProgramError;

/// Byte length of the `VerifyMembership` payload: proof + public inputs.
pub const VERIFY_MEMBERSHIP_DATA_LEN: usize = PROOF_LEN + NUM_PUBLIC_INPUTS * 32;

/// Instruction tags (first byte of instruction data).
#[repr(u8)]
pub enum Tag {
    VerifyMembership = 0,
}

/// A decoded instruction.
pub enum Instruction {
    /// Verify a membership proof against the verifying key stored in the first
    /// account. Carries the proof (`a||b||c`, `a` negated) and the four
    /// big-endian public inputs.
    VerifyMembership {
        proof: [u8; PROOF_LEN],
        public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS],
    },
}

impl Instruction {
    /// Parse instruction data. Fails loudly on any unexpected tag or length.
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let (&tag, rest) = data
            .split_first()
            .ok_or(ProgramError::from(MirrorPoolError::InvalidInstructionData))?;
        match tag {
            t if t == Tag::VerifyMembership as u8 => {
                if rest.len() != VERIFY_MEMBERSHIP_DATA_LEN {
                    return Err(MirrorPoolError::InvalidInstructionData.into());
                }
                let mut proof = [0u8; PROOF_LEN];
                proof.copy_from_slice(&rest[..PROOF_LEN]);
                let mut public_inputs = [[0u8; 32]; NUM_PUBLIC_INPUTS];
                for (i, chunk) in rest[PROOF_LEN..].chunks_exact(32).enumerate() {
                    public_inputs[i].copy_from_slice(chunk);
                }
                Ok(Instruction::VerifyMembership {
                    proof,
                    public_inputs,
                })
            }
            _ => Err(MirrorPoolError::InvalidInstructionData.into()),
        }
    }

    /// Encode a `VerifyMembership` instruction's data (tag + payload).
    pub fn pack_verify_membership(
        proof: &[u8; PROOF_LEN],
        public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + VERIFY_MEMBERSHIP_DATA_LEN);
        data.push(Tag::VerifyMembership as u8);
        data.extend_from_slice(proof);
        for pi in public_inputs {
            data.extend_from_slice(pi);
        }
        data
    }
}
