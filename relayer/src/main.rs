//! `mirror-pool` relayer + epoch batcher (off-chain).
//!
//! The relayer is **core, not optional**: it submits `execute_action`
//! transactions and pays the fee so a member's wallet is never the fee payer of
//! the action it triggered (SPEC §4.4). Landing in milestone 6.

fn main() {
    eprintln!(
        "mirror-pool relayer: not yet implemented (lands in milestone 6). \
         See SPEC.md §4.4."
    );
    std::process::exit(1);
}
