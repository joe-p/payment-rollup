//! Proves one block: that `old_root` becomes `new_root`, and `deposit_anchor` becomes the deposit
//! chain the batch folds to, by replaying the batch the chain records.
//!
//! Everything read here is prover-supplied and private. The only thing that escapes is the 160
//! bytes of [`public_values`], and the batch bytes are represented there by a commitment rather
//! than in full -- public values are hashed into the proof and handed to the verifier, so carrying
//! the batch in them would mean paying for it twice. The settlement contract is given the batch
//! bytes in the same transaction that verifies the proof, hashes them itself, and compares.
//!
//! Note what is *not* here: no root and no deposit chain is read as the expected answer. The guest
//! replays and reports where it landed on both, and the contract decides whether those are the
//! values it was holding.

#![no_main]

sp1_zkvm::entrypoint!(main);

use payment_rollup::execute;

pub fn main() {
    // The batch bytes are read exactly as the chain will record them and decoded with the same
    // decoder a replaying full node runs, so there is no separate encoding of the transactions for
    // the proof to disagree with.
    let old_root: [u8; 32] = sp1_zkvm::io::read_vec()
        .try_into()
        .expect("old_root must be 32 bytes");
    let deposit_anchor: [u8; 32] = sp1_zkvm::io::read_vec()
        .try_into()
        .expect("deposit_anchor must be 32 bytes");
    let batch_bytes = sp1_zkvm::io::read_vec();
    let sidecar_bytes = sp1_zkvm::io::read_vec();

    // Everything the proof asserts lives in `execute`, so the host can compute these same 160 bytes
    // without a zkVM. This is only the io.
    let values =
        execute(old_root, deposit_anchor, &batch_bytes, &sidecar_bytes).expect("block must prove");

    sp1_zkvm::io::commit_slice(&values);
}
