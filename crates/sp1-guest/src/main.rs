//! Proves one block: that `old_root` becomes `new_root` by replaying the batch the chain records.
//!
//! Everything read here is prover-supplied and private. The only thing that escapes is the 96
//! bytes of [`public_values`], and the batch bytes are represented there by a commitment rather
//! than in full -- public values are hashed into the proof and handed to the verifier, so carrying
//! the batch in them would mean paying for it twice. The settlement contract is given the batch
//! bytes in the same transaction that verifies the proof, hashes them itself, and compares.
//!
//! Note what is *not* here: no root is read as the expected answer. The guest replays and reports
//! where it landed, and the contract decides whether that is the root it was holding.

#![no_main]

sp1_zkvm::entrypoint!(main);

use payment_rollup::{Batch, Sidecar, public_values, verify_batch};

pub fn main() {
    // The batch bytes are read exactly as the chain will record them and decoded with the same
    // decoder a replaying full node runs, so there is no separate encoding of the transactions for
    // the proof to disagree with.
    let old_root: [u8; 32] = sp1_zkvm::io::read_vec()
        .try_into()
        .expect("old_root must be 32 bytes");
    let batch_bytes = sp1_zkvm::io::read_vec();
    let sidecar_bytes = sp1_zkvm::io::read_vec();

    let batch = Batch::decode(&batch_bytes).expect("batch must decode");
    let sidecar = Sidecar::decode(&sidecar_bytes, batch.len()).expect("sidecar must decode");

    let new_root = verify_batch(old_root, &batch, &sidecar).expect("block must verify");

    sp1_zkvm::io::commit_slice(&public_values(&old_root, &new_root, &batch_bytes));
}
