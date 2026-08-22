//! Everything a settlement transaction needs, produced without a zkVM.
//!
//! The guest is [`payment_rollup::execute`] wrapped in zkVM io, so running that function directly
//! gives the exact 96 bytes a proof would commit -- the roots and the batch commitment -- for the
//! cost of replaying the block. What is missing is only the proof that the replay happened, which
//! is precisely the part the settlement contract does not check yet.
//!
//! So a [`Settlement`] is the whole of a settlement's argument list: the declared batch length to
//! open with, the chunks to post, and the public values to settle against. See [`scenarios`] for
//! the blocks these are built from.

use payment_rollup::{Block, ExecutionError, VerificationError, chunk_count, execute};

pub mod scenarios;

/// Re-exported so the binary, and anything else driving the contract, reads the chunk size and the
/// public-values size from one place rather than from two crates.
pub use payment_rollup::{CHUNK_SIZE, PUBLIC_VALUES_SIZE};

/// The root the settlement contract starts life holding.
///
/// An empty sparse tree hashes to 32 zero bytes, and the contract's `createApplication` writes
/// exactly that, so this is the one root a freshly deployed contract will accept a proof against.
/// A [`Settlement`] whose `old_root` is anything else cannot be settled without first advancing the
/// contract there -- see [`Settlement::settles_from_genesis`].
pub const GENESIS_ROOT: [u8; 32] = [0u8; 32];

/// One block, reduced to the arguments the settlement contract takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    old_root: [u8; 32],
    new_root: [u8; 32],
    txn_count: usize,
    batch_bytes: Vec<u8>,
    sidecar_bytes: Vec<u8>,
    public_values: [u8; PUBLIC_VALUES_SIZE],
}

impl Settlement {
    /// Run `block` the way the guest will and collect what settling it takes.
    ///
    /// The block is encoded to its two wire halves first and everything after that reads only the
    /// bytes, so this exercises the encoders, the decoders and the replay together -- the same path
    /// the proof will take, rather than a shortcut through the in-memory block.
    pub fn for_block(block: &Block) -> Result<Self, ExecutionError> {
        let batch_bytes = block.batch().encode();
        let sidecar_bytes = block.sidecar().encode();

        let public_values = execute(block.old_root(), &batch_bytes, &sidecar_bytes)?;

        // The guest is never told what root to expect, so the replay landing somewhere other than
        // the root this block claims is a real disagreement and not a redundant check.
        if public_values[32..64] != block.new_root() {
            return Err(ExecutionError::Verification(
                VerificationError::RootMismatch,
            ));
        }

        Ok(Self {
            old_root: block.old_root(),
            new_root: block.new_root(),
            txn_count: block.batch().len(),
            batch_bytes,
            sidecar_bytes,
            public_values,
        })
    }

    pub fn old_root(&self) -> [u8; 32] {
        self.old_root
    }

    pub fn new_root(&self) -> [u8; 32] {
        self.new_root
    }

    pub fn txn_count(&self) -> usize {
        self.txn_count
    }

    /// The bytes the chain records, which the contract is handed one chunk at a time.
    pub fn batch_bytes(&self) -> &[u8] {
        &self.batch_bytes
    }

    /// The prover-only half. Not needed to drive the contract, and emitted only on request, but it
    /// is what a real proof would be generated from.
    pub fn sidecar_bytes(&self) -> &[u8] {
        &self.sidecar_bytes
    }

    /// The 96 bytes a proof would commit, and the single argument `verifyBatch` takes.
    pub fn public_values(&self) -> &[u8; PUBLIC_VALUES_SIZE] {
        &self.public_values
    }

    /// The batch commitment the contract's accumulator has to arrive at, read out of the public
    /// values rather than recomputed -- this is the value the contract compares against.
    pub fn batch_commitment(&self) -> [u8; 32] {
        self.public_values[64..].try_into().unwrap()
    }

    /// What `openBatch` is called with, and what fixes where every chunk boundary falls.
    pub fn batch_length(&self) -> usize {
        self.batch_bytes.len()
    }

    /// One `accumulateChunk` argument each, in the order they must be posted.
    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.batch_bytes.chunks(CHUNK_SIZE)
    }

    pub fn chunk_count(&self) -> usize {
        chunk_count(self.batch_bytes.len())
    }

    /// Whether a freshly deployed contract will accept this, or whether its root has to be seeded
    /// to [`Settlement::old_root`] first.
    ///
    /// Only a block replayed from the empty ledger can settle against a new contract, and today
    /// that means a block that spends nothing -- there is no deposit path, so there is no way to
    /// prove a route from genesis to a funded state. A fixture that starts from a funded ledger has
    /// to be put there by hand, which is what the contract's `seedStateRoot` is for: call it with
    /// this settlement's `oldRoot` before opening the batch.
    pub fn settles_from_genesis(&self) -> bool {
        self.old_root == GENESIS_ROOT
    }
}

/// Lowercase hex, which is how every byte string here crosses into the TypeScript tests.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use payment_rollup::{accumulate_chunk, chunk_accumulator_seed, chunk_digest};

    /// The contract's side of the fold: seed from the declared length, then one step per posted
    /// chunk. If this does not land on the commitment in the public values, the chunks being
    /// emitted are not the ones the contract needs.
    fn accumulate_as_the_contract_would(settlement: &Settlement) -> [u8; 32] {
        let mut accumulator = chunk_accumulator_seed(settlement.batch_length());
        for chunk in settlement.chunks() {
            accumulator = accumulate_chunk(&accumulator, &chunk_digest(chunk));
        }

        accumulator
    }

    #[test]
    fn every_scenario_produces_a_settlement() {
        for scenario in scenarios::all() {
            let settlement = Settlement::for_block(&(scenario.build)())
                .unwrap_or_else(|error| panic!("{}: {error}", scenario.name));

            assert_eq!(&settlement.public_values[..32], &settlement.old_root());
            assert_eq!(&settlement.public_values[32..64], &settlement.new_root());
            assert_eq!(
                accumulate_as_the_contract_would(&settlement),
                settlement.batch_commitment(),
                "{}: the posted chunks must fold to the committed commitment",
                scenario.name
            );
        }
    }

    #[test]
    fn chunks_are_full_until_the_last_one() {
        for scenario in scenarios::all() {
            let settlement = Settlement::for_block(&(scenario.build)()).unwrap();
            let chunks: Vec<_> = settlement.chunks().collect();

            assert_eq!(chunks.len(), settlement.chunk_count());
            // The contract checks exactly this per chunk, so a scenario that violated it would be
            // rejected at the transaction that posted the offending chunk.
            for chunk in chunks.iter().take(chunks.len().saturating_sub(1)) {
                assert_eq!(chunk.len(), CHUNK_SIZE, "{}", scenario.name);
            }
            assert_eq!(
                chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
                settlement.batch_length()
            );
        }
    }

    // Without one of these there is nothing to run end to end against a newly deployed contract,
    // which is the whole point of the fixtures.
    #[test]
    fn at_least_one_scenario_settles_against_a_fresh_contract() {
        assert!(scenarios::all().iter().any(|scenario| {
            Settlement::for_block(&(scenario.build)())
                .unwrap()
                .settles_from_genesis()
        }));
    }

    #[test]
    fn a_multi_chunk_scenario_exists() {
        assert!(
            scenarios::all().iter().any(|scenario| {
                Settlement::for_block(&(scenario.build)())
                    .unwrap()
                    .chunk_count()
                    > 1
            }),
            "the chunked posting path needs a fixture that actually spans chunks"
        );
    }

    // `find` is how the CLI resolves a name, so a duplicate would leave one scenario unreachable.
    #[test]
    fn scenario_names_are_unique_and_findable() {
        let mut seen = std::collections::HashSet::new();
        for scenario in scenarios::all() {
            assert!(
                seen.insert(scenario.name),
                "duplicate name {}",
                scenario.name
            );
            assert_eq!(scenarios::find(scenario.name).unwrap().name, scenario.name);
        }
        assert!(scenarios::find("no such scenario").is_none());
    }
}
