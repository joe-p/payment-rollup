//! Everything a settlement transaction needs, produced without a zkVM.
//!
//! The guest is [`payment_rollup::execute`] wrapped in zkVM io, so running that function directly
//! gives the exact 192 bytes a proof would commit for the cost of replaying the block. What is
//! missing is only the proof that the replay happened, which is precisely the part the settlement
//! contract does not check yet.
//!
//! So a [`Settlement`] is the whole of a settlement's argument list: the declared batch length to
//! open with, the chunks to post, the ordered inbox items to replay onto L1 first, withdrawals
//! afterwards, and the public values to settle against. See [`scenarios`] for the blocks these are
//! built from.

use payment_rollup::{
    Address, Block, DeploymentDomain, ExecutionError, L1Address, Transaction, VerificationError,
    WithdrawalLink, chunk_count, execute,
};

pub mod scenarios;

/// Groth16 proving, which is the one thing here that needs a zkVM and a network.
#[cfg(feature = "prove")]
pub mod prove;

/// What a block costs in the zkVM: the same guest, executed locally and counted rather than proved.
#[cfg(feature = "prove")]
pub mod report;

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

/// The unified L1 inbox chain a freshly deployed contract starts life holding.
pub use payment_rollup::INBOX_CHAIN_GENESIS;

/// A Groth16 proof of one settlement, reduced to what a fixture carries.
///
/// Plain data, and deliberately not behind the `prove` feature. The shape of the emitted JSON
/// should not depend on how the binary was built, and keeping this type unconditional is what lets
/// the emitter have one code path rather than two.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofFixture {
    /// The proof in the encoding an onchain verifier takes: a four-byte selector cut from
    /// [`Self::verifier_hash`], then the proof itself.
    pub bytes: Vec<u8>,
    /// The program's verifying key, `0x`-prefixed. What the verifier is pinned to, and the same
    /// for every scenario proved against one ELF.
    pub vkey: String,
    /// The five field elements the Groth16 circuit is checked against. The first two are the vkey
    /// hash and the hash of the public values.
    pub public_inputs: [String; 5],
    /// The proof alone, hex and without the selector.
    pub encoded_proof: String,
    /// The Groth16 *verifier's* key hash -- not the program's. Its first four bytes are the
    /// selector prefixed onto [`Self::bytes`], which is how a verifier holding several circuits
    /// picks the right one.
    pub verifier_hash: [u8; 32],
}

/// One L1 action, in the global order the settlement must submit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboxItem {
    Deposit {
        recipient: Address,
        amount: u64,
    },
    ForcedWithdrawal {
        address: Address,
        recipient: L1Address,
    },
}

/// One block, reduced to the arguments the settlement contract takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    domain: DeploymentDomain,
    old_root: [u8; 32],
    new_root: [u8; 32],
    old_inbox_chain: [u8; 32],
    new_inbox_chain: [u8; 32],
    withdrawal_chain: [u8; 32],
    deposits: Vec<(Address, u64)>,
    withdrawals: Vec<(L1Address, u64)>,
    requests: Vec<(Address, L1Address)>,
    inbox: Vec<InboxItem>,
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

        let public_values = execute(
            block.domain(),
            block.old_root(),
            block.old_inbox_chain(),
            &batch_bytes,
            &sidecar_bytes,
        )?;

        // The guest is never told what root to expect, so the replay landing somewhere other than
        // the root this block claims is a real disagreement and not a redundant check. The same
        // goes for every chain.
        if public_values[32..64] != block.new_root()
            || public_values[128..160] != block.new_inbox_chain()
            || public_values[160..192] != block.withdrawal_chain()
        {
            return Err(ExecutionError::Verification(
                VerificationError::RootMismatch,
            ));
        }

        // Read back off the wire rather than out of the in-memory block, so these are the lists a
        // replaying node would reconstruct -- which is what the e2e has to feed L1 to reach the
        // chain the batch folds to, and what anyone claiming a withdrawal has to prove.
        let txns = payment_rollup::Batch::decode(&batch_bytes)?;

        let deposits = txns
            .txns()
            .iter()
            .filter_map(|txn| match txn {
                Transaction::Deposit(deposit) => Some((deposit.receiver(), deposit.amount())),
                _ => None,
            })
            .collect();

        // A forced withdrawal's payout is a function of the pre-state, not of the batch bytes, so
        // the queue is read out of the batch and sidecar together rather than off the wire alone.
        let sidecar = payment_rollup::Sidecar::decode(&sidecar_bytes, &txns)?;
        let withdrawals = payment_rollup::withdrawal_payouts(&txns, &sidecar);

        let requests = txns
            .txns()
            .iter()
            .filter_map(|txn| match txn {
                Transaction::ForcedWithdrawal(forced) => {
                    Some((forced.address(), forced.recipient()))
                }
                _ => None,
            })
            .collect();

        let inbox = txns
            .txns()
            .iter()
            .filter_map(|txn| match txn {
                Transaction::Deposit(deposit) => Some(InboxItem::Deposit {
                    recipient: deposit.receiver(),
                    amount: deposit.amount(),
                }),
                Transaction::ForcedWithdrawal(forced) => Some(InboxItem::ForcedWithdrawal {
                    address: forced.address(),
                    recipient: forced.recipient(),
                }),
                _ => None,
            })
            .collect();

        Ok(Self {
            domain: block.domain(),
            old_root: block.old_root(),
            new_root: block.new_root(),
            old_inbox_chain: block.old_inbox_chain(),
            new_inbox_chain: block.new_inbox_chain(),
            withdrawal_chain: block.withdrawal_chain(),
            deposits,
            withdrawals,
            requests,
            inbox,
            txn_count: block.batch().len(),
            batch_bytes,
            sidecar_bytes,
            public_values,
        })
    }

    /// The inbox chain the batch anchors to: what the contract must have settled last time.
    pub fn inbox_chain_from(&self) -> [u8; 32] {
        self.old_inbox_chain
    }

    /// The inbox chain the batch's L1 items fold it to.
    pub fn inbox_chain_to(&self) -> [u8; 32] {
        self.new_inbox_chain
    }

    /// Every deposit the batch credits, in the order it credits them.
    ///
    /// These have to be replayed onto L1 -- one `deposit` call each, in this order -- before the
    /// This is a convenience view. [`Self::inbox`] is authoritative for L1 submission order.
    pub fn deposits(&self) -> &[(Address, u64)] {
        &self.deposits
    }

    pub fn domain(&self) -> DeploymentDomain {
        self.domain
    }

    pub fn withdrawal_chain(&self) -> [u8; 32] {
        self.withdrawal_chain
    }

    /// Every L1 withdrawal request the batch answers, in the order it answers them.
    ///
    /// This is a convenience view. [`Self::inbox`] is authoritative for L1 submission order.
    pub fn requests(&self) -> &[(Address, L1Address)] {
        &self.requests
    }

    /// Deposits and forced withdrawals in exact batch order.
    pub fn inbox(&self) -> &[InboxItem] {
        &self.inbox
    }

    /// Every withdrawal the batch makes, in the order it makes them.
    ///
    pub fn withdrawals(&self) -> &[(L1Address, u64)] {
        &self.withdrawals
    }

    /// The payout calls the settlement contract will accept, in the only order it will accept them.
    pub fn withdrawal_links(&self) -> Vec<WithdrawalLink> {
        payment_rollup::withdrawal_links(&self.domain, &self.withdrawals)
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

    /// The 200 bytes a proof would commit, and the single argument `verifyBatch` takes.
    pub fn public_values(&self) -> &[u8; PUBLIC_VALUES_SIZE] {
        &self.public_values
    }

    /// The batch commitment the contract's accumulator has to arrive at, read out of the public
    /// values rather than recomputed -- this is the value the contract compares against.
    pub fn batch_commitment(&self) -> [u8; 32] {
        self.public_values[64..96].try_into().unwrap()
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

    /// Whether a freshly deployed contract will accept this.
    ///
    /// Now that a batch can carry deposits, every funded state is reachable from the empty ledger
    /// by a block that opens with them -- so this should hold for every scenario, and the host
    /// tests assert exactly that. It is kept as a named invariant rather than deleted because it is
    /// the property that let the contract's `seedStateRoot` escape hatch be removed.
    pub fn settles_from_genesis(&self) -> bool {
        self.old_root == GENESIS_ROOT && self.old_inbox_chain == INBOX_CHAIN_GENESIS
    }
}

/// Lowercase hex, which is how every byte string here crosses into the TypeScript tests.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use payment_rollup::{
        accumulate_chunk, accumulate_deposit, accumulate_request, chunk_accumulator_seed,
        chunk_digest,
    };

    const DOMAIN: DeploymentDomain = [0x42; 32];

    /// The contract's side of the fold: seed from the declared length, then one step per posted
    /// chunk. If this does not land on the commitment in the public values, the chunks being
    /// emitted are not the ones the contract needs.
    fn accumulate_as_the_contract_would(settlement: &Settlement) -> [u8; 32] {
        let mut accumulator =
            chunk_accumulator_seed(&settlement.domain(), settlement.batch_length());
        for chunk in settlement.chunks() {
            accumulator = accumulate_chunk(&accumulator, &chunk_digest(chunk));
        }

        accumulator
    }

    #[test]
    fn every_scenario_produces_a_settlement() {
        for scenario in scenarios::all() {
            let settlement = Settlement::for_block(&(scenario.build)(DOMAIN))
                .unwrap_or_else(|error| panic!("{}: {error}", scenario.name));

            assert_eq!(&settlement.public_values[..32], &settlement.old_root());
            assert_eq!(&settlement.public_values[32..64], &settlement.new_root());
            assert_eq!(
                &settlement.public_values[96..128],
                &settlement.inbox_chain_from()
            );
            assert_eq!(
                &settlement.public_values[128..160],
                &settlement.inbox_chain_to()
            );
            assert_eq!(
                &settlement.public_values[160..192],
                &settlement.withdrawal_chain()
            );
            assert_eq!(
                accumulate_as_the_contract_would(&settlement),
                settlement.batch_commitment(),
                "{}: the posted chunks must fold to the committed commitment",
                scenario.name
            );
        }
    }

    /// The contract's side of the unified inbox: one fold per L1 action in batch order.
    #[test]
    fn every_scenario_inbox_folds_from_its_anchor() {
        for scenario in scenarios::all() {
            let settlement = Settlement::for_block(&(scenario.build)(DOMAIN)).unwrap();

            let mut chain = settlement.inbox_chain_from();
            for item in settlement.inbox() {
                chain = match item {
                    InboxItem::Deposit { recipient, amount } => {
                        accumulate_deposit(&chain, recipient, *amount)
                    }
                    InboxItem::ForcedWithdrawal { address, recipient } => {
                        accumulate_request(&chain, address, recipient)
                    }
                };
            }

            assert_eq!(
                chain,
                settlement.inbox_chain_to(),
                "{}: replaying the inbox onto L1 must reach the chain the batch folds to",
                scenario.name
            );
        }
    }

    // A batch with no inbox items leaves the chain where it was.
    #[test]
    fn a_scenario_without_deposits_leaves_the_chain_alone() {
        let settlement = Settlement::for_block(&(scenarios::find("genesis-empty-batch")
            .unwrap()
            .build)(DOMAIN))
        .unwrap();

        assert!(settlement.inbox().is_empty());
        assert_eq!(settlement.inbox_chain_to(), settlement.inbox_chain_from());
    }

    // Deposits are the only way value enters, so a scenario that moves money has to start with one.
    #[test]
    fn a_deposit_bearing_scenario_exists() {
        assert!(
            scenarios::all().iter().any(|scenario| {
                !Settlement::for_block(&(scenario.build)(DOMAIN))
                    .unwrap()
                    .deposits()
                    .is_empty()
            }),
            "the deposit path needs a fixture that actually carries deposits"
        );
    }

    #[test]
    fn chunks_are_full_until_the_last_one() {
        for scenario in scenarios::all() {
            let settlement = Settlement::for_block(&(scenario.build)(DOMAIN)).unwrap();
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

    // Every scenario, not merely one: with deposits carrying value in, there is no longer any state
    // a block cannot prove its way to from the empty ledger, so nothing needs its root seeded.
    #[test]
    fn every_scenario_settles_against_a_fresh_contract() {
        for scenario in scenarios::all() {
            assert!(
                Settlement::for_block(&(scenario.build)(DOMAIN))
                    .unwrap()
                    .settles_from_genesis(),
                "{} does not start from genesis, and there is no longer a way to seed a contract \
                 to meet it",
                scenario.name
            );
        }
    }

    #[test]
    fn a_multi_chunk_scenario_exists() {
        assert!(
            scenarios::all().iter().any(|scenario| {
                Settlement::for_block(&(scenario.build)(DOMAIN))
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
