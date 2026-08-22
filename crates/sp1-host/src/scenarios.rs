//! Blocks to settle, chosen for what they make the contract do rather than for what they do to the
//! ledger.
//!
//! Between them they cover what a settlement exercises: a batch that fits in one chunk, a batch
//! that does not, a batch of nothing but deposits, and the transition being nothing at all. Every
//! account here is authorized by [`Scheme::Managed`], because signature verification is still a
//! `TODO` in the replay -- a scenario carries an empty signature and the replay checks only that
//! its address matches the account's `auth_address`.
//!
//! Every scenario starts from the empty ledger. Value gets in the way it does in production, with a
//! deposit at the head of the block, so there is nothing here a contract has to be put into
//! position to accept.

use payment_rollup::{
    Address, Block, Deposit, Ledger, Payment, Scheme, Signature, SignedTransaction,
    address_from_public_key,
};

const SCHEME: Scheme = Scheme::Managed;

/// A named block, built on demand so nothing is computed for scenarios that were not asked for.
pub struct Scenario {
    pub name: &'static str,
    /// What this scenario is for, carried through to the emitted JSON so a failing test says
    /// something about the case it was covering.
    pub description: &'static str,
    pub build: fn() -> Block,
}

pub fn all() -> &'static [Scenario] {
    &[
        Scenario {
            name: "genesis-empty-batch",
            description: "An empty batch replayed from the empty ledger. It starts and ends at the \
                          genesis root and carries no deposits, so it drives openBatch, one \
                          accumulateChunk and verifyBatch while leaving both the state root and the \
                          deposit chain where they were.",
            build: genesis_empty_batch,
        },
        Scenario {
            name: "deposits-only",
            description: "Nothing but deposits, from the empty ledger. The cleanest test of the \
                          deposit chain: with no payments in the way, a mismatch between what the \
                          contract folded as the deposits arrived and what the guest folded out of \
                          the batch can only be a disagreement about the fold itself.",
            build: deposits_only,
        },
        Scenario {
            name: "payments",
            description: "Two deposits and then three payments: a plain one, one that brings a new \
                          account into existence, and a self-payment. One chunk. Value enters and \
                          moves in the same batch, which is what interleaving deposits with \
                          payments is for.",
            build: payments,
        },
        Scenario {
            name: "multi-chunk",
            description: "A deposit followed by payments to enough distinct receivers that the \
                          batch spans several chunks, so the accumulator is folded more than once \
                          and the last chunk is a partial one.",
            build: multi_chunk,
        },
    ]
}

pub fn find(name: &str) -> Option<&'static Scenario> {
    all().iter().find(|scenario| scenario.name == name)
}

fn address_of(key: &[u8]) -> Address {
    address_from_public_key(SCHEME, key)
}

/// Put `amount` into the account for `key`, the way L1 does it.
///
/// Placed at the head of a block, this is what funds every scenario below. Nothing is written into
/// the ledger behind the block's back any more, which is what lets all of them start from
/// [`crate::GENESIS_ROOT`].
///
/// The address it credits is the account for `key`, so the depositor can spend what they put in --
/// see `Account::empty`, which is what a deposit pins a created account to.
fn deposit(key: &[u8], amount: u64) -> SignedTransaction {
    SignedTransaction::deposit(Deposit::new(address_of(key), amount))
}

/// A payment of `amount` from the account for `key` to `receiver`, signed by `key`.
///
/// No nonce: the sequencer assigns each sender its next one in the order the block lists them.
fn pay(key: &[u8], receiver: Address, amount: u64) -> SignedTransaction {
    SignedTransaction::payment(
        Payment::new(address_of(key), receiver, amount),
        Signature::new(SCHEME, key.to_vec(), Vec::new()),
    )
}

fn genesis_empty_batch() -> Block {
    Ledger::new().get_block(Vec::new())
}

/// Three deposits, the first two identical, so the fixture covers a fresh dictionary entry and a
/// warm one -- and, more to the point, two deposits a set commitment would collapse into one.
///
/// Deliberately not a palindrome. A reversed copy of this list has to be a different list, or the
/// end-to-end test for reordering would be asserting against the sequence it started with.
fn deposits_only() -> Block {
    Ledger::new().get_block(vec![
        deposit(b"a key", 1_000),
        deposit(b"a key", 1_000),
        deposit(b"b key", 500),
    ])
}

fn payments() -> Block {
    let mut ledger = Ledger::new();
    let (a, b) = (address_of(b"a key"), address_of(b"b key"));
    let fresh = address_of(b"fresh key");

    ledger.get_block(vec![
        deposit(b"a key", 1_000),
        deposit(b"b key", 500),
        pay(b"a key", b, 100),
        pay(b"b key", fresh, 50),
        pay(b"a key", a, 25),
    ])
}

/// One payment per receiver, at the ~38 bytes a payment costs when the sender repeats and the
/// receiver is new, which puts the batch a few chunks over the boundary.
fn multi_chunk() -> Block {
    const PAYMENTS: u32 = 300;
    const AMOUNT: u64 = 1_000_000;

    let mut ledger = Ledger::new();

    let mut stxns = vec![deposit(b"spender", PAYMENTS as u64 * AMOUNT)];
    stxns.extend(
        (0..PAYMENTS).map(|index| pay(b"spender", address_of(&index.to_be_bytes()), AMOUNT)),
    );

    ledger.get_block(stxns)
}

#[cfg(test)]
mod tests {
    use super::*;

    use payment_rollup::{CHUNK_SIZE, verify_block};

    #[test]
    fn every_scenario_is_a_block_that_verifies() {
        for scenario in all() {
            assert_eq!(
                verify_block(&(scenario.build)()),
                Ok(()),
                "{}",
                scenario.name
            );
        }
    }

    #[test]
    fn the_multi_chunk_scenario_spills_past_one_chunk() {
        let bytes = multi_chunk().batch().encode();

        assert!(
            bytes.len() > CHUNK_SIZE,
            "expected more than {CHUNK_SIZE} bytes, got {}",
            bytes.len()
        );
        // A partial last chunk is the case the contract's size check is there for, so the fixture
        // has to land off the boundary.
        assert_ne!(bytes.len() % CHUNK_SIZE, 0);
    }

    #[test]
    fn the_genesis_scenario_does_not_move_the_root() {
        let block = genesis_empty_batch();

        assert_eq!(block.old_root(), crate::GENESIS_ROOT);
        assert_eq!(block.new_root(), crate::GENESIS_ROOT);
        assert_eq!(block.old_deposit_chain(), crate::DEPOSIT_CHAIN_GENESIS);
        assert_eq!(block.new_deposit_chain(), crate::DEPOSIT_CHAIN_GENESIS);
    }

    // No scenario fabricates a balance any more, so none of them needs a contract put into position
    // first. This is the property that let `seedStateRoot` be deleted.
    #[test]
    fn every_scenario_starts_from_the_empty_ledger() {
        for scenario in all() {
            let block = (scenario.build)();

            assert_eq!(block.old_root(), crate::GENESIS_ROOT, "{}", scenario.name);
            assert_eq!(
                block.old_deposit_chain(),
                crate::DEPOSIT_CHAIN_GENESIS,
                "{}",
                scenario.name
            );
        }
    }

    // Two of the three deposits credit the same address for the same amount. If the fold were over
    // a set rather than a chain they would collapse into one, so this is the fixture that would
    // catch it.
    #[test]
    fn the_deposits_only_scenario_repeats_a_deposit() {
        let block = deposits_only();

        assert_ne!(block.new_deposit_chain(), block.old_deposit_chain());
        assert_eq!(
            block.batch().len(),
            3,
            "the repeated deposit must survive into the batch"
        );
    }

    // The end-to-end test for reordering replays this list backwards and expects the settlement to
    // fail. That only tests anything if the reversed list is a different list.
    #[test]
    fn the_deposits_only_scenario_is_not_a_palindrome() {
        let deposits: Vec<_> = deposits_only()
            .batch()
            .txns()
            .iter()
            .map(|txn| (txn.receiver(), txn.amount()))
            .collect();

        let mut reversed = deposits.clone();
        reversed.reverse();

        assert_ne!(deposits, reversed);
    }
}
