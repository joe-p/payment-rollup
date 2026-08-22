//! Blocks to settle, chosen for what they make the contract do rather than for what they do to the
//! ledger.
//!
//! Between them they cover the three things a settlement exercises: a batch that fits in one chunk,
//! a batch that does not, and the transition being nothing at all. Every account here is authorized
//! by [`Scheme::Managed`], because signature verification is still a `TODO` in the replay -- a
//! scenario carries an empty signature and the replay checks only that its address matches the
//! account's `auth_address`.

use payment_rollup::{
    Account, Address, Block, Ledger, Payment, Scheme, Signature, SignedTransaction, Transaction,
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
            description: "An empty batch replayed from the empty ledger. The only block a freshly \
                          deployed contract can settle today: it starts and ends at the genesis \
                          root, so it drives openBatch, one accumulateChunk and verifyBatch \
                          without needing the ledger to be funded first.",
            build: genesis_empty_batch,
        },
        Scenario {
            name: "payments",
            description: "Three payments from a funded genesis: a plain one, one that brings a new \
                          account into existence, and a self-payment. One chunk. The first fixture \
                          that actually moves the state root -- seed the contract to its oldRoot \
                          first, since nothing can prove a route to a funded ledger yet.",
            build: payments,
        },
        Scenario {
            name: "multi-chunk",
            description: "Payments to enough distinct receivers that the batch spans several \
                          chunks, so the accumulator is folded more than once and the last chunk is \
                          a partial one. Also starts from a funded genesis, so it needs the same \
                          seeding.",
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

/// Put `amount` into the account for `key`, outside any block.
///
/// This is the fabricated part of every funded scenario. There is no deposit transaction yet, so a
/// balance can only be written straight into the genesis ledger -- which is also why these
/// scenarios do not start from [`crate::GENESIS_ROOT`].
fn fund(ledger: &mut Ledger, key: &[u8], amount: u64) -> Address {
    let address = address_of(key);
    ledger.insert_account(address, Account::new(0, amount, address));

    address
}

/// A payment of `amount` from the account for `key` to `receiver`, signed by `key`.
///
/// No nonce: the sequencer assigns each sender its next one in the order the block lists them.
fn pay(key: &[u8], receiver: Address, amount: u64) -> SignedTransaction {
    SignedTransaction::new(
        Transaction::Payment(Payment::new(address_of(key), receiver, amount)),
        Signature::new(SCHEME, key.to_vec(), Vec::new()),
    )
}

fn genesis_empty_batch() -> Block {
    Ledger::new().get_block(Vec::new())
}

fn payments() -> Block {
    let mut ledger = Ledger::new();
    let a = fund(&mut ledger, b"a key", 1_000);
    let b = fund(&mut ledger, b"b key", 500);
    let fresh = address_of(b"fresh key");

    ledger.get_block(vec![
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
    fund(&mut ledger, b"spender", PAYMENTS as u64 * AMOUNT);

    ledger.get_block(
        (0..PAYMENTS)
            .map(|index| pay(b"spender", address_of(&index.to_be_bytes()), AMOUNT))
            .collect(),
    )
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
    }
}
