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

use payment_rollup::ForcedWithdrawal;
use payment_rollup::{
    Address, Block, DeploymentDomain, Deposit, L1Address, Ledger, MIN_WITHDRAWAL, Payment, Scheme,
    Signature, SignedTransaction, Slot, Withdrawal, address_from_public_key,
};

const SCHEME: Scheme = Scheme::Managed;

/// A named block, built on demand so nothing is computed for scenarios that were not asked for.
pub struct Scenario {
    pub name: &'static str,
    /// What this scenario is for, carried through to the emitted JSON so a failing test says
    /// something about the case it was covering.
    pub description: &'static str,
    pub build: fn(DeploymentDomain) -> Block,
}

pub fn all() -> &'static [Scenario] {
    &[
        Scenario {
            name: "genesis-empty-batch",
            description: "An empty batch replayed from the empty ledger. It starts and ends at the \
                          genesis root and carries no deposits, so it drives openBatch, one \
                          accumulateChunk and verifyBatch while leaving both the state root and the \
                          inbox chain where they were.",
            build: genesis_empty_batch,
        },
        Scenario {
            name: "deposits-only",
            description: "Nothing but deposits, from the empty ledger. The cleanest test of the \
                          inbox deposit fold: with no payments in the way, a mismatch between what the \
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
        Scenario {
            name: "withdrawals",
            description: "A deposit and then three withdrawals to distinct L1 accounts. The \
                          cleanest test of the ordered withdrawal Merkle tree: each payout has a \
                          distinct index and inclusion path under the root the proof commits.",
            build: withdrawals,
        },
        Scenario {
            name: "duplicate-withdrawals",
            description: "Two identical payouts at distinct transaction indices. Their indexed \
                          leaves and claim bits must keep both withdrawals independently payable.",
            build: duplicate_withdrawals,
        },
        Scenario {
            name: "forced-exit",
            description: "Two deposits to Ed25519 accounts, so the settled tree holds two leaves \
                          and each proves against the root through one sibling. Built for the \
                          contract's forceExit, which is the only path that reads the state root as \
                          data rather than advancing it.",
            build: forced_exit,
        },
        Scenario {
            name: "forced-inclusion",
            description: "Two deposits to Ed25519 accounts and then a withdrawal L1 ordered on \
                          behalf of one of them, emptying it. The batch that answers the request \
                          is the only batch that can settle, which is what makes withdrawal \
                          censorship indistinguishable from halting.",
            build: forced_inclusion,
        },
        Scenario {
            name: "inbox-ordering",
            description: "A deposit, forced withdrawal, and another deposit in one batch. The \
                          ordered inbox requires L1 to call deposit, requestWithdrawal, deposit \
                          exactly in that cross-kind order.",
            build: inbox_ordering,
        },
        Scenario {
            name: "round-trip",
            description: "Value deposited, moved by payment, and withdrawn again in one batch. \
                          Covers the inbox and withdrawal commitments moving together and a withdrawal \
                          spending what a payment delivered earlier in that same block.",
            build: round_trip,
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

/// A withdrawal of `amount` from the account for `key` to the L1 account `recipient`.
///
/// `recipient` is an [`L1Address`] -- the raw 32 bytes of an Algorand account, not a rollup
/// address. The e2e supplies real LocalNet accounts here; these fixtures only need the bytes to be
/// distinct and stable.
fn withdraw(key: &[u8], recipient: L1Address, amount: u64) -> SignedTransaction {
    SignedTransaction::withdrawal(
        Withdrawal::new(address_of(key), recipient, amount),
        Signature::new(SCHEME, key.to_vec(), Vec::new()),
    )
}

/// A stand-in L1 account, distinguishable by its first byte.
///
/// Deliberately not derived from any rollup key: the whole point of an [`L1Address`] is that it
/// lives in the other namespace, and a fixture that derived one the way it derives rollup addresses
/// would quietly suggest otherwise.
fn l1_account(index: u8) -> L1Address {
    let mut address = [0u8; 32];
    address[0] = index;
    address[31] = 0xff;

    address
}

fn genesis_empty_batch(domain: DeploymentDomain) -> Block {
    Ledger::with_domain(domain).get_block(Vec::new())
}

/// Three deposits, the first two identical, so the fixture covers a fresh dictionary entry and a
/// warm one -- and, more to the point, two deposits a set commitment would collapse into one.
///
/// Deliberately not a palindrome. A reversed copy of this list has to be a different list, or the
/// end-to-end test for reordering would be asserting against the sequence it started with.
fn deposits_only(domain: DeploymentDomain) -> Block {
    Ledger::with_domain(domain).get_block(vec![
        deposit(b"a key", 1_000),
        deposit(b"a key", 1_000),
        deposit(b"b key", 500),
    ])
}

fn payments(domain: DeploymentDomain) -> Block {
    let mut ledger = Ledger::with_domain(domain);
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

/// A deposit and three withdrawals, to three distinct L1 accounts for three distinct amounts.
///
/// Distinct on both counts on purpose: the e2e claims this queue and checks each
/// payout lands where it should, which only tests anything if no two claims are interchangeable.
/// Every amount is at or above `MIN_WITHDRAWAL`, because a block containing one below it does not
/// verify at all.
fn withdrawals(domain: DeploymentDomain) -> Block {
    let mut ledger = Ledger::with_domain(domain);

    ledger.get_block(vec![
        deposit(b"a key", 1_000_000),
        withdraw(b"a key", l1_account(1), MIN_WITHDRAWAL),
        withdraw(b"a key", l1_account(2), 250_000),
        withdraw(b"a key", l1_account(3), 300_000),
    ])
}

fn duplicate_withdrawals(domain: DeploymentDomain) -> Block {
    let mut ledger = Ledger::with_domain(domain);

    ledger.get_block(vec![
        deposit(b"a key", 500_000),
        withdraw(b"a key", l1_account(6), MIN_WITHDRAWAL),
        withdraw(b"a key", l1_account(6), MIN_WITHDRAWAL),
    ])
}

/// Value in, value across, value out -- in one batch.
///
/// The withdrawal spends from `b key`, which holds nothing until the payment two lines above
/// delivers it. That is the interleaving that matters: the inbox chain and withdrawal commitment
/// both move, and the withdrawal is only affordable because the replay applies the transactions in
/// order against a running root.
fn round_trip(domain: DeploymentDomain) -> Block {
    let mut ledger = Ledger::with_domain(domain);
    let b = address_of(b"b key");

    ledger.get_block(vec![
        deposit(b"a key", 1_000_000),
        pay(b"a key", b, 400_000),
        withdraw(b"b key", l1_account(4), 250_000),
        withdraw(b"a key", l1_account(5), 100_000),
    ])
}

/// Ed25519 public keys the forced-exit fixtures are built around, and the one place they are
/// written down on this side.
///
/// Real keys, derived from the fixed seeds `"payment-rollup exit key one!!!!!"` and
/// `"payment-rollup exit key two!!!!!"`. They have to be real because the contract runs
/// `ed25519verify_bare` against a signature the end-to-end test produces from the matching secret,
/// which no made-up 32 bytes could satisfy. They are written out rather than derived because this
/// crate has no Ed25519 implementation -- the replay still checks only that a key hashes to an
/// account's `auth_address`, so it has never needed one.
///
/// The seeds are the contract between the two sides. The end-to-end test re-derives these public
/// keys from them and asserts they match what the fixture carries, so the two cannot drift apart in
/// silence.
const EXIT_KEYS: [[u8; 32]; 2] = [
    [
        0xa0, 0xff, 0xaa, 0x0d, 0xde, 0x9d, 0xca, 0x42, 0x9e, 0x71, 0x60, 0x7d, 0x0b, 0x61, 0xc2,
        0xc7, 0x1e, 0x7a, 0xbd, 0xfe, 0xed, 0x45, 0xfa, 0x1d, 0x65, 0x44, 0x88, 0x35, 0xf6, 0x36,
        0x4d, 0xf2,
    ],
    [
        0xe1, 0xfd, 0xcf, 0x39, 0xa3, 0x35, 0xb2, 0xed, 0xfb, 0x3f, 0x5c, 0x1e, 0x91, 0xec, 0xc4,
        0x14, 0xc6, 0xdf, 0x2a, 0x54, 0xf3, 0xfc, 0xc7, 0x51, 0x4c, 0xc1, 0x13, 0x74, 0x18, 0xd2,
        0xce, 0x50,
    ],
];

/// What the forced-exit fixtures pay each account. Distinct, so a test cannot pass by exiting the
/// wrong leaf, and comfortably above `EXIT_BOX_MBR` in the contract.
const EXIT_AMOUNTS: [u64; 2] = [5_000_000, 3_000_000];

/// One account as `forceExit` needs to see it: the leaf, and the path from it to the root.
///
/// Everything here is public -- it is all recoverable from the batch bytes on L1 by anyone who
/// replays them. The fixture carries it so the end-to-end test does not have to reimplement the
/// tree in TypeScript to find out what to send.
#[derive(Clone, Debug)]
pub struct ExitProof {
    pub address: Address,
    pub pub_key: [u8; 32],
    pub nonce: u64,
    pub amount: u64,
    pub auth_address: Address,
    /// `32 * depth` bytes, root-first, exactly as `forceExit` reads them.
    pub siblings: Vec<[u8; 32]>,
}

/// Two Ed25519-derived accounts, funded the only way a state can be reached from genesis.
///
/// A deposit pins a created account to `Account::empty`, so each one ends up authorized by the very
/// key its address was derived from -- which is what makes the deposit recipient and the exit
/// signer the same party without anything having to say so.
fn forced_exit(domain: DeploymentDomain) -> Block {
    forced_exit_ledger(domain).0
}

/// The same block, with the ledger that produced it, so the proofs can be read off the settled tree.
///
/// Everything here is deterministic, so rebuilding the block rebuilds the identical tree. That is
/// what lets `build` stay a plain `fn() -> Block` for every scenario instead of growing a second
/// shape for the one that needs more.
fn forced_exit_ledger(domain: DeploymentDomain) -> (Block, Ledger) {
    let mut ledger = Ledger::with_domain(domain);

    let block = ledger.get_block(
        EXIT_KEYS
            .iter()
            .zip(EXIT_AMOUNTS)
            .map(|(key, amount)| {
                SignedTransaction::deposit(Deposit::new(
                    address_from_public_key(Scheme::Ed25519, key),
                    amount,
                ))
            })
            .collect(),
    );

    (block, ledger)
}

/// The forced-exit ledger, plus a withdrawal L1 ordered against the first of its two accounts.
///
/// Reuses the exit keys because the L1 side of a request has to check a signature by the key the
/// account was derived from, and these are the only real Ed25519 keys the fixtures have. The second
/// account is left alone so the e2e can tell an emptied account from an untouched one.
fn forced_inclusion(domain: DeploymentDomain) -> Block {
    let mut ledger = Ledger::with_domain(domain);

    let mut stxns: Vec<_> = EXIT_KEYS
        .iter()
        .zip(EXIT_AMOUNTS)
        .map(|(key, amount)| {
            SignedTransaction::deposit(Deposit::new(
                address_from_public_key(Scheme::Ed25519, key),
                amount,
            ))
        })
        .collect();

    stxns.push(SignedTransaction::forced_withdrawal(ForcedWithdrawal::new(
        address_from_public_key(Scheme::Ed25519, &EXIT_KEYS[0]),
        l1_account(9),
    )));

    ledger.get_block(stxns)
}

fn inbox_ordering(domain: DeploymentDomain) -> Block {
    let mut ledger = Ledger::with_domain(domain);
    let address = address_from_public_key(Scheme::Ed25519, &EXIT_KEYS[0]);

    ledger.get_block(vec![
        SignedTransaction::deposit(Deposit::new(address, 1_000_000)),
        SignedTransaction::forced_withdrawal(ForcedWithdrawal::new(address, l1_account(10))),
        SignedTransaction::deposit(Deposit::new(address, 500_000)),
    ])
}

/// Proofs for every account the forced-exit scenario leaves in the tree.
///
/// Only inclusion proofs are emitted, and the assertion below is the reason: `forceExit` accepts
/// nothing else. An account that exists always proves through its own position, so a `Slot` of any
/// other shape here would mean the tree had stopped holding what the scenario put in it.
pub fn forced_exit_proofs(domain: DeploymentDomain) -> Vec<ExitProof> {
    let (_, ledger) = forced_exit_ledger(domain);

    EXIT_KEYS
        .iter()
        .map(|pub_key| {
            let address = address_from_public_key(Scheme::Ed25519, pub_key);
            let account = ledger
                .account(&address)
                .expect("the scenario deposits to this address");
            let proof = ledger.proof(&address);

            assert!(
                matches!(proof.slot(), Slot::Own),
                "forceExit only accepts an inclusion proof",
            );

            ExitProof {
                address,
                pub_key: *pub_key,
                nonce: account.nonce(),
                amount: account.amount(),
                auth_address: account.auth_address(),
                siblings: proof.siblings().to_vec(),
            }
        })
        .collect()
}

/// One payment per receiver, at the ~38 bytes a payment costs when the sender repeats and the
/// receiver is new, which puts the batch a few chunks over the boundary.
fn multi_chunk(domain: DeploymentDomain) -> Block {
    const PAYMENTS: u32 = 300;
    const AMOUNT: u64 = 1_000_000;

    let mut ledger = Ledger::with_domain(domain);

    let mut stxns = vec![deposit(b"spender", PAYMENTS as u64 * AMOUNT)];
    stxns.extend(
        (0..PAYMENTS).map(|index| pay(b"spender", address_of(&index.to_be_bytes()), AMOUNT)),
    );

    ledger.get_block(stxns)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Settlement;
    use payment_rollup::{CHUNK_SIZE, verify_block};

    const DOMAIN: DeploymentDomain = [0x42; 32];

    #[test]
    fn every_scenario_is_a_block_that_verifies() {
        for scenario in all() {
            assert_eq!(
                verify_block(&(scenario.build)(DOMAIN)),
                Ok(()),
                "{}",
                scenario.name
            );
        }
    }

    #[test]
    fn the_multi_chunk_scenario_spills_past_one_chunk() {
        let bytes = multi_chunk(DOMAIN).batch().encode();

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
        let block = genesis_empty_batch(DOMAIN);

        assert_eq!(block.old_root(), crate::GENESIS_ROOT);
        assert_eq!(block.new_root(), crate::GENESIS_ROOT);
        assert_eq!(block.old_inbox_chain(), crate::INBOX_CHAIN_GENESIS);
        assert_eq!(block.new_inbox_chain(), crate::INBOX_CHAIN_GENESIS);
    }

    // No scenario fabricates a balance any more, so none of them needs a contract put into position
    // first. This is the property that let `seedStateRoot` be deleted.
    #[test]
    fn every_scenario_starts_from_the_empty_ledger() {
        for scenario in all() {
            let block = (scenario.build)(DOMAIN);

            assert_eq!(block.old_root(), crate::GENESIS_ROOT, "{}", scenario.name);
            assert_eq!(
                block.old_inbox_chain(),
                crate::INBOX_CHAIN_GENESIS,
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
        let block = deposits_only(DOMAIN);

        assert_ne!(block.new_inbox_chain(), block.old_inbox_chain());
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
        let deposits: Vec<_> = deposits_only(DOMAIN)
            .batch()
            .txns()
            .iter()
            .map(|txn| (txn.receiver(), txn.amount()))
            .collect();

        let mut reversed = deposits.clone();
        reversed.reverse();

        assert_ne!(deposits, reversed);
    }

    #[test]
    fn the_inbox_ordering_scenario_interleaves_kinds() {
        let settlement = Settlement::for_block(&inbox_ordering(DOMAIN)).unwrap();

        assert!(matches!(
            settlement.inbox()[0],
            crate::InboxItem::Deposit { .. }
        ));
        assert!(matches!(
            settlement.inbox()[1],
            crate::InboxItem::ForcedWithdrawal { .. }
        ));
        assert!(matches!(
            settlement.inbox()[2],
            crate::InboxItem::Deposit { .. }
        ));
    }

    // The e2e claims this queue one payout at a time and asserts each lands where it was addressed.
    #[test]
    fn the_withdrawals_scenario_has_no_two_alike() {
        let settled = Settlement::for_block(&withdrawals(DOMAIN)).unwrap();
        let payouts = settled.withdrawals();

        assert_eq!(payouts.len(), 3);
        for (index, left) in payouts.iter().enumerate() {
            for right in &payouts[index + 1..] {
                assert_ne!(left.0, right.0, "two withdrawals share an L1 recipient");
                assert_ne!(left.1, right.1, "two withdrawals share an amount");
            }
        }
    }

    #[test]
    fn the_duplicate_withdrawals_scenario_keeps_both_payouts() {
        let settled = Settlement::for_block(&duplicate_withdrawals(DOMAIN)).unwrap();

        assert_eq!(settled.withdrawals().len(), 2);
        assert_eq!(settled.withdrawals()[0], settled.withdrawals()[1]);
        assert_ne!(
            settled.withdrawal_claims()[0].index,
            settled.withdrawal_claims()[1].index
        );
    }

    // The one bound the guest enforces on a withdrawal, and the reason the settlement contract can
    // pay a claim out without worrying whether the payment will go through.
    #[test]
    fn no_scenario_withdraws_below_the_minimum() {
        for scenario in all() {
            let settled = Settlement::for_block(&(scenario.build)(DOMAIN)).unwrap();

            for (recipient, amount) in settled.withdrawals() {
                assert!(
                    *amount >= MIN_WITHDRAWAL,
                    "{}: withdrawal of {amount} to {recipient:?} is below the minimum",
                    scenario.name
                );
            }
        }
    }

    // Every block folds its withdrawals from genesis, so a block with none has to land exactly
    // there -- that is how the contract knows not to open a payout queue.
    #[test]
    fn only_the_withdrawing_scenarios_have_a_withdrawal_root() {
        for scenario in all() {
            let settled = Settlement::for_block(&(scenario.build)(DOMAIN)).unwrap();
            let moved = settled.withdrawal_root() != payment_rollup::EMPTY_WITHDRAWAL_ROOT;

            assert_eq!(
                moved,
                !settled.withdrawals().is_empty(),
                "{}: the withdrawal root is nonzero iff the batch withdrew something",
                scenario.name
            );
        }
    }

    // The proofs the fixture hands the contract have to check out against the very root that
    // settling the scenario leaves in `stateRoot`. If they did not, a `forceExit` failure in the
    // end-to-end test would be ambiguous between a broken AVM verifier and a broken fixture.
    #[test]
    fn every_forced_exit_proof_verifies_against_the_settled_root() {
        let root = forced_exit(DOMAIN).new_root();

        for exit in forced_exit_proofs(DOMAIN) {
            let account = payment_rollup::Account::new(exit.nonce, exit.amount, exit.auth_address);
            let proof = payment_rollup::MerkleProof::from_parts(exit.siblings.clone(), Slot::Own);

            assert!(
                payment_rollup::verify_proof(&root, &exit.address, Some(&account), &proof),
                "the proof for {:?} does not reach the settled root",
                exit.address
            );
        }
    }

    // A deposit pins a created account to `Account::empty`, so its `auth_address` is its own
    // address -- which is what makes the depositor and the only party who can force-exit the same
    // person, and what the contract's `sha256("ADDR" || scheme || pubKey)` check relies on.
    #[test]
    fn a_forced_exit_account_is_authorized_by_the_key_it_was_derived_from() {
        for exit in forced_exit_proofs(DOMAIN) {
            assert_eq!(
                exit.auth_address,
                address_from_public_key(Scheme::Ed25519, &exit.pub_key)
            );
            assert_eq!(exit.auth_address, exit.address);
            assert_eq!(exit.nonce, 0);
        }
    }

    // Two leaves in the tree means each proves through at least one sibling, so the end-to-end test
    // exercises the fold rather than the degenerate case where the root *is* the leaf.
    #[test]
    fn the_forced_exit_proofs_are_not_degenerate() {
        let proofs = forced_exit_proofs(DOMAIN);

        assert_eq!(proofs.len(), 2);
        for exit in &proofs {
            assert!(
                !exit.siblings.is_empty(),
                "a depth-zero proof would not exercise the contract's fold at all"
            );
        }
        assert_ne!(proofs[0].amount, proofs[1].amount);
        assert_ne!(proofs[0].address, proofs[1].address);
    }

    // The round-trip scenario's third transaction spends from an account that held nothing when the
    // block opened. If the replay did not apply transactions in order against a running root, it
    // could not be afforded at all.
    #[test]
    fn the_round_trip_scenario_withdraws_what_a_payment_just_delivered() {
        let block = round_trip(DOMAIN);
        let b = address_of(b"b key");

        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(block.batch().txns()[2].sender(), b);
        assert_eq!(block.old_root(), crate::GENESIS_ROOT);
    }
}
