//! Blocks to settle, chosen for what they make the contract do rather than for what they do to the
//! ledger.
//!
//! Between them they cover what a settlement exercises: a batch that fits in one chunk, a batch
//! that does not, a batch of nothing but deposits, and the transition being nothing at all.
//!
//! Almost every account that spends here is authorized by [`Scheme::Managed`], which is the one
//! scheme with no key behind it: the replay checks that the presented key hashes to the account's
//! `auth_address` and has nothing else to check. That is deliberate rather than left over. These
//! blocks exist to drive the settlement contract, and the contract never sees a signature -- the
//! sidecar they live in stays with the prover -- so real keys would cost most of these fixtures a
//! nonce ledger of their own and buy the contract nothing. What signature verification *means* is
//! tested where it lives, in `payment-rollup`'s own suite.
//!
//! Two scenarios are exceptions, for two different reasons.
//!
//! The forced-exit fixtures use [`Scheme::Ed25519`] accounts because L1 *does* check a signature on
//! that path -- but they are funded by deposits and never spend, so nothing signs on this side. See
//! `EXIT_KEYS`.
//!
//! `every-scheme` is the one block whose spends carry signatures the replay has to check, one
//! account per scheme, holding real keys. It is here rather than in `payment-rollup` because what it
//! is for is the *cost* of those checks: it is the only fixture whose proof pays for an Ed25519
//! verification and a Falcon one, so it is the only one that says what a signature costs in the
//! guest. See [`Key`].
//!
//! Every scenario starts from the empty ledger. Value gets in the way it does in production, with a
//! deposit at the head of the block, so there is nothing here a contract has to be put into
//! position to accept.

use ed25519_dalek::{Signer, SigningKey};
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
        Scenario {
            name: "every-scheme",
            description: "One account per signing scheme -- managed, Ed25519, and the \
                          Falcon-1024/Ed25519 hybrid -- each funded by a deposit and each then \
                          signing a payment and a withdrawal. The only scenario whose spends carry \
                          signatures the replay has to check, so the only one whose proof pays for \
                          a curve verification and a lattice one.",
            build: every_scheme,
        },
    ]
}

/// Scenarios too expensive to run by accident.
///
/// Not in [`all`], so `--list`, a no-argument run and every unit test below that loops over `all`
/// never touch them -- the same reason `--prove` refuses an unnamed run, applied here to scenario
/// selection itself rather than to the network call. [`find`] still reaches them, so naming one
/// explicitly is all it takes.
fn heavy() -> &'static [Scenario] {
    &[Scenario {
        name: "falcon-hybrid-load",
        description: "Ten thousand Falcon-1024/Ed25519 hybrid payments, almost all of them \
                      between accounts that already exist: a small pool is funded once and then \
                      spends from and to itself in a round-robin, so the batch is dominated by \
                      warm accounts and repeat signers rather than one-off receivers. What the \
                      Falcon half of the hybrid scheme costs at a scale nothing else here \
                      reaches -- replaying it signs and verifies ten thousand lattice signatures, \
                      which is minutes rather than milliseconds, so unlike every scenario above it \
                      is reachable only by name.",
        build: falcon_hybrid_load,
    }]
}

pub fn find(name: &str) -> Option<&'static Scenario> {
    all()
        .iter()
        .chain(heavy())
        .find(|scenario| scenario.name == name)
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
/// which no made-up 32 bytes could satisfy. They are written out rather than derived because
/// nothing on this side ever signs with them: the accounts they stand for are funded by deposits,
/// which carry no signature, so all the rollup needs is the public key its address comes from.
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

/// The length of every seed below, which is the length Ed25519 fixes.
///
/// Falcon takes a seed of any length, so the two halves of a hybrid key can be -- and are -- grown
/// from the same 32 bytes.
const SEED_SIZE: usize = 32;

/// A key pair for one [`Scheme`], and the only thing in this file that can sign.
///
/// Every key is grown from a fixed seed, so two runs of the emitter produce byte-identical
/// fixtures. That holds for the Falcon half as well, whose key generation and signing are both
/// deterministic -- see the note on determinism in `falcon-det1024` -- so "the same key" here means
/// the same bytes rather than merely a key that works.
///
/// The seeds are written out in the calls below rather than hidden behind a counter for the reason
/// [`EXIT_KEYS`] is written out: a fixture that anybody may have to reproduce should say what it was
/// made from.
// A Falcon key pair is 4098 bytes and an enum is as large as its largest variant. Nothing here holds
// more than three of them.
#[allow(clippy::large_enum_variant)]
enum Key {
    /// No key at all, in the sense that matters: the bytes are what the address hashes, and nothing
    /// signs with them. Carried anyway so a managed account can be handled alongside the others.
    Managed(&'static [u8; SEED_SIZE]),
    Ed25519(SigningKey),
    /// Both halves, in the order [`Scheme::Falcon1024HybridEd25519`] concatenates them.
    Hybrid(SigningKey, falcon_det1024::SigningKey),
}

impl Key {
    fn managed(seed: &'static [u8; SEED_SIZE]) -> Self {
        Key::Managed(seed)
    }

    fn ed25519(seed: &[u8; SEED_SIZE]) -> Self {
        Key::Ed25519(SigningKey::from_bytes(seed))
    }

    fn hybrid(seed: &[u8; SEED_SIZE]) -> Self {
        Key::Hybrid(
            SigningKey::from_bytes(seed),
            falcon_det1024::SigningKey::from_seed(seed),
        )
    }

    fn scheme(&self) -> Scheme {
        match self {
            Key::Managed(_) => Scheme::Managed,
            Key::Ed25519(_) => Scheme::Ed25519,
            Key::Hybrid(..) => Scheme::Falcon1024HybridEd25519,
        }
    }

    /// The public key the account's address is derived from, in its scheme's layout.
    fn pub_key(&self) -> Vec<u8> {
        match self {
            Key::Managed(seed) => seed.to_vec(),
            Key::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
            Key::Hybrid(ed25519, falcon) => {
                let mut key = ed25519.verifying_key().to_bytes().to_vec();
                key.extend_from_slice(falcon.public_key());

                key
            }
        }
    }

    fn address(&self) -> Address {
        address_from_public_key(self.scheme(), &self.pub_key())
    }

    /// This key's signature over `message`, in the layout its scheme calls for.
    ///
    /// The hybrid's two halves sign the same bytes and are concatenated Ed25519-first, which is the
    /// order the verifier splits them at -- see `crypto::verify`. A managed key signs nothing at
    /// all, which is not a special case so much as the whole of what the scheme is.
    fn sign(&self, message: &[u8]) -> Signature {
        let sig = match self {
            Key::Managed(_) => Vec::new(),
            Key::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
            Key::Hybrid(ed25519, falcon) => {
                let mut sig = ed25519.sign(message).to_bytes().to_vec();
                sig.extend_from_slice(&falcon.sign_compressed(message));

                sig
            }
        };

        Signature::new(self.scheme(), self.pub_key(), sig)
    }
}

/// One key per scheme, in the order [`Scheme::identifier`] declares them.
///
/// A function rather than a constant because generating the Falcon half is real work, and no other
/// scenario should pay for it.
fn every_scheme_keys() -> [Key; 3] {
    [
        Key::managed(b"payment-rollup managed key!!!!!!"),
        Key::ed25519(b"payment-rollup ed25519 key!!!!!!"),
        Key::hybrid(b"payment-rollup hybrid key!!!!!!!"),
    ]
}

/// What each of the three accounts is deposited, paid, and withdraws.
///
/// The payments are a cycle -- each account pays the next, the last pays the first -- so every
/// account ends the payments holding exactly what it was deposited, and the withdrawal amounts can
/// be chosen freely. They are chosen distinct so no two payouts in the emitted queue are
/// interchangeable, the same reason the `withdrawals` scenario's are.
const EVERY_SCHEME_DEPOSIT: u64 = 2_000_000;
const EVERY_SCHEME_PAYMENT: u64 = 250_000;
const EVERY_SCHEME_WITHDRAWALS: [u64; 3] = [300_000, 400_000, 500_000];

/// A block in which all three schemes authorize a spend.
///
/// Each account is funded by a deposit, then signs a payment and a withdrawal -- both signing tags,
/// under every scheme, in one batch. The nonces are written out because a deposit does not advance
/// one and [`Ledger::debit`] advances before it checks: a fresh account's first spend signs nonce 1
/// and its second signs nonce 2. Getting either wrong is a panic out of the ledger rather than a
/// fixture that quietly proves nothing.
///
/// Both signing preimages commit to the deployment domain, so the signatures here are only valid
/// for the `domain` they were built with. That is not a caveat for the settlement contract, which
/// never sees them, but it does mean the sidecar of this scenario -- unlike every other -- cannot be
/// rebound to another deployment after the fact. Emit it for the domain it will be proved under.
fn every_scheme(domain: DeploymentDomain) -> Block {
    let keys = every_scheme_keys();
    let mut ledger = Ledger::with_domain(domain);

    let mut stxns: Vec<_> = keys
        .iter()
        .map(|key| SignedTransaction::deposit(Deposit::new(key.address(), EVERY_SCHEME_DEPOSIT)))
        .collect();

    for (index, key) in keys.iter().enumerate() {
        let receiver = keys[(index + 1) % keys.len()].address();
        let payment = Payment::new(key.address(), receiver, EVERY_SCHEME_PAYMENT);

        stxns.push(SignedTransaction::payment(
            payment,
            key.sign(&payment.bytes_to_sign(&domain, 1)),
        ));
    }

    for (index, key) in keys.iter().enumerate() {
        let withdrawal = Withdrawal::new(
            key.address(),
            l1_account(11 + index as u8),
            EVERY_SCHEME_WITHDRAWALS[index],
        );

        stxns.push(SignedTransaction::withdrawal(
            withdrawal,
            key.sign(&withdrawal.bytes_to_sign(&domain, 2)),
        ));
    }

    ledger.get_block(stxns)
}

/// How many hybrid accounts [`falcon_hybrid_load`] keeps warm.
///
/// Small enough that every account spends many times over the course of the scenario, which is
/// the whole point: [`FALCON_LOAD_PAYMENTS`] payments among this many accounts means each one
/// signs `FALCON_LOAD_PAYMENTS / FALCON_LOAD_ACCOUNTS` times, so the batch exercises a hybrid
/// signature over a warm, high-nonce account far more often than it exercises one over a fresh
/// one.
const FALCON_LOAD_ACCOUNTS: usize = 25;

/// How many signed payments the scenario carries -- and so how many Falcon verifications a
/// replay pays for.
const FALCON_LOAD_PAYMENTS: u32 = 10_000;

/// What each load account is deposited, chosen so that the most any one account could ever pay
/// out -- `FALCON_LOAD_PAYMENTS / FALCON_LOAD_ACCOUNTS * FALCON_LOAD_AMOUNT` -- is comfortably
/// below it regardless of the order transfers land in, the same reasoning [`round_trip`] relies
/// on for one payment instead of hundreds.
const FALCON_LOAD_DEPOSIT: u64 = 1_000_000;
const FALCON_LOAD_AMOUNT: u64 = 1_000;

/// One payment in this many is redirected to a brand-new address instead of another load account.
///
/// The scenario is for the cost of a hybrid signature at scale, not for account creation, so new
/// accounts are the exception here rather than the rule `multi_chunk` follows -- but a handful
/// keep the scenario from claiming to be "mostly existing accounts" while secretly being
/// "entirely existing accounts", which is a different fixture.
const FALCON_LOAD_NEW_ACCOUNT_STRIDE: u32 = 500;

/// The seed for load account `index`, distinct only in its last byte.
///
/// One byte is all [`FALCON_LOAD_ACCOUNTS`] needs, and unlike [`EXIT_KEYS`] or the seeds in
/// [`every_scheme_keys`] nothing outside this file ever has to reproduce one of these keys on its
/// own, so there is no reason to write two dozen of them out by hand.
fn falcon_load_seed(index: usize) -> [u8; SEED_SIZE] {
    let mut seed = *b"payment-rollup falcon load key!!";
    seed[SEED_SIZE - 1] = u8::try_from(index).expect("FALCON_LOAD_ACCOUNTS fits in a byte");

    seed
}

fn falcon_load_keys() -> Vec<Key> {
    (0..FALCON_LOAD_ACCOUNTS)
        .map(|index| Key::hybrid(&falcon_load_seed(index)))
        .collect()
}

/// Ten thousand Falcon-hybrid payments, almost all of them between accounts that already exist.
///
/// The load accounts are funded once at the head of the block, then pay each other in a
/// round-robin -- account `n` to account `n + 1` -- for [`FALCON_LOAD_PAYMENTS`] payments, so
/// every payment but the rare redirected one both spends from and credits an account the scenario
/// already created. See [`heavy`] for why this is not in [`all`].
fn falcon_hybrid_load(domain: DeploymentDomain) -> Block {
    let keys = falcon_load_keys();
    let mut ledger = Ledger::with_domain(domain);
    let mut nonces = vec![0u64; keys.len()];

    let mut stxns: Vec<_> = keys
        .iter()
        .map(|key| SignedTransaction::deposit(Deposit::new(key.address(), FALCON_LOAD_DEPOSIT)))
        .collect();

    for index in 0..FALCON_LOAD_PAYMENTS {
        let sender_index = index as usize % keys.len();
        let key = &keys[sender_index];

        let receiver = if (index + 1) % FALCON_LOAD_NEW_ACCOUNT_STRIDE == 0 {
            address_of(&index.to_be_bytes())
        } else {
            keys[(sender_index + 1) % keys.len()].address()
        };

        let payment = Payment::new(key.address(), receiver, FALCON_LOAD_AMOUNT);
        nonces[sender_index] += 1;

        stxns.push(SignedTransaction::payment(
            payment,
            key.sign(&payment.bytes_to_sign(&domain, nonces[sender_index])),
        ));
    }

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

    // The e2e drains this chain one payout at a time and asserts each lands where it was addressed.
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

        // Identical payouts, so the two links differ only in their tails -- which is exactly what
        // keeps them distinct positions in the chain rather than one payout the contract could make
        // twice.
        let links = settled.withdrawal_links();
        assert_eq!(links[0].recipient, links[1].recipient);
        assert_eq!(links[0].amount, links[1].amount);
        assert_ne!(links[0].tail, links[1].tail);
    }

    // The one bound the guest enforces on a withdrawal, and the reason the settlement contract can
    // pay one out without worrying whether the payment will go through -- and so the reason a drain
    // cannot stall halfway with the next batch waiting on it.
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

    // Every block folds its withdrawals onto the terminal, so a block with none has to land exactly
    // there -- that is how the contract knows there is nothing to pay out.
    #[test]
    fn only_the_withdrawing_scenarios_move_off_the_withdrawal_terminal() {
        let terminal = payment_rollup::withdrawal_chain_terminal(&DOMAIN);

        for scenario in all() {
            let settled = Settlement::for_block(&(scenario.build)(DOMAIN)).unwrap();
            let moved = settled.withdrawal_chain() != terminal;

            assert_eq!(
                moved,
                !settled.withdrawals().is_empty(),
                "{}: the withdrawal chain leaves the terminal iff the batch withdrew something",
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

    // Every scheme, spending. Two transactions per account -- the payment and the withdrawal -- so
    // both signing tags are covered under all three, and `every_scenario_is_a_block_that_verifies`
    // above is what says the signatures over them check out.
    #[test]
    fn the_every_scheme_scenario_spends_under_every_scheme() {
        let block = every_scheme(DOMAIN);
        let senders: Vec<_> = block
            .batch()
            .txns()
            .iter()
            .map(|txn| txn.sender())
            .collect();

        let mut schemes = Vec::new();
        for key in &every_scheme_keys() {
            assert_eq!(
                senders.iter().filter(|s| **s == key.address()).count(),
                2,
                "{:?} does not spend exactly twice",
                key.scheme()
            );
            schemes.push(key.scheme());
        }

        assert_eq!(
            schemes,
            vec![
                Scheme::Managed,
                Scheme::Ed25519,
                Scheme::Falcon1024HybridEd25519
            ],
            "a scheme was added or dropped without the scenario following"
        );
    }

    // The claim the scenario exists for: the sidecar the prover reads names all three schemes, so
    // replaying it is what costs a curve verification and a lattice one.
    #[test]
    fn the_every_scheme_sidecar_names_every_scheme() {
        let sidecar = every_scheme(DOMAIN).sidecar().encode();

        for key in &every_scheme_keys() {
            let identifier = key.scheme().identifier();

            assert!(
                sidecar.windows(identifier.len()).any(|w| w == identifier),
                "{:?} does not appear in the sidecar",
                key.scheme()
            );
        }
    }

    // What makes the fixture's signatures load-bearing rather than decorative. The ledger checks
    // every signature as it builds the block -- see `Ledger::debit` -- so a hybrid signature over
    // the wrong nonce cannot be built into one at all. If this stopped panicking, the scenario would
    // have stopped proving anything about Falcon.
    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn an_every_scheme_signature_over_the_wrong_nonce_is_refused() {
        let key = Key::hybrid(b"payment-rollup hybrid key!!!!!!!");
        let mut ledger = Ledger::with_domain(DOMAIN);
        let payment = Payment::new(key.address(), address_of(b"a key"), EVERY_SCHEME_PAYMENT);

        ledger.get_block(vec![
            SignedTransaction::deposit(Deposit::new(key.address(), EVERY_SCHEME_DEPOSIT)),
            // Nonce 2, where a fresh account's first spend is at 1.
            SignedTransaction::payment(payment, key.sign(&payment.bytes_to_sign(&DOMAIN, 2))),
        ]);
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

    // The guard `heavy` exists for: reachable by name, but not something an unnamed run or a loop
    // over `all` stumbles into.
    #[test]
    fn a_heavy_scenario_is_reachable_by_name_but_absent_from_all() {
        assert!(
            all()
                .iter()
                .all(|scenario| scenario.name != "falcon-hybrid-load")
        );
        assert!(find("falcon-hybrid-load").is_some());
    }

    // The one thing worth the minutes this costs to check: ten thousand hybrid signatures verify,
    // and the scenario keeps the shape its name promises -- spends confined to the load accounts,
    // and only the rare redirected payment reaching outside them.
    #[test]
    #[ignore = "signs and verifies 10,000 Falcon-hybrid signatures -- minutes, not milliseconds; \
                run explicitly with `cargo test -p sp1-host falcon_hybrid_load -- --ignored`"]
    fn the_falcon_hybrid_load_scenario_verifies_and_stays_mostly_existing() {
        let block = falcon_hybrid_load(DOMAIN);
        assert_eq!(verify_block(&block), Ok(()));

        let addresses: Vec<_> = falcon_load_keys().iter().map(Key::address).collect();
        let txns = block.batch().txns();

        let senders: Vec<_> = txns.iter().map(|txn| txn.sender()).collect();
        assert_eq!(
            senders.len(),
            FALCON_LOAD_ACCOUNTS + FALCON_LOAD_PAYMENTS as usize
        );
        for sender in &senders[FALCON_LOAD_ACCOUNTS..] {
            assert!(
                addresses.contains(sender),
                "a payment was signed by something other than a load account"
            );
        }

        // Almost all of it: only the redirected payments -- one in
        // `FALCON_LOAD_NEW_ACCOUNT_STRIDE` -- ever credit an address outside the load accounts.
        let receivers: Vec<_> = txns
            .iter()
            .skip(FALCON_LOAD_ACCOUNTS)
            .filter_map(|txn| txn.receiver())
            .collect();
        let existing = receivers.iter().filter(|r| addresses.contains(r)).count();
        assert_eq!(receivers.len(), FALCON_LOAD_PAYMENTS as usize);
        assert!(
            existing * 100 >= receivers.len() * 99,
            "fewer than 99% of receivers were existing load accounts"
        );
    }
}
