use std::collections::HashMap;
use std::fmt;

use sha2::{Digest, Sha256};

mod codec;
mod merkle;

pub use codec::DecodeError;
pub use merkle::{MerkleProof, Slot, SparseMerkleTree, verify_proof};

pub type Address = [u8; 32];

/// The sender of a [`Deposit`]: the one address no key can produce.
///
/// Every real address is `sha256("ADDR" || scheme || pub_key)` (see [`address_from_public_key`]),
/// so standing here means finding a SHA-256 preimage for thirty-two zero bytes. Nothing can spend
/// from it and no user account can ever collide with it, which is what makes it safe to use as a
/// marker for "this value came from outside the rollup".
///
/// It is only ever a marker. [`verify_batch`] never reads or writes an account here, so the address
/// never enters the tree at all.
///
/// Numerically equal to `merkle::EMPTY_SUBTREE`, and unrelated to it: that is a hash in the tree's
/// namespace, this is an address. Do not unify the two constants.
pub const ZERO_ADDRESS: Address = [0u8; 32];

const SCHEME_SIZE: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Signing authority for this account is granted via crypto signatures
    /// Instead, it is directly managed by the sequencer
    Managed,
    Ed25519,
    Falcon1024HybridEd25519,
}

impl Scheme {
    /// Every scheme, so a decoder can recover one from its identifier without a second mapping to
    /// keep in step with [`Scheme::identifier`].
    const ALL: [Scheme; 3] = [
        Scheme::Managed,
        Scheme::Ed25519,
        Scheme::Falcon1024HybridEd25519,
    ];

    pub fn identifier(&self) -> [u8; SCHEME_SIZE] {
        match self {
            Scheme::Managed => *b"man",
            Scheme::Ed25519 => *b"edd",
            Scheme::Falcon1024HybridEd25519 => *b"f1h",
        }
    }

    pub fn from_identifier(identifier: &[u8; SCHEME_SIZE]) -> Option<Scheme> {
        Scheme::ALL
            .into_iter()
            .find(|scheme| scheme.identifier() == *identifier)
    }
}

/// The address controlled by `pub_key` under `scheme`.
///
/// The scheme identifier is committed to, so the same key bytes under two schemes give two
/// different addresses.
pub fn address_from_public_key(scheme: Scheme, pub_key: &[u8]) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(b"ADDR");
    hasher.update(scheme.identifier());
    hasher.update(pub_key);

    hasher.finalize().into()
}

const ENCODED_TX_SIZE: usize = 32 + 8 + 32 + 8;

pub(crate) const ENCODED_ACCOUNT_SIZE: usize = 8 + 8 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidAuthAddress,
    /// An account's nonce cannot be advanced any further.
    InvalidNonce,
    /// A transaction spends from an address the witness proves holds no account.
    UnknownSender,
    InsufficientFunds,
    AmountOverflow,
    /// A witness proof is internally inconsistent; see [`MerkleProof`].
    MalformedProof,
    /// A witness does not describe the state at the point in the block where it is used.
    StaleWitness,
    /// Replaying the transactions from `old_root` did not land on the block's `new_root`.
    RootMismatch,
    /// A [`Sidecar`] does not carry exactly one entry per transaction in its [`Batch`].
    ///
    /// [`Sidecar::decode`] rules this out at the wire boundary, so it can only be reached by
    /// pairing a batch and sidecar that were never meant for each other.
    SidecarLengthMismatch,
    /// A [`TxnSidecar`] is not of the shape its [`Transaction`] calls for.
    ///
    /// Like [`VerificationError::SidecarLengthMismatch`], unreachable from the wire:
    /// [`Sidecar::decode`] reads each entry in the shape the batch's transaction kinds dictate, so
    /// a mismatched pair cannot be encoded. It exists for sidecars built by hand.
    SidecarKindMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    nonce: u64,
    amount: u64,
    auth_address: Address,
}

impl Account {
    /// An account in an arbitrary state.
    ///
    /// Nothing here ties `auth_address` to the address the account will be stored at, so this can
    /// build states no sequence of blocks could reach. That is what makes it useful for laying down
    /// a genesis ledger or a test fixture, and why ordinary block replay never calls it -- see
    /// [`Account::empty`], which is what [`verify_batch`] pins a created account to.
    pub fn new(nonce: u64, amount: u64, auth_address: Address) -> Self {
        Self {
            nonce,
            amount,
            auth_address,
        }
    }

    /// A fresh, empty account at `address`, authorized by the key that hashes to `address`.
    ///
    /// This is the state an account is created in when it is first paid, before its owner has ever
    /// signed anything. It is spendable only by the key the address was derived from, until a
    /// rekey points `auth_address` elsewhere.
    pub fn empty(address: Address) -> Self {
        Self::new(0, 0, address)
    }

    /// A fresh, empty account controlled by `pub_key` under `scheme`, along with the address it
    /// lives at.
    pub fn from_public_key(scheme: Scheme, pub_key: &[u8]) -> (Address, Self) {
        let address = address_from_public_key(scheme, pub_key);

        (address, Self::empty(address))
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn auth_address(&self) -> Address {
        self.auth_address
    }

    /// The account state as committed to by a leaf of the [`SparseMerkleTree`].
    pub fn encode(&self) -> [u8; ENCODED_ACCOUNT_SIZE] {
        let mut buf = [0u8; ENCODED_ACCOUNT_SIZE];
        let mut offset = 0;

        let nonce_bytes = self.nonce.to_be_bytes();
        buf[offset..offset + nonce_bytes.len()].copy_from_slice(&nonce_bytes);
        offset += nonce_bytes.len();

        let amount_bytes = self.amount.to_be_bytes();
        buf[offset..offset + amount_bytes.len()].copy_from_slice(&amount_bytes);
        offset += amount_bytes.len();

        buf[offset..offset + self.auth_address.len()].copy_from_slice(&self.auth_address);

        buf
    }

    /// Inverse of [`Account::encode`], for a decoder rebuilding a witnessed account off the wire.
    pub(crate) fn decode(bytes: &[u8; ENCODED_ACCOUNT_SIZE]) -> Self {
        let mut offset = 0;

        let nonce = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let amount = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let auth_address: Address = bytes[offset..offset + 32].try_into().unwrap();

        Self::new(nonce, amount, auth_address)
    }

    /// Advance to the next nonce, which is the only value a transaction from this account can carry.
    ///
    /// Because the next nonce is fixed by the current one, it does not have to be transmitted: a
    /// replayer derives it, and the signature is checked against the derived value. That is what
    /// keeps the nonce out of the [`Batch`] encoding entirely. The cost is that nonces cannot be
    /// skipped, so a signature is only ever valid at one exact position in the account's history --
    /// which is the replay protection the nonce existed for in the first place.
    fn bump_nonce(&mut self) -> Result<(), VerificationError> {
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(VerificationError::InvalidNonce)?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionHeader {
    sender: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payment {
    header: TransactionHeader,
    receiver: Address,
    amount: u64,
}

impl Payment {
    pub fn new(sender: Address, receiver: Address, amount: u64) -> Self {
        Self {
            header: TransactionHeader { sender },
            receiver,
            amount,
        }
    }

    /// The bytes a sender signs to authorize this payment at `nonce`.
    ///
    /// `nonce` is not carried by the payment: it is whatever [`Account::bump_nonce`] produces for
    /// the sender at the point the payment is replayed, so the signature commits to the payment's
    /// exact position in that account's history without a byte on the wire.
    pub fn bytes_to_sign(&self, nonce: u64) -> [u8; ENCODED_TX_SIZE] {
        let mut buf = [0u8; ENCODED_TX_SIZE];
        let mut offset = 0;

        buf[offset..offset + self.header.sender.len()].copy_from_slice(&self.header.sender);
        offset += self.header.sender.len();

        let nonce_bytes = nonce.to_be_bytes();
        buf[offset..offset + nonce_bytes.len()].copy_from_slice(&nonce_bytes);
        offset += nonce_bytes.len();

        buf[offset..offset + self.receiver.len()].copy_from_slice(&self.receiver);
        offset += self.receiver.len();

        let amount_bytes = self.amount.to_be_bytes();
        buf[offset..offset + amount_bytes.len()].copy_from_slice(&amount_bytes);

        buf
    }
}

/// Value entering the rollup from L1.
///
/// Carries a header like any other transaction, but its sender is always [`ZERO_ADDRESS`]: the
/// funds come from outside the rollup, so there is no account to debit. [`Deposit::new`] is the
/// only constructor and pins the sender, which makes a deposit from anywhere else unconstructible.
///
/// The sender is not on the wire. It is a constant, and the batch format's whole thesis is that a
/// replaying node derives what it can, so [`Batch::decode`] fills it in. See [`Batch::encode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deposit {
    header: TransactionHeader,
    receiver: Address,
    amount: u64,
}

impl Deposit {
    pub fn new(receiver: Address, amount: u64) -> Self {
        Self {
            header: TransactionHeader {
                sender: ZERO_ADDRESS,
            },
            receiver,
            amount,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transaction {
    Payment(Payment),
    Deposit(Deposit),
}

impl Transaction {
    /// Who the transaction spends from, which for a [`Deposit`] is [`ZERO_ADDRESS`].
    ///
    /// Total rather than optional precisely because deposits carry a header: a caller never has to
    /// case on the kind to ask this, and the one address that comes back for a deposit is the one
    /// that can never be an account.
    pub fn sender(&self) -> Address {
        match self {
            Transaction::Payment(payment) => payment.header.sender,
            Transaction::Deposit(deposit) => deposit.header.sender,
        }
    }

    pub fn receiver(&self) -> Address {
        match self {
            Transaction::Payment(payment) => payment.receiver,
            Transaction::Deposit(deposit) => deposit.receiver,
        }
    }

    pub fn amount(&self) -> u64 {
        match self {
            Transaction::Payment(payment) => payment.amount,
            Transaction::Deposit(deposit) => deposit.amount,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    scheme: Scheme,
    pub_key: Vec<u8>,
    sig: Vec<u8>,
}

impl Signature {
    pub fn new(scheme: Scheme, pub_key: Vec<u8>, sig: Vec<u8>) -> Self {
        Self {
            scheme,
            pub_key,
            sig,
        }
    }

    /// The address of the signer, which must match an account's `auth_address` to spend from it.
    pub fn address(&self) -> Address {
        address_from_public_key(self.scheme, &self.pub_key)
    }

    pub fn verify_auth(&self, account: &Account) -> Result<(), VerificationError> {
        if self.address() == account.auth_address {
            Ok(())
        } else {
            Err(VerificationError::InvalidAuthAddress)
        }
    }
}

/// A transaction as submitted, before the sequencer has placed it in a block.
///
/// This is a mempool type, not a wire type: the two halves are separated on the way into a block,
/// the transaction going into the [`Batch`] and the signature into the [`Sidecar`].
///
/// An enum rather than a struct with an optional signature, so that "a deposit carries no
/// signature" is a fact about the type rather than a case every reader has to remember to handle.
/// A signed deposit is unrepresentable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedTransaction {
    Payment { payment: Payment, sig: Signature },
    Deposit { deposit: Deposit },
}

impl SignedTransaction {
    pub fn payment(payment: Payment, sig: Signature) -> Self {
        SignedTransaction::Payment { payment, sig }
    }

    /// A deposit, which nobody signs.
    ///
    /// Authorization comes from L1 instead: the settlement contract only accepts a batch whose
    /// deposits fold to the chain it built as the deposits arrived. See [`accumulate_deposit`].
    pub fn deposit(deposit: Deposit) -> Self {
        SignedTransaction::Deposit { deposit }
    }
}

/// Everything a verifier needs to know about one leaf slot at the moment it is written.
///
/// `proof` serves twice: with `old_account` it pins the pre-state against the running root, and
/// with the computed post-state it yields the next root. The siblings are never checked directly
/// -- a witness carrying the wrong ones simply fails to reproduce the running root -- and neither
/// is the depth the proof implies, for the same reason. The one thing checked outright is a
/// [`Slot::Neighbor`]'s address, which has to be consistent with the path that reached it; see
/// [`merkle::root_from_proof`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafWitness {
    /// State of the slot immediately before the write, or `None` for an empty slot.
    old_account: Option<Account>,
    proof: MerkleProof,
}

/// Everything about one transaction that the chain does not have to record.
///
/// A sidecar entry can only make a transaction fail to prove; it can never change what the
/// transaction does. The addresses and the amount come from the [`Batch`], the nonce is derived,
/// and post-states are computed -- so a doctored sidecar produces a rejected block, not a
/// redirected payment.
///
/// The shape mirrors [`Transaction`], because the two halves of a transaction need different things
/// witnessed. [`Sidecar::decode`] reads each entry in the shape the batch's kinds call for, so an
/// entry paired with the wrong kind is not representable on the wire.
// A deposit entry is well under half the size of a payment entry, so every deposit in a batch
// carries a payment entry's worth of slack. Boxing the large variant would recover it at the cost
// of a heap allocation per *payment* during decode -- and this decode runs in the guest, where
// payments are the common case and allocation is paid for in cycles. The slack is transient,
// unpublished, and bounded by the batch; the allocations would not be.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxnSidecar {
    Payment(PaymentSidecar),
    Deposit(DepositSidecar),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentSidecar {
    sig: Signature,
    sender_witness: LeafWitness,
    receiver_witness: LeafWitness,
}

/// A deposit witnesses one slot, not two.
///
/// There is no sender witness because there is no sender account -- [`ZERO_ADDRESS`] is a marker
/// and never enters the tree -- and no signature because a deposit is authorized on L1 rather than
/// by a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositSidecar {
    receiver_witness: LeafWitness,
}

/// The transactions of a block, exactly as the chain records them.
///
/// This is the only part of a block that has to be published. Everything else a verifier needs is
/// either derivable from the pre-state ([`Sidecar`]) or already known to the settlement contract
/// (the roots). See [`Batch::encode`] for the wire format.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Batch {
    txns: Vec<Transaction>,
}

impl Batch {
    pub fn txns(&self) -> &[Transaction] {
        &self.txns
    }

    pub fn len(&self) -> usize {
        self.txns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txns.is_empty()
    }
}

/// The signatures and witnesses for a [`Batch`], supplied to the prover and never published.
///
/// Entry `i` belongs to transaction `i`. The pairing is enforced at the wire boundary by
/// [`Sidecar::decode`], which is handed the transaction count the batch decoded to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sidecar {
    entries: Vec<TxnSidecar>,
}

impl Sidecar {
    pub fn entries(&self) -> &[TxnSidecar] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A block as the sequencer holds it: the published half, the private half, and the transition.
///
/// The two halves go to different places -- [`Block::batch`] to the chain, [`Block::sidecar`] to
/// the prover -- and only the sequencer ever needs all four fields at once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    old_root: [u8; 32],
    new_root: [u8; 32],
    old_deposit_chain: [u8; 32],
    new_deposit_chain: [u8; 32],
    batch: Batch,
    sidecar: Sidecar,
}

impl Block {
    pub fn old_root(&self) -> [u8; 32] {
        self.old_root
    }

    pub fn new_root(&self) -> [u8; 32] {
        self.new_root
    }

    /// Deposit chain the block starts from; see [`accumulate_deposit`].
    pub fn old_deposit_chain(&self) -> [u8; 32] {
        self.old_deposit_chain
    }

    /// Deposit chain the block's deposits fold it to. Equal to `old_deposit_chain` when the block
    /// contains no deposits.
    pub fn new_deposit_chain(&self) -> [u8; 32] {
        self.new_deposit_chain
    }

    pub fn batch(&self) -> &Batch {
        &self.batch
    }

    pub fn sidecar(&self) -> &Sidecar {
        &self.sidecar
    }
}

/// Where the deposit chain starts: no deposit has ever been accepted.
///
/// Thirty-two zero bytes, matching the genesis state root, and for the same reason -- a chain over
/// nothing should be the value a fresh contract holds without having to be told.
pub const DEPOSIT_CHAIN_GENESIS: [u8; 32] = [0u8; 32];

/// Fold one deposit into the running chain.
///
/// This is how the settlement contract knows a batch credited exactly the deposits L1 accepted, and
/// no others. The contract extends the chain as each deposit arrives; the guest folds the same hash
/// over the deposits it decodes out of the batch and commits where it landed. The contract pins
/// both ends -- the value it settled last time, and the value it holds now -- and with both ends
/// fixed the folds between them are determined, short of a SHA-256 collision.
///
/// Chaining is what makes one 32-byte word enough. Because each step consumes the last, the value
/// pins the set, the order, and the count at once: inventing, dropping, reordering, or altering a
/// deposit all diverge the fold at that step and never recover. It is an exclusion proof as much as
/// an inclusion proof, which is what stops a prover minting a credit L1 never saw.
///
/// Only `receiver` and `amount` are hashed, and that is a rule rather than an omission: every field
/// in this preimage has to be reconstructible by the guest from the batch bytes alone. An L1 nonce
/// or the L1 payer's address would not be, so committing to either would mean carrying it on the
/// wire forever to buy something the chaining already provides.
///
/// The preimage is 79 bytes, far inside [`AVM_MAX_BYTE_SLICE`]. The domain tag keeps a chain value
/// from ever being mistakable for a state root, a chunk digest, or a chunk accumulator.
pub fn accumulate_deposit(chain: &[u8; 32], receiver: &Address, amount: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DEPOSIT");
    hasher.update(chain);
    hasher.update(receiver);
    hasher.update(amount.to_be_bytes());

    hasher.finalize().into()
}

/// The root implied by `account` sitting at `address`, or an error if `proof` is malformed.
fn root_with(
    address: &Address,
    account: Option<&Account>,
    proof: &MerkleProof,
) -> Result<[u8; 32], VerificationError> {
    merkle::root_from_proof(address, account, proof).ok_or(VerificationError::MalformedProof)
}

/// Check that `witness` describes the slot for `address` as it stands at `root`.
fn expect_pre_state(
    address: &Address,
    witness: &LeafWitness,
    root: [u8; 32],
) -> Result<(), VerificationError> {
    if root_with(address, witness.old_account.as_ref(), &witness.proof)? == root {
        Ok(())
    } else {
        Err(VerificationError::StaleWitness)
    }
}

/// Credit `amount` to `receiver` against the running `root`, and return the root that produces.
///
/// The second half of a payment and the whole of a deposit. A created account is pinned to
/// [`Account::empty`], so a prover cannot choose the `auth_address` of an account it brings into
/// existence -- which is also what lets a depositor spend immediately with the key their address
/// was derived from.
fn credit(
    receiver_addr: &Address,
    witness: &LeafWitness,
    amount: u64,
    root: [u8; 32],
) -> Result<[u8; 32], VerificationError> {
    expect_pre_state(receiver_addr, witness, root)?;

    let mut receiver = witness
        .old_account
        .unwrap_or_else(|| Account::empty(*receiver_addr));
    receiver.amount = receiver
        .amount
        .checked_add(amount)
        .ok_or(VerificationError::AmountOverflow)?;

    root_with(receiver_addr, Some(&receiver), &witness.proof)
}

/// Replay `batch` against `sidecar`, from `old_root` and `deposit_anchor`, and return the root and
/// deposit chain it lands on.
///
/// This is the guest's entry point, and it is deliberately not told what to expect for either: the
/// settlement contract compares both returned values against what it has stored, so there is no
/// prover-supplied answer for the replay to be checked against.
///
/// A payment writes two slots -- sender then receiver -- and every write both checks the pre-state
/// against the running root and advances it. Chaining the roots this way means a self-payment needs
/// no special case: the receiver write reads the slot the sender write just produced, and the root
/// comparison enforces that it agrees.
///
/// A deposit writes one. There is no sender to debit, so total balances rise -- the mint is backed
/// by the settlement contract's own ALGO rather than by conservation inside the tree, and what
/// authorizes it is the deposit chain: see [`accumulate_deposit`]. A reserve account funding
/// deposits from inside the tree would only relocate the mint, since the reserve would have to be
/// minted into as well, at the cost of a second write and witness on every deposit.
///
/// Deposits and payments interleave freely. The chain constrains the order of deposits relative to
/// each other and nothing more, which is what lets a payment spend a deposit credited earlier in
/// the same batch.
///
/// Nothing here trusts the sidecar. Addresses and amounts come from the batch, nonces are derived
/// from the witnessed account, and post-states are computed rather than supplied, so a doctored
/// sidecar produces a rejected block rather than a redirected payment.
pub fn verify_batch(
    old_root: [u8; 32],
    deposit_anchor: [u8; 32],
    batch: &Batch,
    sidecar: &Sidecar,
) -> Result<([u8; 32], [u8; 32]), VerificationError> {
    if batch.txns.len() != sidecar.entries.len() {
        return Err(VerificationError::SidecarLengthMismatch);
    }

    let mut root = old_root;
    let mut deposit_chain = deposit_anchor;

    for (txn, entry) in batch.txns.iter().zip(&sidecar.entries) {
        match (txn, entry) {
            (Transaction::Payment(payment), TxnSidecar::Payment(entry)) => {
                let (sender_addr, receiver_addr, amt) =
                    (payment.header.sender, payment.receiver, payment.amount);

                expect_pre_state(&sender_addr, &entry.sender_witness, root)?;
                let mut sender = entry
                    .sender_witness
                    .old_account
                    .ok_or(VerificationError::UnknownSender)?;
                entry.sig.verify_auth(&sender)?;
                sender.amount = sender
                    .amount
                    .checked_sub(amt)
                    .ok_or(VerificationError::InsufficientFunds)?;
                sender.bump_nonce()?;
                // `sender.nonce` now holds the only nonce this transaction could carry, which is
                // the value the signature must have been made over.
                // TODO: crypto verification of `entry.sig` over `payment.bytes_to_sign(sender.nonce)`.
                root = root_with(&sender_addr, Some(&sender), &entry.sender_witness.proof)?;

                // Read against the root the sender write just produced, so a self-payment sees the
                // debited balance and the bumped nonce.
                root = credit(&receiver_addr, &entry.receiver_witness, amt, root)?;
            }
            (Transaction::Deposit(deposit), TxnSidecar::Deposit(entry)) => {
                let (receiver_addr, amt) = (deposit.receiver, deposit.amount);

                root = credit(&receiver_addr, &entry.receiver_witness, amt, root)?;
                deposit_chain = accumulate_deposit(&deposit_chain, &receiver_addr, amt);
            }
            _ => return Err(VerificationError::SidecarKindMismatch),
        }
    }

    Ok((root, deposit_chain))
}

/// Longest application argument a settlement transaction can carry, as of go-algorand 5.0 (AVM
/// v42).
pub const MAX_APP_ARG: usize = 4096;

/// Bytes an ABI `byte[]` argument spends on its own length prefix, and so bytes a chunk cannot use.
const ABI_LENGTH_PREFIX: usize = 2;

/// Largest fragment of a batch: as much as fits in one application argument once the ABI length
/// prefix has taken its two bytes.
///
/// This is an argument-size limit, not the [`AVM_MAX_BYTE_SLICE`] limit on hashing -- a chunk has
/// to both arrive in one transaction and be hashable in one step, and the delivery limit is the
/// tighter of the two.
pub const CHUNK_SIZE: usize = MAX_APP_ARG - ABI_LENGTH_PREFIX;

/// How many chunks a batch of `batch_len` bytes is posted in.
pub fn chunk_count(batch_len: usize) -> usize {
    batch_len.div_ceil(CHUNK_SIZE)
}

/// Where a contract starts accumulating, for a batch the sequencer declares to be `batch_len`
/// bytes long.
///
/// Committing to the length up front does two things. It tells the contract how many chunks to
/// expect, so it knows when a batch is complete rather than having to be told. And it makes the
/// chunk boundaries canonical: every chunk is [`CHUNK_SIZE`] bytes except the last, whose size the
/// length fixes, so a sequencer cannot re-cut the same bytes into different chunks and reach a
/// different commitment.
pub fn chunk_accumulator_seed(batch_len: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BATCH");
    hasher.update((batch_len as u64).to_be_bytes());

    hasher.finalize().into()
}

/// Longest byte string the AVM can hold in one stack element, and so the longest preimage a
/// settlement contract can hash in one step.
///
/// Every hash in the chunk commitment is built to stay under this. It is the reason the commitment
/// is a two-step fold rather than one hash per chunk: a chunk is already allowed to fill this
/// budget on its own, leaving no room to concatenate a domain tag and an accumulator alongside it.
pub const AVM_MAX_BYTE_SLICE: usize = 4096;

/// Commitment to one posted chunk, hashed on its own.
///
/// Deliberately untagged. A full chunk is [`CHUNK_SIZE`] bytes, within two bytes of the entire
/// budget the AVM allows in one value, so there is no room for a prefix -- and none is needed,
/// because a chunk digest is only ever consumed inside the tagged preimage of
/// [`accumulate_chunk`]. It can never be read as a seed or as an accumulator.
pub fn chunk_digest(chunk: &[u8]) -> [u8; 32] {
    debug_assert!(
        chunk.len() <= CHUNK_SIZE,
        "a chunk must fit in one settlement transaction"
    );

    Sha256::digest(chunk).into()
}

/// Fold one chunk's digest into a contract's accumulator.
///
/// This plus [`chunk_digest`] is the whole of the contract's data-availability bookkeeping: one
/// 32-byte word of state and two hashes per chunk, with no tree and no per-chunk proofs. Both
/// preimages are far inside [`AVM_MAX_BYTE_SLICE`] -- this one is 69 bytes.
///
/// The domain tag keeps an accumulator from ever being mistaken for a seed or for a chunk digest.
pub fn accumulate_chunk(accumulator: &[u8; 32], chunk_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"CHUNK");
    hasher.update(accumulator);
    hasher.update(chunk_digest);

    hasher.finalize().into()
}

/// Commitment to the batch bytes the chain records, folded over the chunks they are posted in.
///
/// The guest commits this rather than the bytes themselves. Public values are hashed into the
/// proof and passed to the verifier, so putting a whole block in them would mean paying for the
/// batch twice.
///
/// Folding over chunks is what lets a batch larger than one settlement transaction be posted
/// across several: the contract accumulates as the chunks arrive and compares the result against
/// this. A batch that fits in one chunk is just the one-step case of the same fold, so there is a
/// single code path regardless of size.
///
/// Chunking is deliberately a property of the byte stream and not of the transaction list -- the
/// cut can fall in the middle of a payment, and the decoder never sees a chunk boundary because
/// the bytes are reassembled before [`Batch::decode`] runs.
///
/// The guest computes this over the whole batch it holds; the contract reaches the same value one
/// chunk at a time. Neither ever hashes more than [`AVM_MAX_BYTE_SLICE`] bytes in one step, which
/// is what makes the two computations the same computation.
pub fn batch_commitment(batch_bytes: &[u8]) -> [u8; 32] {
    let mut accumulator = chunk_accumulator_seed(batch_bytes.len());

    for chunk in batch_bytes.chunks(CHUNK_SIZE) {
        accumulator = accumulate_chunk(&accumulator, &chunk_digest(chunk));
    }

    accumulator
}

pub const PUBLIC_VALUES_SIZE: usize = 32 * 5;

/// What a proof exposes: the two roots, which batch got between them, and the two ends of the
/// deposit chain the batch consumed.
///
/// ```text
/// [  0.. 32)  old_root
/// [ 32.. 64)  new_root
/// [ 64.. 96)  batch_commitment
/// [ 96..128)  old_deposit_chain
/// [128..160)  new_deposit_chain
/// ```
///
/// Laid out here so the guest and the settlement contract read the same 160 bytes the same way. The
/// contract's side is: check `old_root` against the root it has stored, check the commitment
/// against a hash of the batch bytes it was handed across the preceding transactions, check both
/// deposit-chain ends against what it has recorded, verify the proof, then store `new_root`.
///
/// The commitment check is what makes the data available: the bytes have to be presented to the
/// contract, not merely promised, or the root advances with nothing to reconstruct state from. The
/// two deposit-chain checks are what make the batch's deposits exactly L1's; see
/// [`accumulate_deposit`]. Both ends are pinned rather than just the last, so a prover cannot pick
/// an anchor that makes a fabricated fold land correctly.
pub fn public_values(
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    batch_bytes: &[u8],
    old_deposit_chain: &[u8; 32],
    new_deposit_chain: &[u8; 32],
) -> [u8; PUBLIC_VALUES_SIZE] {
    let mut buf = [0u8; PUBLIC_VALUES_SIZE];

    buf[..32].copy_from_slice(old_root);
    buf[32..64].copy_from_slice(new_root);
    buf[64..96].copy_from_slice(&batch_commitment(batch_bytes));
    buf[96..128].copy_from_slice(old_deposit_chain);
    buf[128..].copy_from_slice(new_deposit_chain);

    buf
}

/// Why a pair of encoded block halves does not produce a proof.
///
/// The two cases are the two boundaries a block crosses on its way into the guest: the bytes have
/// to be a block at all, and the block has to replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    Decode(DecodeError),
    Verification(VerificationError),
}

impl From<DecodeError> for ExecutionError {
    fn from(error: DecodeError) -> Self {
        ExecutionError::Decode(error)
    }
}

impl From<VerificationError> for ExecutionError {
    fn from(error: VerificationError) -> Self {
        ExecutionError::Verification(error)
    }
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionError::Decode(error) => write!(f, "could not decode the block: {error}"),
            ExecutionError::Verification(error) => {
                write!(f, "the block does not verify: {error:?}")
            }
        }
    }
}

impl std::error::Error for ExecutionError {}

/// The whole of what a proof asserts, computed from the same bytes the guest is handed.
///
/// This is the guest program with the zkVM taken out: decode both halves, replay from `old_root`
/// and `deposit_anchor`, and lay out the public values. The guest is a wrapper that reads its four
/// inputs, calls this, and commits what comes back -- so there is one implementation of "what this
/// proof says", and a host can reach the committed values without proving anything.
///
/// Note there is still no expected root among the inputs, and for the same reason no expected
/// deposit chain. The replay reports where it landed on both, and the settlement contract is the
/// only thing that decides whether those are the values it was holding.
pub fn execute(
    old_root: [u8; 32],
    deposit_anchor: [u8; 32],
    batch_bytes: &[u8],
    sidecar_bytes: &[u8],
) -> Result<[u8; PUBLIC_VALUES_SIZE], ExecutionError> {
    let batch = Batch::decode(batch_bytes)?;
    let sidecar = Sidecar::decode(sidecar_bytes, &batch)?;

    let (new_root, new_deposit_chain) = verify_batch(old_root, deposit_anchor, &batch, &sidecar)?;

    Ok(public_values(
        &old_root,
        &new_root,
        batch_bytes,
        &deposit_anchor,
        &new_deposit_chain,
    ))
}

/// Replay a whole [`Block`] and check it reaches its own `new_root` and `new_deposit_chain`.
///
/// The sequencer-side convenience wrapper around [`verify_batch`]: a block already carries the
/// values it claims, so this is the one place `RootMismatch` can come from. The guest calls
/// [`verify_batch`] directly and lets the settlement contract make the comparison.
pub fn verify_block(block: &Block) -> Result<(), VerificationError> {
    let (root, deposit_chain) = verify_batch(
        block.old_root,
        block.old_deposit_chain,
        &block.batch,
        &block.sidecar,
    )?;

    if root == block.new_root && deposit_chain == block.new_deposit_chain {
        Ok(())
    } else {
        Err(VerificationError::RootMismatch)
    }
}

#[derive(Default)]
pub struct Ledger {
    accounts: HashMap<Address, Account>,
    /// Commitment to `accounts`, kept in step with every write so [`Ledger::state_root`] is always
    /// current.
    tree: SparseMerkleTree,
    /// Fold over every deposit this ledger has applied, mirroring what the settlement contract
    /// holds. Never reset -- it is an anchor, not a per-block accumulator.
    deposit_chain: [u8; 32],
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            deposit_chain: DEPOSIT_CHAIN_GENESIS,
            ..Self::default()
        }
    }

    /// The deposit chain as it stands, which is what the next block will anchor to.
    pub fn deposit_chain(&self) -> [u8; 32] {
        self.deposit_chain
    }

    pub fn account(&self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    pub fn insert_account(&mut self, address: Address, account: Account) {
        self.tree.update(&address, Some(&account));
        self.accounts.insert(address, account);
    }

    /// Create an empty account for `pub_key` under `scheme` and return its address.
    ///
    /// An account that already exists at that address is left untouched, so this cannot be used to
    /// wipe a balance by re-submitting a key.
    pub fn create_account(&mut self, scheme: Scheme, pub_key: &[u8]) -> Address {
        let (address, account) = Account::from_public_key(scheme, pub_key);
        if !self.accounts.contains_key(&address) {
            self.insert_account(address, account);
        }

        address
    }

    /// Commitment to the full account state, suitable for publishing on-chain.
    pub fn state_root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Prove what [`Ledger::state_root`] commits to for `address`. Addresses with no account get a
    /// non-inclusion proof; see [`verify_proof`].
    pub fn proof(&self, address: &Address) -> MerkleProof {
        self.tree.proof(address)
    }

    /// Apply `stxns` in order, splitting them into the [`Batch`] the chain records and the
    /// [`Sidecar`] the prover consumes.
    ///
    /// Nonces are assigned here rather than taken from the submitted transactions -- each sender
    /// gets its next one, in the order the transactions appear -- so the order the sequencer picks
    /// is what fixes which nonce each signature has to cover.
    pub fn get_block(&mut self, stxns: Vec<SignedTransaction>) -> Block {
        let old_root = self.state_root();
        let old_deposit_chain = self.deposit_chain;
        let mut txns = Vec::with_capacity(stxns.len());
        let mut entries = Vec::with_capacity(stxns.len());

        for stxn in stxns {
            let txn = match stxn {
                SignedTransaction::Payment { payment, sig } => {
                    let sender_addr = payment.header.sender;

                    let sender_witness = LeafWitness {
                        old_account: self.accounts.get(&sender_addr).copied(),
                        proof: self.tree.proof(&sender_addr),
                    };

                    let receiver_addr = payment.receiver;
                    let amt = payment.amount;

                    let sender = self.accounts.get_mut(&sender_addr).unwrap();
                    sig.verify_auth(sender).unwrap();
                    // TODO: crypto verification
                    sender.amount = sender.amount.checked_sub(amt).unwrap();
                    sender.bump_nonce().unwrap();
                    let sender = *sender;
                    self.tree.update(&sender_addr, Some(&sender));

                    // Captured after the sender write, so a self-payment witnesses the debited balance.
                    let receiver_witness = self.credit(receiver_addr, amt);

                    entries.push(TxnSidecar::Payment(PaymentSidecar {
                        sig,
                        sender_witness,
                        receiver_witness,
                    }));

                    Transaction::Payment(payment)
                }
                SignedTransaction::Deposit { deposit } => {
                    let receiver_witness = self.credit(deposit.receiver, deposit.amount);

                    self.deposit_chain =
                        accumulate_deposit(&self.deposit_chain, &deposit.receiver, deposit.amount);

                    entries.push(TxnSidecar::Deposit(DepositSidecar { receiver_witness }));

                    Transaction::Deposit(deposit)
                }
            };

            txns.push(txn);
        }

        Block {
            old_root,
            new_root: self.state_root(),
            old_deposit_chain,
            new_deposit_chain: self.deposit_chain,
            batch: Batch { txns },
            sidecar: Sidecar { entries },
        }
    }

    /// Credit `amount` to `receiver`, returning the witness for the slot as it stood beforehand.
    ///
    /// The witness is captured before the write and after everything preceding it, which is what
    /// makes a self-payment work: the receiver half witnesses the balance the sender half just
    /// debited. Mirrors [`credit`] on the verifying side.
    fn credit(&mut self, receiver: Address, amount: u64) -> LeafWitness {
        let witness = LeafWitness {
            old_account: self.accounts.get(&receiver).copied(),
            proof: self.tree.proof(&receiver),
        };

        let account = self
            .accounts
            .entry(receiver)
            .or_insert_with(|| Account::empty(receiver));
        account.amount = account.amount.checked_add(amount).unwrap();
        let account = *account;
        self.tree.update(&receiver, Some(&account));

        witness
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEME: Scheme = Scheme::Managed;

    fn signature_with(scheme: Scheme, pub_key: &[u8]) -> Signature {
        Signature {
            scheme,
            pub_key: pub_key.to_vec(),
            sig: Vec::new(),
        }
    }

    fn signature(pub_key: &[u8]) -> Signature {
        signature_with(SCHEME, pub_key)
    }

    /// The account for `key` in the state `(nonce, amount)`, at its derived address.
    ///
    /// Building on [`Account::from_public_key`] rather than [`Account::new`] means the address and
    /// `auth_address` always agree with the key -- a test cannot accidentally pair a key with an
    /// account it could not sign for.
    fn account_at(key: &[u8], nonce: u64, amount: u64) -> (Address, Account) {
        let (address, mut account) = Account::from_public_key(SCHEME, key);
        account.nonce = nonce;
        account.amount = amount;

        (address, account)
    }

    /// Put a freshly created account for `key` into `ledger`, holding `amount`.
    fn fund(ledger: &mut Ledger, key: &[u8], amount: u64) -> Address {
        let (address, account) = account_at(key, 0, amount);
        ledger.insert_account(address, account);

        address
    }

    /// A payment of `amount` from the account for `key` to `receiver`, signed by `key`.
    ///
    /// No nonce: the sequencer assigns it, so a test only controls the order it submits in.
    fn stxn(key: &[u8], receiver: Address, amount: u64) -> SignedTransaction {
        payment(key, address_from_public_key(SCHEME, key), receiver, amount)
    }

    /// A payment from `sender` to `receiver`, signed by `key`, for the cases where the two are
    /// deliberately not derived from each other.
    fn payment(key: &[u8], sender: Address, receiver: Address, amount: u64) -> SignedTransaction {
        SignedTransaction::payment(
            Payment {
                header: TransactionHeader { sender },
                receiver,
                amount,
            },
            signature(key),
        )
    }

    /// A deposit crediting the account for `key`.
    fn deposit(key: &[u8], amount: u64) -> SignedTransaction {
        SignedTransaction::deposit(Deposit::new(address_from_public_key(SCHEME, key), amount))
    }

    /// The payment entry at `index`, for tests that doctor one of its witnesses.
    fn payment_entry(block: &mut Block, index: usize) -> &mut PaymentSidecar {
        match &mut block.sidecar.entries[index] {
            TxnSidecar::Payment(entry) => entry,
            TxnSidecar::Deposit(_) => panic!("entry {index} is a deposit, not a payment"),
        }
    }

    /// A ledger holding `a key` and `b key`, and the address the `fresh key` account would live at
    /// once something pays it.
    fn three_txn_block() -> (Block, Address, Address, Address) {
        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", 1_000);
        let b = fund(&mut ledger, b"b key", 500);
        let fresh = address_from_public_key(SCHEME, b"fresh key");

        let block = ledger.get_block(vec![
            // A plain payment, a payment that brings a new account into existence, and a
            // self-payment -- the three shapes a witness has to cover.
            stxn(b"a key", b, 100),
            stxn(b"b key", fresh, 50),
            stxn(b"a key", a, 25),
        ]);

        (block, a, b, fresh)
    }

    #[test]
    fn a_block_verifies_with_no_access_to_the_ledger() {
        let (block, ..) = three_txn_block();

        assert_eq!(verify_block(&block), Ok(()));
    }

    #[test]
    fn verify_block_agrees_with_the_ledger_that_built_it() {
        let mut ledger = Ledger::new();
        let sender = fund(&mut ledger, b"sender key", 1_000);
        let receiver = fund(&mut ledger, b"receiver key", 5);

        let before = ledger.state_root();
        let block = ledger.get_block(vec![stxn(b"sender key", receiver, 250)]);

        assert_eq!(block.old_root(), before);
        assert_eq!(block.new_root(), ledger.state_root());
        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(ledger.account(&sender).unwrap().amount(), 750);
    }

    #[test]
    fn verify_block_rejects_a_doctored_pre_state() {
        let (mut block, ..) = three_txn_block();

        // Claim the sender was richer than it was. The witness proof pins the pre-state to the
        // running root, so an inflated balance cannot reproduce it.
        payment_entry(&mut block, 0).sender_witness.old_account =
            Some(account_at(b"a key", 0, 1_000_000).1);

        assert_eq!(verify_block(&block), Err(VerificationError::StaleWitness));
    }

    #[test]
    fn a_created_account_cannot_have_its_auth_address_chosen() {
        let (mut block, ..) = three_txn_block();
        let attacker = address_from_public_key(SCHEME, b"attacker key");

        // The second transaction creates `fresh`, so its receiver slot is empty. Claiming it
        // already held an account the attacker can sign for would hand them the balance.
        payment_entry(&mut block, 1).receiver_witness.old_account =
            Some(Account::new(0, 0, attacker));

        assert_eq!(verify_block(&block), Err(VerificationError::StaleWitness));
    }

    #[test]
    fn verify_block_rejects_a_transition_to_the_wrong_root() {
        let (mut block, ..) = three_txn_block();
        block.new_root = [0xff; 32];

        assert_eq!(verify_block(&block), Err(VerificationError::RootMismatch));
    }

    #[test]
    fn verify_block_rejects_a_dropped_transaction() {
        let (mut block, ..) = three_txn_block();

        // Drop the transaction and its sidecar entry together, so nothing is out of step. The
        // remaining two no longer reach the claimed `new_root`.
        block.batch.txns.pop();
        block.sidecar.entries.pop();

        assert_eq!(verify_block(&block), Err(VerificationError::RootMismatch));
    }

    #[test]
    fn verify_block_rejects_reordered_transactions() {
        let (mut block, ..) = three_txn_block();

        // The swap carries each transaction's own sidecar entry with it, and it still fails: a
        // witness describes one specific point in the root chain, so order is load-bearing on its
        // own.
        block.batch.txns.swap(0, 1);
        block.sidecar.entries.swap(0, 1);

        assert!(verify_block(&block).is_err());
    }

    // Splitting the block in two makes a count mismatch representable, where pairing a transaction
    // with its witnesses in one struct did not. It is caught outright rather than left to misalign
    // the replay.
    #[test]
    fn verify_batch_rejects_a_sidecar_that_does_not_line_up() {
        let (mut block, ..) = three_txn_block();
        block.sidecar.entries.pop();

        assert_eq!(
            verify_batch(
                block.old_root,
                block.old_deposit_chain,
                &block.batch,
                &block.sidecar
            ),
            Err(VerificationError::SidecarLengthMismatch)
        );
    }

    // The settlement contract reads these 160 bytes by offset, so the layout is as load-bearing as
    // the roots themselves.
    #[test]
    fn public_values_lay_out_the_transition_and_the_batch_commitment() {
        let (block, ..) = three_txn_block();
        let batch_bytes = block.batch().encode();

        let values = public_values(
            &block.old_root(),
            &block.new_root(),
            &batch_bytes,
            &block.old_deposit_chain(),
            &block.new_deposit_chain(),
        );

        assert_eq!(values.len(), PUBLIC_VALUES_SIZE);
        assert_eq!(&values[..32], &block.old_root());
        assert_eq!(&values[32..64], &block.new_root());
        assert_eq!(&values[64..96], &batch_commitment(&batch_bytes));
        assert_eq!(&values[96..128], &block.old_deposit_chain());
        assert_eq!(&values[128..], &block.new_deposit_chain());

        // The commitment is domain-separated and covers every byte, so a batch that differs
        // anywhere cannot be presented against this proof.
        let mut tampered = batch_bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_ne!(batch_commitment(&tampered), batch_commitment(&batch_bytes));
    }

    /// What a settlement contract does: seed from the declared length, fold each chunk as it
    /// arrives, and end up with something to compare against the proof's public values.
    fn accumulate_as_a_contract_would(batch_bytes: &[u8]) -> [u8; 32] {
        let mut accumulator = chunk_accumulator_seed(batch_bytes.len());
        for chunk in batch_bytes.chunks(CHUNK_SIZE) {
            accumulator = accumulate_chunk(&accumulator, &chunk_digest(chunk));
        }

        accumulator
    }

    // The constraint that shapes the whole scheme: a settlement contract cannot hold more than
    // `AVM_MAX_BYTE_SLICE` bytes in one value, so no preimage in the commitment may exceed it. A
    // single hash of `tag || accumulator || chunk` would need 4131 bytes and be unimplementable
    // on-chain, which is why the fold digests the chunk first.
    #[test]
    fn no_key_can_produce_the_zero_address() {
        // Not a proof -- that rests on SHA-256 preimage resistance -- but it pins the claim the
        // marker depends on against every scheme, so a future one that hashed differently would
        // have to defend itself here.
        for scheme in Scheme::ALL {
            for key in [b"".as_slice(), b"a key", b"\x00", &[0u8; 32]] {
                assert_ne!(address_from_public_key(scheme, key), ZERO_ADDRESS);
            }
        }
    }

    #[test]
    fn a_deposit_is_always_from_the_zero_address() {
        let receiver = address_from_public_key(SCHEME, b"receiver");

        assert_eq!(
            Transaction::Deposit(Deposit::new(receiver, 1)).sender(),
            ZERO_ADDRESS
        );
    }

    #[test]
    fn a_deposit_creates_and_credits_an_account() {
        let mut ledger = Ledger::new();
        let block = ledger.get_block(vec![deposit(b"a key", 1_000)]);
        let a = address_from_public_key(SCHEME, b"a key");

        // A deposit is the only way a block starting from the empty ledger can fund anything.
        assert_eq!(block.old_root(), Ledger::new().state_root());
        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(ledger.account(&a).unwrap().amount(), 1_000);
        // Pinned to `Account::empty`, so the depositor can spend with the key their address was
        // derived from and nobody else can.
        assert_eq!(ledger.account(&a).unwrap().auth_address(), a);
        assert_eq!(ledger.account(&a).unwrap().nonce(), 0);
    }

    #[test]
    fn a_deposit_can_be_spent_in_the_same_batch_that_created_it() {
        let mut ledger = Ledger::new();
        let b = address_from_public_key(SCHEME, b"b key");

        let block = ledger.get_block(vec![deposit(b"a key", 1_000), stxn(b"a key", b, 400)]);

        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(ledger.account(&b).unwrap().amount(), 400);
    }

    #[test]
    fn an_empty_batch_leaves_the_deposit_chain_unchanged() {
        let block = Ledger::new().get_block(vec![]);

        assert_eq!(block.old_deposit_chain(), DEPOSIT_CHAIN_GENESIS);
        assert_eq!(block.new_deposit_chain(), block.old_deposit_chain());
        assert_eq!(verify_block(&block), Ok(()));
    }

    // "Unchanged" is what a batch with no deposits commits, which is why an empty deposit set needs
    // no distinguishing seed constant: the settlement contract compares the chain it holds against
    // the chain the batch landed on, and with deposits pending those cannot be equal.
    #[test]
    fn a_batch_that_skips_a_pending_deposit_lands_short_of_the_chain() {
        let mut settled = Ledger::new();
        let posted = settled.get_block(vec![deposit(b"a key", 1_000)]);

        // What L1 would hold after accepting two deposits, only one of which the batch credits.
        let contract_chain = accumulate_deposit(
            &posted.new_deposit_chain(),
            &address_from_public_key(SCHEME, b"b key"),
            500,
        );

        assert_ne!(posted.new_deposit_chain(), contract_chain);
    }

    #[test]
    fn the_deposit_chain_pins_order() {
        let ab = Ledger::new()
            .get_block(vec![deposit(b"a key", 1_000), deposit(b"b key", 500)])
            .new_deposit_chain();
        let ba = Ledger::new()
            .get_block(vec![deposit(b"b key", 500), deposit(b"a key", 1_000)])
            .new_deposit_chain();

        assert_ne!(ab, ba);
    }

    #[test]
    fn the_deposit_chain_pins_count() {
        let one = Ledger::new()
            .get_block(vec![deposit(b"a key", 1_000)])
            .new_deposit_chain();
        let two = Ledger::new()
            .get_block(vec![deposit(b"a key", 1_000), deposit(b"a key", 1_000)])
            .new_deposit_chain();

        assert_ne!(one, two);
    }

    // Each step consumes the last, so position is already committed to. This is why the L1 nonce
    // does not need to be in the preimage -- which matters, because the guest could not reconstruct
    // it from the batch bytes if it were.
    #[test]
    fn two_identical_deposits_do_not_collapse() {
        let mut ledger = Ledger::new();
        let block = ledger.get_block(vec![deposit(b"a key", 1_000), deposit(b"a key", 1_000)]);

        let first = accumulate_deposit(
            &DEPOSIT_CHAIN_GENESIS,
            &address_from_public_key(SCHEME, b"a key"),
            1_000,
        );

        assert_ne!(first, block.new_deposit_chain());
        assert_eq!(
            ledger
                .account(&address_from_public_key(SCHEME, b"a key"))
                .unwrap()
                .amount(),
            2_000
        );
    }

    // The whole point of the chain: a prover that credits an account L1 never funded lands on a
    // value the contract is not holding, so the fabricated mint cannot settle.
    #[test]
    fn a_fabricated_deposit_diverges_the_chain() {
        let mut honest = Ledger::new();
        let real = honest.get_block(vec![deposit(b"a key", 1_000)]);

        let mut greedy = Ledger::new();
        let forged = greedy.get_block(vec![
            deposit(b"a key", 1_000),
            deposit(b"attacker key", 1_000_000),
        ]);

        // Both replay cleanly on their own terms -- the fraud is not detectable inside the guest.
        assert_eq!(verify_block(&real), Ok(()));
        assert_eq!(verify_block(&forged), Ok(()));

        // It is detectable against L1's chain, which is the only copy that counts.
        assert_ne!(forged.new_deposit_chain(), real.new_deposit_chain());
    }

    #[test]
    fn verify_batch_rejects_a_sidecar_of_the_wrong_kind() {
        let mut ledger = Ledger::new();
        let mut block = ledger.get_block(vec![deposit(b"a key", 1_000)]);

        // A payment entry against a deposit: unreachable over the wire, since `Sidecar::decode`
        // reads the shape the batch calls for, but reachable by hand.
        block.sidecar.entries[0] = TxnSidecar::Payment(PaymentSidecar {
            sig: signature(b"a key"),
            sender_witness: LeafWitness {
                old_account: None,
                proof: ledger.proof(&ZERO_ADDRESS),
            },
            receiver_witness: LeafWitness {
                old_account: None,
                proof: ledger.proof(&address_from_public_key(SCHEME, b"a key")),
            },
        });

        assert_eq!(
            verify_batch(
                block.old_root,
                block.old_deposit_chain,
                &block.batch,
                &block.sidecar
            ),
            Err(VerificationError::SidecarKindMismatch)
        );
    }

    #[test]
    fn every_preimage_a_contract_must_hash_fits_in_one_avm_value() {
        let seed_preimage = b"BATCH".len() + size_of::<u64>();
        let digest_preimage = CHUNK_SIZE;
        let fold_preimage = b"CHUNK".len() + 32 + 32;
        let deposit_preimage = b"DEPOSIT".len() + 32 + 32 + size_of::<u64>();

        for (name, len) in [
            ("seed", seed_preimage),
            ("chunk digest", digest_preimage),
            ("fold step", fold_preimage),
            ("deposit fold", deposit_preimage),
        ] {
            assert!(
                len <= AVM_MAX_BYTE_SLICE,
                "{name} preimage is {len} bytes, over the {AVM_MAX_BYTE_SLICE}-byte AVM limit"
            );
        }
    }

    #[test]
    fn a_batch_posted_in_chunks_accumulates_to_its_commitment() {
        // Enough payments to span several chunks at ~70 bytes each.
        let mut ledger = Ledger::new();
        let sender = fund(&mut ledger, b"spender", 1_000_000);
        let stxns = (0..500u32)
            .map(|i| {
                payment(
                    b"spender",
                    sender,
                    address_from_public_key(SCHEME, &i.to_be_bytes()),
                    1_000,
                )
            })
            .collect();
        let batch_bytes = ledger.get_block(stxns).batch().encode();

        assert!(
            chunk_count(batch_bytes.len()) > 1,
            "the fixture must actually span chunks, got {} bytes",
            batch_bytes.len()
        );
        assert_eq!(
            accumulate_as_a_contract_would(&batch_bytes),
            batch_commitment(&batch_bytes),
            "the contract's fold must land where the guest's commitment did"
        );
    }

    #[test]
    fn a_partially_posted_batch_does_not_match() {
        let (block, ..) = three_txn_block();
        let batch_bytes = block.batch().encode();

        // Stopping one chunk short must not accumulate to the commitment, or a sequencer could
        // advance the root having published only part of the batch.
        let mut accumulator = chunk_accumulator_seed(batch_bytes.len());
        let chunks: Vec<_> = batch_bytes.chunks(CHUNK_SIZE).collect();
        for chunk in &chunks[..chunks.len() - 1] {
            accumulator = accumulate_chunk(&accumulator, &chunk_digest(chunk));
        }

        assert_ne!(accumulator, batch_commitment(&batch_bytes));
    }

    #[test]
    fn the_declared_length_pins_the_chunking() {
        let bytes = vec![0u8; CHUNK_SIZE + 1];

        // Two chunks, and re-cutting them is not open to the sequencer: the seed commits to the
        // total length, which fixes where every boundary falls.
        assert_eq!(chunk_count(bytes.len()), 2);
        assert_ne!(
            batch_commitment(&bytes),
            accumulate_chunk(
                &chunk_accumulator_seed(bytes.len()),
                &Sha256::digest(&bytes).into()
            ),
            "one oversized chunk must not reach the same commitment as the canonical two"
        );

        // And a batch of a different length starts from a different seed, so no two lengths share
        // an accumulator at any point.
        assert_ne!(
            chunk_accumulator_seed(bytes.len()),
            chunk_accumulator_seed(bytes.len() - 1)
        );
    }

    #[test]
    fn chunk_counts_cover_the_boundaries() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_SIZE), 1);
        assert_eq!(chunk_count(CHUNK_SIZE + 1), 2);

        // An empty batch is the zero-step fold, which is just the seed.
        assert_eq!(batch_commitment(&[]), chunk_accumulator_seed(0));
    }

    #[test]
    fn verify_block_rejects_spending_from_an_empty_slot() {
        let mut ledger = Ledger::new();
        let receiver = fund(&mut ledger, b"receiver key", 10);
        let funded = fund(&mut ledger, b"sender key", 100);

        let mut block = ledger.get_block(vec![stxn(b"sender key", receiver, 40)]);

        // Rewrite the transaction to spend from an address with no account, and hand it the
        // matching absence proof from before the block -- the strongest witness there is for that
        // slot. A missing sender must still be rejected outright.
        let empty = address_from_public_key(SCHEME, b"no account here");
        let mut fresh_ledger = Ledger::new();
        fresh_ledger.insert_account(receiver, account_at(b"receiver key", 0, 10).1);
        fresh_ledger.insert_account(funded, account_at(b"sender key", 0, 100).1);

        let Transaction::Payment(payment) = &mut block.batch.txns[0] else {
            panic!("the first transaction of the fixture block is a payment")
        };
        payment.header.sender = empty;
        payment_entry(&mut block, 0).sender_witness = LeafWitness {
            old_account: None,
            proof: fresh_ledger.proof(&empty),
        };

        assert_eq!(verify_block(&block), Err(VerificationError::UnknownSender));
    }

    #[test]
    fn process_block_keeps_the_state_root_in_step() {
        let mut ledger = Ledger::new();
        let sender_addr = fund(&mut ledger, b"sender key", 1_000);
        let receiver_addr = fund(&mut ledger, b"receiver key", 5);

        let before = ledger.state_root();

        ledger.get_block(vec![payment(
            b"sender key",
            sender_addr,
            receiver_addr,
            250,
        )]);

        assert_ne!(ledger.state_root(), before);
        assert_eq!(ledger.account(&sender_addr).unwrap().amount(), 750);
        assert_eq!(ledger.account(&receiver_addr).unwrap().amount(), 255);

        // Both touched accounts prove against the post-block root.
        for address in [sender_addr, receiver_addr] {
            assert!(verify_proof(
                &ledger.state_root(),
                &address,
                ledger.account(&address),
                &ledger.proof(&address),
            ));
        }

        // And an address the ledger has never seen proves absent.
        let unknown = address_from_public_key(SCHEME, b"unknown key");
        assert!(verify_proof(
            &ledger.state_root(),
            &unknown,
            None,
            &ledger.proof(&unknown),
        ));
    }

    #[test]
    fn address_commits_to_the_scheme() {
        let key = b"some key";

        assert_ne!(
            address_from_public_key(Scheme::Ed25519, key),
            address_from_public_key(Scheme::Falcon1024HybridEd25519, key),
            "the same key under two schemes must give two addresses"
        );
        assert_eq!(
            address_from_public_key(Scheme::Ed25519, key),
            signature_with(Scheme::Ed25519, key).address(),
            "Signature::address must agree with the standalone derivation"
        );
    }

    #[test]
    fn scheme_identifiers_round_trip() {
        for scheme in Scheme::ALL {
            assert_eq!(
                Scheme::from_identifier(&scheme.identifier()),
                Some(scheme),
                "every scheme must be recoverable from the identifier it encodes to"
            );
        }
        assert_eq!(Scheme::from_identifier(b"???"), None);
    }

    #[test]
    fn account_from_public_key_can_sign_for_itself() {
        let key = b"fresh key";
        let (address, account) = Account::from_public_key(Scheme::Ed25519, key);

        assert_eq!(account.nonce(), 0);
        assert_eq!(account.amount(), 0);
        assert_eq!(
            account.auth_address(),
            address,
            "a new account is self-authorized"
        );
        assert!(
            signature_with(Scheme::Ed25519, key)
                .verify_auth(&account)
                .is_ok()
        );
    }

    #[test]
    fn create_account_does_not_clobber_an_existing_one() {
        let key = b"funded key";

        let mut ledger = Ledger::new();
        let address = ledger.create_account(SCHEME, key);
        assert_eq!(ledger.account(&address), Some(&Account::empty(address)));

        let (_, funded) = account_at(key, 3, 900);
        ledger.insert_account(address, funded);

        assert_eq!(ledger.create_account(SCHEME, key), address);
        assert_eq!(ledger.account(&address), Some(&funded));
    }

    #[test]
    fn paying_an_unknown_address_creates_the_account() {
        let new_addr = address_from_public_key(SCHEME, b"never seen");

        let mut ledger = Ledger::new();
        let sender_addr = fund(&mut ledger, b"sender key", 1_000);

        // The tree proves the receiver absent before the block.
        assert!(ledger.account(&new_addr).is_none());
        assert!(verify_proof(
            &ledger.state_root(),
            &new_addr,
            None,
            &ledger.proof(&new_addr),
        ));

        ledger.get_block(vec![payment(b"sender key", sender_addr, new_addr, 300)]);

        let created = *ledger.account(&new_addr).unwrap();
        assert_eq!(created, account_at(b"never seen", 0, 300).1);

        // ...and proves it present afterwards, spendable by the key it was derived from.
        assert!(verify_proof(
            &ledger.state_root(),
            &new_addr,
            Some(&created),
            &ledger.proof(&new_addr),
        ));
        assert!(signature(b"never seen").verify_auth(&created).is_ok());
    }

    #[test]
    fn sequential_writes_match_rebuilding_from_final_state() {
        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", 1_000);
        let b = fund(&mut ledger, b"b key", 500);
        // `c` starts empty, so plain account creation is all it needs.
        let c = ledger.create_account(SCHEME, b"c key");

        // `a` and `b` are each written by more than one transaction, so their leaf slots are
        // rehashed repeatedly. The end state must still match a ledger built directly from it: an
        // address has one fixed slot, so the root depends only on the final account set.
        let block = ledger.get_block(vec![
            payment(b"a key", a, b, 100),
            payment(b"b key", b, c, 50),
            payment(b"a key", signature(b"a key").address(), b, 25),
        ]);

        let mut expected = Ledger::new();
        for (key, nonce, amount) in [
            (b"a key".as_slice(), 2, 875),
            (b"b key".as_slice(), 1, 575),
            (b"c key".as_slice(), 0, 50),
        ] {
            let (address, account) = account_at(key, nonce, amount);
            expected.insert_account(address, account);
        }

        assert_eq!(ledger.account(&a), expected.account(&a));
        assert_eq!(ledger.account(&b), expected.account(&b));
        assert_eq!(ledger.account(&c), expected.account(&c));
        assert_eq!(ledger.state_root(), expected.state_root());
        assert_eq!(verify_block(&block), Ok(()));

        for address in [a, b, c] {
            assert!(verify_proof(
                &ledger.state_root(),
                &address,
                ledger.account(&address),
                &ledger.proof(&address),
            ));
        }
    }

    #[test]
    fn self_payment_commits_the_nonce_bump() {
        let mut ledger = Ledger::new();
        let addr = fund(&mut ledger, b"self key", 100);

        ledger.get_block(vec![payment(b"self key", addr, addr, 40)]);

        let account = *ledger.account(&addr).unwrap();
        assert_eq!(account.amount(), 100);
        assert_eq!(account.nonce(), 1);
        assert!(verify_proof(
            &ledger.state_root(),
            &addr,
            Some(&account),
            &ledger.proof(&addr),
        ));
    }
}
