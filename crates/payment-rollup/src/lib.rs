use std::collections::HashMap;
use std::fmt;

use sha2::{Digest, Sha256};

mod codec;
mod crypto;
mod merkle;

pub use codec::DecodeError;
pub use crypto::{
    ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE, FALCON_PUBLIC_KEY_SIZE,
    HYBRID_PUBLIC_KEY_SIZE, MAX_HYBRID_SIGNATURE_SIZE, MIN_HYBRID_SIGNATURE_SIZE,
};
pub use merkle::{MerkleProof, Slot, SparseMerkleTree, verify_proof};

pub type Address = [u8; 32];

/// An account on the settlement chain, as the AVM holds one: the raw 32-byte public key, without
/// the checksum and base32 armour a human-readable Algorand address carries.
///
/// A separate alias from [`Address`] because the two are the same width and mean opposite things --
/// an [`Address`] is a position in this rollup's tree, an [`L1Address`] is somewhere outside it. The
/// alias cannot stop a mix-up on its own, but it makes one visible at every signature that handles
/// both. See the warning on [`Withdrawal`].
pub type L1Address = [u8; 32];

/// Identifies one rollup deployment for signatures and batch commitments.
pub type DeploymentDomain = [u8; 32];

/// Derive the domain for an application on a settlement-chain genesis.
pub fn deployment_domain(genesis_hash: &[u8; 32], app_id: u64) -> DeploymentDomain {
    let mut hasher = Sha256::new();
    hasher.update(b"PAYMENT_ROLLUP_V1");
    hasher.update(genesis_hash);
    hasher.update(app_id.to_be_bytes());

    hasher.finalize().into()
}

/// Smallest withdrawal the rollup will process, in microALGO.
///
/// Equal to the network's own minimum balance, and that is the whole reason for it. The settlement
/// contract pays a withdrawal out with an inner transaction, and an inner payment below the minimum
/// balance fails outright when its receiver does not yet exist.
///
/// Enforcing it here rather than on L1 is what makes that impossible rather than merely unlikely: a
/// block containing an unpayable withdrawal does not verify, so the contract is never asked to make
/// a payment it cannot complete.
///
/// Load-bearing for liveness as well as for correctness, since payouts are made in chain order:
/// see [`withdrawal_chain`]. One unpayable payment would not merely fail on its own, it would block
/// every later payout in the same batch -- and with them the next batch, which cannot open until
/// the chain drains. This constant is what rules that out.
pub const MIN_WITHDRAWAL: u64 = 100_000;

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

/// How an account proves a spend, and so what its key and signature bytes are.
///
/// The scheme is part of the address -- see [`address_from_public_key`] -- so it is fixed when the
/// account is created and cannot be changed afterwards except by rekeying to an address that has a
/// different one. See `crypto.rs` for what each scheme checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// No signing authority is granted via crypto signatures at all: the account is managed
    /// directly by the sequencer.
    ///
    /// There is no key behind the `auth_address` of a managed account, so nothing a verifier could
    /// hold a signature to -- a spend from one is authorized by the fact that the sequencer built
    /// the batch containing it. Everything else in the replay still applies: the pre-state is
    /// witnessed, the nonce is derived, and the roots have to line up.
    Managed,
    /// Ed25519, the scheme the settlement chain itself uses.
    ///
    /// A [`ED25519_PUBLIC_KEY_SIZE`]-byte key and a [`ED25519_SIGNATURE_SIZE`]-byte signature.
    Ed25519,
    /// Falcon-1024 and Ed25519 together, both of which must sign.
    ///
    /// The post-quantum option, and hybrid rather than Falcon alone so that adopting it cannot make
    /// an account *less* safe: forging a signature means breaking the lattice scheme and the curve
    /// scheme, so a holder is never worse off than they were under [`Scheme::Ed25519`].
    ///
    /// The key is [`HYBRID_PUBLIC_KEY_SIZE`] bytes, Ed25519 first; the signature is the Ed25519
    /// signature followed by a variable-length Falcon one. Falcon is the deterministic "det1024"
    /// variant in its compressed format, which is what the AVM's `falcon_verify` accepts -- so a
    /// signature that spends here is one the settlement contract can also be shown.
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

/// What a signed transaction is, written into the bytes its sender signs.
///
/// Without these, a [`Payment`] and a [`Withdrawal`] over the same sender, nonce, 32-byte
/// destination and amount produce byte-identical preimages -- so one signature would authorize
/// either, and a signature meant to move funds inside the rollup would move them out of it. The tag
/// is what makes the two unmistakable.
const SIGN_TAG_PAYMENT: &[u8; 3] = b"PAY";
const SIGN_TAG_WITHDRAWAL: &[u8; 3] = b"WDR";

const SIGN_TAG_SIZE: usize = 3;

const ENCODED_TX_SIZE: usize = 32 + SIGN_TAG_SIZE + 32 + 8 + 32 + 8;

/// The bytes a sender signs to authorize moving `amount` to `destination` at `nonce`.
///
/// Shared by [`Payment::bytes_to_sign`] and [`Withdrawal::bytes_to_sign`]. The transaction tag is
/// first, followed by the deployment domain and fields, so neither transaction kinds nor
/// deployments can share a signing preimage.
fn bytes_to_sign(
    domain: &DeploymentDomain,
    tag: &[u8; SIGN_TAG_SIZE],
    sender: &Address,
    nonce: u64,
    destination: &[u8; 32],
    amount: u64,
) -> [u8; ENCODED_TX_SIZE] {
    let mut buf = [0u8; ENCODED_TX_SIZE];
    let mut offset = 0;

    buf[offset..offset + tag.len()].copy_from_slice(tag);
    offset += tag.len();

    buf[offset..offset + domain.len()].copy_from_slice(domain);
    offset += domain.len();

    buf[offset..offset + sender.len()].copy_from_slice(sender);
    offset += sender.len();

    let nonce_bytes = nonce.to_be_bytes();
    buf[offset..offset + nonce_bytes.len()].copy_from_slice(&nonce_bytes);
    offset += nonce_bytes.len();

    buf[offset..offset + destination.len()].copy_from_slice(destination);
    offset += destination.len();

    buf[offset..offset + size_of::<u64>()].copy_from_slice(&amount.to_be_bytes());

    buf
}

pub(crate) const ENCODED_ACCOUNT_SIZE: usize = 8 + 8 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidAuthAddress,
    /// A signature is not the signature of the account's key over the transaction it accompanies.
    ///
    /// The one error a signer's own mistake can produce: the wrong key, the wrong nonce, the wrong
    /// domain, or a signature over a payment presented for a withdrawal. All of them are the same
    /// thing to a verifier -- the bytes the account would have had to sign are not the bytes it
    /// signed.
    InvalidSignature,
    /// A public key is not a key of the scheme its address commits to.
    ///
    /// Reachable only for an account nobody can spend from, since the address is a hash of these
    /// very bytes: to hold an account whose key does not parse, its creator would have had to derive
    /// the address from a key they could not sign with.
    MalformedKey,
    /// A signature is not the shape its scheme calls for -- the wrong length for the fixed-size
    /// schemes, or outside the bounds the hybrid's variable-length Falcon half allows.
    MalformedSignature,
    /// An account's nonce cannot be advanced any further.
    InvalidNonce,
    /// A transaction spends from an address the witness proves holds no account.
    UnknownSender,
    InsufficientFunds,
    AmountOverflow,
    /// A withdrawal is for less than [`MIN_WITHDRAWAL`], so the settlement contract could not
    /// reliably pay it out.
    WithdrawalTooSmall,
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
    pub fn bytes_to_sign(&self, domain: &DeploymentDomain, nonce: u64) -> [u8; ENCODED_TX_SIZE] {
        bytes_to_sign(
            domain,
            SIGN_TAG_PAYMENT,
            &self.header.sender,
            nonce,
            &self.receiver,
            self.amount,
        )
    }
}

/// Value leaving the rollup for the settlement chain.
///
/// The mirror of a [`Deposit`]: a deposit writes one slot and credits it, a withdrawal writes one
/// slot and debits it. Total balances fall, and the settlement contract makes the holder whole in
/// real ALGO once the batch settles -- see [`withdrawal_chain`] for how it learns to.
///
/// **`recipient` is an Algorand address, not a rollup address.** Everywhere else in this crate a
/// 32-byte destination is an [`Address`], meaning a position in the state tree; here it is the raw
/// public key of an account on L1. Passing a rollup address pays out to an L1 account nobody holds
/// the key to, and the funds are gone. The type alias is the only thing marking the difference, and
/// it is advisory -- see [`L1Address`].
///
/// `amount` is at least [`MIN_WITHDRAWAL`], checked in [`verify_batch`] rather than here so that a
/// hand-built withdrawal is representable and simply fails to prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    header: TransactionHeader,
    recipient: L1Address,
    amount: u64,
}

impl Withdrawal {
    pub fn new(sender: Address, recipient: L1Address, amount: u64) -> Self {
        Self {
            header: TransactionHeader { sender },
            recipient,
            amount,
        }
    }

    pub fn recipient(&self) -> L1Address {
        self.recipient
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// The bytes a sender signs to authorize this withdrawal at `nonce`.
    ///
    /// Domain-separated from [`Payment::bytes_to_sign`], which is what stops a signature over a
    /// payment from also authorizing a withdrawal of the same amount to the same 32 bytes.
    pub fn bytes_to_sign(&self, domain: &DeploymentDomain, nonce: u64) -> [u8; ENCODED_TX_SIZE] {
        bytes_to_sign(
            domain,
            SIGN_TAG_WITHDRAWAL,
            &self.header.sender,
            nonce,
            &self.recipient,
            self.amount,
        )
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

    pub fn receiver(&self) -> Address {
        self.receiver
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }
}

/// A withdrawal the settlement chain ordered, rather than one the sequencer was asked for.
///
/// The censorship-resistant counterpart to [`Withdrawal`]. An ordinary withdrawal is handed to the
/// sequencer and can simply be dropped -- L1 never hears of it, so nothing notices. This one is
/// filed on L1 first, folded into a chain there, and [`verify_batch`] cannot reach the value the
/// contract is holding unless the batch consumes it. Ignoring one is therefore not censorship of a
/// transaction, it is a refusal to settle at all, which is the failure the escape hatch already
/// watches for.
///
/// **No amount.** The account is emptied. That is not a simplification but the property that makes
/// forced inclusion safe: a request for a specific amount can be unaffordable when the batch
/// reaches it, so a verifier would need a rule for what to do then -- and any such rule is a lever
/// the sequencer can pull. A request for the whole balance is always satisfiable, so the only thing
/// left for a verifier to decide is whether there is enough to be worth paying out at all. See the
/// forced-withdrawal arm of [`verify_batch`].
///
/// Like a [`Deposit`], it carries no signature. Authorization happened on L1, where the settlement
/// contract checked that the key presented derives the address being emptied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForcedWithdrawal {
    header: TransactionHeader,
    recipient: L1Address,
}

impl ForcedWithdrawal {
    pub fn new(address: Address, recipient: L1Address) -> Self {
        Self {
            header: TransactionHeader { sender: address },
            recipient,
        }
    }

    /// The rollup account being emptied.
    pub fn address(&self) -> Address {
        self.header.sender
    }

    pub fn recipient(&self) -> L1Address {
        self.recipient
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transaction {
    Payment(Payment),
    Deposit(Deposit),
    Withdrawal(Withdrawal),
    ForcedWithdrawal(ForcedWithdrawal),
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
            Transaction::Withdrawal(withdrawal) => withdrawal.header.sender,
            Transaction::ForcedWithdrawal(forced) => forced.header.sender,
        }
    }

    /// Which account in the tree the transaction credits, or `None` when it credits none.
    ///
    /// Optional where [`Transaction::sender`] is total, and the asymmetry is the point: a deposit
    /// has no sender *account* but [`ZERO_ADDRESS`] stands in for one, whereas a withdrawal's
    /// destination is an [`L1Address`] outside the tree entirely and no rollup address could stand
    /// in for it. Returning it here would be handing a caller 32 bytes in the wrong namespace.
    pub fn receiver(&self) -> Option<Address> {
        match self {
            Transaction::Payment(payment) => Some(payment.receiver),
            Transaction::Deposit(deposit) => Some(deposit.receiver),
            Transaction::Withdrawal(_) | Transaction::ForcedWithdrawal(_) => None,
        }
    }

    /// How much the transaction moves, or `None` when the wire does not say.
    ///
    /// Only a [`ForcedWithdrawal`] does not say: it moves the account's whole balance, which is
    /// read out of the pre-state during replay rather than carried. Optional rather than zero
    /// because "this transaction moves nothing" and "the amount is not written down here" are
    /// different claims, and a caller totalling a batch has to be made to notice the difference.
    pub fn amount(&self) -> Option<u64> {
        match self {
            Transaction::Payment(payment) => Some(payment.amount),
            Transaction::Deposit(deposit) => Some(deposit.amount),
            Transaction::Withdrawal(withdrawal) => Some(withdrawal.amount),
            Transaction::ForcedWithdrawal(_) => None,
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

    /// Check that this authorizes `message` on behalf of `account`.
    ///
    /// Two questions, asked in this order because they are about different things and the first is
    /// nearly free. Is this key allowed to spend from this account -- [`Signature::verify_auth`],
    /// one hash and a comparison. And did that key actually sign these bytes -- the scheme's own
    /// check, which is the expensive part of verifying a block.
    ///
    /// Asking the cheap question first is not only about cost. A signature that is perfectly valid
    /// under the wrong account should say so, and it does: `InvalidAuthAddress` rather than
    /// `InvalidSignature`.
    ///
    /// `message` is built by the caller, and what it commits to is the whole of what a signature
    /// means here: see `bytes_to_sign`.
    pub fn verify(&self, account: &Account, message: &[u8]) -> Result<(), VerificationError> {
        self.verify_auth(account)?;

        crypto::verify(self.scheme, &self.pub_key, &self.sig, message)
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
    Payment {
        payment: Payment,
        sig: Signature,
    },
    Deposit {
        deposit: Deposit,
    },
    Withdrawal {
        withdrawal: Withdrawal,
        sig: Signature,
    },
    ForcedWithdrawal {
        forced: ForcedWithdrawal,
    },
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

    /// A withdrawal, which its sender signs like any other spend.
    ///
    /// The signature is what authorizes the debit; the chain the batch folds to is only what tells
    /// L1 whom to pay. Both are needed, and they answer different questions -- see
    /// [`withdrawal_chain`].
    pub fn withdrawal(withdrawal: Withdrawal, sig: Signature) -> Self {
        SignedTransaction::Withdrawal { withdrawal, sig }
    }

    /// A withdrawal L1 ordered, which nobody signs here.
    ///
    /// Like a deposit, it was authorized on L1 -- the settlement contract checked a signature
    /// before it would accept the request. Unlike a deposit, the sequencer cannot decline to
    /// sequence it and still settle anything. See [`accumulate_request`].
    pub fn forced_withdrawal(forced: ForcedWithdrawal) -> Self {
        SignedTransaction::ForcedWithdrawal { forced }
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
    Withdrawal(WithdrawalSidecar),
    ForcedWithdrawal(ForcedWithdrawalSidecar),
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

/// A withdrawal witnesses one slot too, and the opposite one.
///
/// The deposit's missing half is the sender; the withdrawal's is the receiver, because the
/// recipient is an [`L1Address`] and has no slot in this tree to witness. The signature is present
/// -- unlike a deposit, a withdrawal spends from an account and has to be authorized by its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalSidecar {
    sig: Signature,
    sender_witness: LeafWitness,
}

/// A forced withdrawal witnesses one slot and carries no signature.
///
/// The witness is doing more work here than anywhere else. Everywhere else it pins a pre-state the
/// transaction is about to change; here it also *decides what the transaction does*, because the
/// amount withdrawn is the balance it reveals. That is safe for exactly the usual reason: the
/// witness is checked against the running root before it is read, so a prover cannot understate a
/// balance to suppress a payout, or overstate one to mint.
///
/// No signature, for the same reason a [`DepositSidecar`] has none -- the settlement contract
/// checked the authorization when it accepted the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForcedWithdrawalSidecar {
    sender_witness: LeafWitness,
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
    domain: DeploymentDomain,
    old_root: [u8; 32],
    new_root: [u8; 32],
    old_inbox_chain: [u8; 32],
    new_inbox_chain: [u8; 32],
    withdrawal_chain: [u8; 32],
    batch: Batch,
    sidecar: Sidecar,
}

impl Block {
    pub fn domain(&self) -> DeploymentDomain {
        self.domain
    }

    pub fn old_root(&self) -> [u8; 32] {
        self.old_root
    }

    pub fn new_root(&self) -> [u8; 32] {
        self.new_root
    }

    /// Inbox chain the block starts from.
    pub fn old_inbox_chain(&self) -> [u8; 32] {
        self.old_inbox_chain
    }

    /// Inbox chain after deposits and forced withdrawals are folded in transaction order.
    pub fn new_inbox_chain(&self) -> [u8; 32] {
        self.new_inbox_chain
    }

    /// Reverse-linked chain over every payout the block authorizes; see [`withdrawal_chain`].
    pub fn withdrawal_chain(&self) -> [u8; 32] {
        self.withdrawal_chain
    }

    pub fn batch(&self) -> &Batch {
        &self.batch
    }

    pub fn sidecar(&self) -> &Sidecar {
        &self.sidecar
    }
}

/// Where the L1 inbox chain starts: no deposit or forced withdrawal has been accepted.
///
/// Thirty-two zero bytes, matching the genesis state root, and for the same reason -- a chain over
/// nothing should be the value a fresh contract holds without having to be told.
pub const INBOX_CHAIN_GENESIS: [u8; 32] = [0u8; 32];

/// Fold one deposit into the running L1 inbox chain.
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
/// The preimage is 78 bytes, far inside [`AVM_MAX_BYTE_SLICE`]. The domain tag keeps a chain value
/// from ever being mistakable for a state root, a chunk digest, or a chunk accumulator.
pub fn accumulate_deposit(chain: &[u8; 32], receiver: &Address, amount: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"INBOXD");
    hasher.update(chain);
    hasher.update(receiver);
    hasher.update(amount.to_be_bytes());

    hasher.finalize().into()
}

/// Where a batch's payout chain ends, and so the value the settlement contract stops at.
///
/// Domain-separated rather than batch-separated, which is worth being explicit about because the
/// obvious alternative -- folding [`batch_commitment`] in -- looks stronger and is not. The chain
/// head is written to L1 only by the settlement call, out of the proof's public values, and never
/// by whoever makes a payout; so there is no batch whose chain could be spliced onto another's, and
/// nothing for batch-binding to prevent. It would only cost the contract a second global to hold,
/// since the commitment it would be derived from is deleted the moment the batch settles.
///
/// Two batches with identical payout lists therefore commit the same chain, which is harmless: each
/// head is installed and drained on its own, and the payouts are the same payouts.
pub fn withdrawal_chain_terminal(domain: &DeploymentDomain) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"WEND");
    hasher.update(domain);

    hasher.finalize().into()
}

/// Fold one payout onto the front of a batch's payout chain.
///
/// Note the direction: this prepends, so the argument is the chain value that comes *after* the
/// payout being added and the result is the value that comes before it. Building the chain
/// backwards is what lets the settlement contract check a payout before making it -- it holds the
/// head, and a caller offering the next payout must offer the tail it links to, so the preimage
/// either reproduces the head or it does not. A chain folded the other way could only be checked
/// once every payout had already been made, which is exactly too late.
///
/// The preimage is 76 bytes, far inside [`AVM_MAX_BYTE_SLICE`]. The domain tag keeps a chain value
/// from ever being mistakable for an inbox chain, a state root, or a chunk accumulator.
pub fn accumulate_withdrawal(tail: &[u8; 32], recipient: &L1Address, amount: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"WPAY");
    hasher.update(tail);
    hasher.update(recipient);
    hasher.update(amount.to_be_bytes());

    hasher.finalize().into()
}

/// The one word that commits to every payout a batch authorized, in order.
///
/// A reverse-linked hash chain over the payouts, anchored at [`withdrawal_chain_terminal`]. Like
/// the inbox chain, one 32-byte value pins the set, the order, and the count at once: each step
/// consumes the next, so inventing, dropping, reordering, or altering a payout diverges the chain
/// and never recovers.
///
/// What it replaces is a Merkle tree with a claim bitmap on L1. The tree let recipients claim in
/// any order, which needed a nullifier per payout, which needed a bound on how many a batch could
/// hold. A chain needs no nullifiers -- position in it *is* the nullifier -- so the bound goes too,
/// along with the tree, its proofs, and the box the bitmap lived in.
///
/// The cost is that payouts must be made in order and the sequencer must make them: the settlement
/// contract will not open the next batch until the chain has drained. That is the point rather than
/// a side effect. It turns withdrawals from something a recipient has to come and claim into
/// something the rollup owes and has to pay before it may continue.
pub fn withdrawal_chain(domain: &DeploymentDomain, payouts: &[(L1Address, u64)]) -> [u8; 32] {
    payouts.iter().rev().fold(
        withdrawal_chain_terminal(domain),
        |tail, (recipient, amount)| accumulate_withdrawal(&tail, recipient, *amount),
    )
}

/// One payout, and the chain value that follows it.
///
/// Exactly the arguments one settlement-contract payout call takes. `tail` is what makes the call
/// checkable: the contract recomputes [`accumulate_withdrawal`] over these three fields and
/// compares against the head it is holding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalLink {
    pub recipient: L1Address,
    pub amount: u64,
    pub tail: [u8; 32],
}

/// Every payout call a batch's chain requires, in the order the contract will accept them.
///
/// The counterpart to [`withdrawal_chain`] for whoever has to act on it, and the replacement for
/// what used to be a list of Merkle inclusion proofs. Folding [`accumulate_withdrawal`] over the
/// first link reproduces the committed chain, and each link's `tail` is the head the contract holds
/// once that payout has been made.
pub fn withdrawal_links(
    domain: &DeploymentDomain,
    payouts: &[(L1Address, u64)],
) -> Vec<WithdrawalLink> {
    let mut links = Vec::with_capacity(payouts.len());
    let mut tail = withdrawal_chain_terminal(domain);

    for (recipient, amount) in payouts.iter().rev() {
        links.push(WithdrawalLink {
            recipient: *recipient,
            amount: *amount,
            tail,
        });
        tail = accumulate_withdrawal(&tail, recipient, *amount);
    }

    links.reverse();
    links
}

/// Fold one L1 withdrawal request into the running L1 inbox chain.
///
/// This is what closes the censorship hole that ordinary [`Withdrawal`]s leave open. A withdrawal
/// handed to the sequencer can be dropped and nobody outside would know; a request folded in here
/// cannot, because [`verify_batch`] will not reach the chain value the contract is holding unless
/// the batch consumes every pending request in order. The sequencer's choices collapse to two:
/// honour them, or settle nothing at all -- and settling nothing is what the escape hatch is
/// already watching for.
///
/// Exactly the shape of [`accumulate_deposit`], and for the same reasons -- both ends pinned so a
/// fabricated fold has nowhere to anchor, and only fields the guest can rebuild from the batch
/// bytes in the preimage. There is no amount here because a request does not name one: it empties
/// the account, and the balance is read from the state during replay. The 102-byte preimage is far
/// inside [`AVM_MAX_BYTE_SLICE`].
pub fn accumulate_request(chain: &[u8; 32], address: &Address, recipient: &L1Address) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"INBOXW");
    hasher.update(chain);
    hasher.update(address);
    hasher.update(recipient);

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
/// Debit `amount` from `sender_addr` against the running `root`, and return the root that produces.
///
/// The first half of a payment and the whole of a withdrawal. Unlike [`credit`] this refuses an
/// empty slot outright: paying an address that holds nothing creates an account, but *spending*
/// from one that holds nothing is [`VerificationError::UnknownSender`] however good the proof of
/// its absence is.
///
/// The nonce is bumped before the signature is checked, and the bumped value is what
/// `bytes_to_sign` is handed: it is the only nonce a signature for this transaction could have been
/// made over, which is what lets the nonce stay off the wire entirely. See [`Account::bump_nonce`].
/// A caller passes the message as a closure rather than a value for exactly that reason -- the nonce
/// it commits to is not known until the witnessed pre-state has been read.
///
/// Authorization is settled before the balance is touched, so an unaffordable spend that nobody
/// signed for is reported as the forgery it is rather than as a shortfall.
fn debit(
    sender_addr: &Address,
    witness: &LeafWitness,
    sig: &Signature,
    amount: u64,
    root: [u8; 32],
    bytes_to_sign: impl FnOnce(u64) -> [u8; ENCODED_TX_SIZE],
) -> Result<[u8; 32], VerificationError> {
    expect_pre_state(sender_addr, witness, root)?;

    let mut sender = witness
        .old_account
        .ok_or(VerificationError::UnknownSender)?;
    sender.bump_nonce()?;
    sig.verify(&sender, &bytes_to_sign(sender.nonce))?;
    sender.amount = sender
        .amount
        .checked_sub(amount)
        .ok_or(VerificationError::InsufficientFunds)?;

    root_with(sender_addr, Some(&sender), &witness.proof)
}

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

/// Replay `batch` against `sidecar`, from `old_root` and `inbox_anchor`.
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
/// authorizes it is the inbox chain: see [`accumulate_deposit`]. A reserve account funding
/// deposits from inside the tree would only relocate the mint, since the reserve would have to be
/// minted into as well, at the cost of a second write and witness on every deposit.
///
/// A withdrawal writes one slot too, and it is the other one. There is no receiver to credit, so
/// total balances fall -- the burn is matched by the settlement contract paying out real ALGO, and
/// what tells it whom to pay is the withdrawal chain: see [`withdrawal_chain`]. This is the
/// exact inverse of a deposit, down to which half of the payment is missing.
///
/// Deposits, payments and withdrawals interleave freely. Their commitments preserve transaction
/// order, which is what lets a payment spend a deposit credited earlier in the same batch, or a
/// withdrawal spend what a payment just delivered.
///
/// Nothing here trusts the sidecar. Addresses and amounts come from the batch, nonces are derived
/// from the witnessed account, and post-states are computed rather than supplied, so a doctored
/// sidecar produces a rejected block rather than a redirected payment.
///
/// The batch bytes themselves are not an argument, only the decoded [`Batch`]: replay reads
/// transactions, and the one thing the raw bytes are needed for -- the commitment -- is computed
/// where it is used, in [`public_values`].
pub fn verify_batch(
    domain: &DeploymentDomain,
    old_root: [u8; 32],
    inbox_anchor: [u8; 32],
    batch: &Batch,
    sidecar: &Sidecar,
) -> Result<([u8; 32], [u8; 32], [u8; 32]), VerificationError> {
    if batch.txns.len() != sidecar.entries.len() {
        return Err(VerificationError::SidecarLengthMismatch);
    }

    let mut root = old_root;
    let mut inbox_chain = inbox_anchor;
    let mut payouts = Vec::new();

    for (txn, entry) in batch.txns.iter().zip(&sidecar.entries) {
        match (txn, entry) {
            (Transaction::Payment(payment), TxnSidecar::Payment(entry)) => {
                let (sender_addr, receiver_addr, amt) =
                    (payment.header.sender, payment.receiver, payment.amount);

                root = debit(
                    &sender_addr,
                    &entry.sender_witness,
                    &entry.sig,
                    amt,
                    root,
                    |nonce| payment.bytes_to_sign(domain, nonce),
                )?;

                // Read against the root the sender write just produced, so a self-payment sees the
                // debited balance and the bumped nonce.
                root = credit(&receiver_addr, &entry.receiver_witness, amt, root)?;
            }
            (Transaction::Deposit(deposit), TxnSidecar::Deposit(entry)) => {
                let (receiver_addr, amt) = (deposit.receiver, deposit.amount);

                root = credit(&receiver_addr, &entry.receiver_witness, amt, root)?;
                inbox_chain = accumulate_deposit(&inbox_chain, &receiver_addr, amt);
            }
            (Transaction::Withdrawal(withdrawal), TxnSidecar::Withdrawal(entry)) => {
                let (sender_addr, recipient, amt) = (
                    withdrawal.header.sender,
                    withdrawal.recipient,
                    withdrawal.amount,
                );

                // Checked before the debit so that an unpayable withdrawal is rejected on its own
                // terms, rather than incidentally by the sender happening to be short.
                if amt < MIN_WITHDRAWAL {
                    return Err(VerificationError::WithdrawalTooSmall);
                }

                root = debit(
                    &sender_addr,
                    &entry.sender_witness,
                    &entry.sig,
                    amt,
                    root,
                    |nonce| withdrawal.bytes_to_sign(domain, nonce),
                )?;

                payouts.push((recipient, amt));
            }
            (Transaction::ForcedWithdrawal(forced), TxnSidecar::ForcedWithdrawal(entry)) => {
                let (address, recipient) = (forced.header.sender, forced.recipient);

                // Checked before the balance is read, and that is what makes the balance
                // trustworthy: a witness that misreports it cannot reproduce the running root, so
                // the amount paid out is as pinned as if it had been written on the wire.
                expect_pre_state(&address, &entry.sender_witness, root)?;
                let balance = entry
                    .sender_witness
                    .old_account
                    .map_or(0, |account| account.amount);

                // Below the minimum there is nothing L1 could pay out -- an inner payment that
                // small fails against an account that does not yet exist -- so the request is
                // consumed without effect. This is the one case a request does not move value, and
                // it is determined by the witnessed pre-state rather than chosen by the prover.
                // A request against an address holding no account at all lands here too, with a
                // balance of zero.
                if balance >= MIN_WITHDRAWAL {
                    let mut account = entry
                        .sender_witness
                        .old_account
                        .ok_or(VerificationError::UnknownSender)?;
                    account.amount = 0;
                    // Bumped even though nothing was signed for this transaction. The account
                    // survives at zero rather than leaving the tree, and its nonce moves, so a
                    // payment its owner signed earlier cannot be held back and replayed against a
                    // balance somebody deposits later.
                    account.bump_nonce()?;
                    root = root_with(&address, Some(&account), &entry.sender_witness.proof)?;

                    payouts.push((recipient, balance));
                }

                // Folded either way. A request the batch could not pay is still a request the batch
                // answered, and leaving it unconsumed would wedge the rollup on an account that can
                // never be worth enough to empty.
                inbox_chain = accumulate_request(&inbox_chain, &address, &recipient);
            }
            _ => return Err(VerificationError::SidecarKindMismatch),
        }
    }

    Ok((root, inbox_chain, withdrawal_chain(domain, &payouts)))
}

/// Every payout a batch queues on L1, in the order it queues them.
///
/// A reporting function, not a checking one: [`verify_batch`] has already decided what is valid, and
/// this reads the same decisions back out for whoever has to act on them. The sequencer needs it
/// because it has to make each of these payouts on L1 before the next batch may open, and a
/// [`ForcedWithdrawal`]'s amount is not on the wire -- it is the balance its witness reveals. Feed
/// the result to [`withdrawal_links`] to get the calls themselves.
///
/// The `MIN_WITHDRAWAL` condition is repeated from the forced-withdrawal arm of [`verify_batch`],
/// which is a duplication worth being uneasy about. What keeps the two honest is that folding
/// [`withdrawal_chain`] over this list has to reproduce the chain that arm computed, and a test
/// asserts exactly that for every scenario.
///
/// Garbage in, garbage out: pair a batch with a sidecar that never verified and the amounts are
/// whatever that sidecar claimed.
pub fn withdrawal_payouts(batch: &Batch, sidecar: &Sidecar) -> Vec<(L1Address, u64)> {
    batch
        .txns
        .iter()
        .zip(&sidecar.entries)
        .filter_map(|(txn, entry)| match (txn, entry) {
            (Transaction::Withdrawal(withdrawal), _) => {
                Some((withdrawal.recipient, withdrawal.amount))
            }
            (Transaction::ForcedWithdrawal(forced), TxnSidecar::ForcedWithdrawal(entry)) => {
                let balance = entry
                    .sender_witness
                    .old_account
                    .map_or(0, |account| account.amount);

                (balance >= MIN_WITHDRAWAL).then_some((forced.recipient, balance))
            }
            _ => None,
        })
        .collect()
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
pub fn chunk_accumulator_seed(domain: &DeploymentDomain, batch_len: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BATCH");
    hasher.update(domain);
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
pub fn batch_commitment(domain: &DeploymentDomain, batch_bytes: &[u8]) -> [u8; 32] {
    let mut accumulator = chunk_accumulator_seed(domain, batch_bytes.len());

    for chunk in batch_bytes.chunks(CHUNK_SIZE) {
        accumulator = accumulate_chunk(&accumulator, &chunk_digest(chunk));
    }

    accumulator
}

pub const PUBLIC_VALUES_SIZE: usize = 32 * 6;

/// What a proof exposes: the two roots, batch commitment, unified inbox endpoints, and the
/// withdrawal chain.
///
/// ```text
/// [  0.. 32)  old_root
/// [ 32.. 64)  new_root
/// [ 64.. 96)  batch_commitment
/// [ 96..128)  old_inbox_chain
/// [128..160)  new_inbox_chain
/// [160..192)  withdrawal_chain
/// ```
///
/// Laid out here so the guest and the settlement contract read the same 192 bytes the same way. The
/// contract's side is: check `old_root` against the root it has stored, check the commitment
/// against a hash of the batch bytes it was handed across the preceding transactions, check both
/// inbox-chain ends against what it has recorded, verify the proof,
/// store `new_root`, and store the withdrawal chain unless it is already the terminal.
///
/// One chain preserves the global L1 order between deposits and forced withdrawals. It makes a
/// batch credit exactly what L1 accepted and answer every forced withdrawal in that same order.
///
/// The commitment check is what makes the data available: the bytes have to be presented to the
/// contract, not merely promised, or the root advances with nothing to reconstruct state from. The
/// two inbox-chain checks are what make the batch's L1 items exactly L1's; see
/// [`accumulate_deposit`]. Both ends are pinned rather than just the last, so a prover cannot pick
/// an anchor that makes a fabricated fold land correctly.
///
/// The withdrawal chain needs no count beside it and no nullifiers on L1. Its own structure carries
/// both: the contract walks it one payout at a time, a payout's position in the chain is what makes
/// it unrepeatable, and reaching [`withdrawal_chain_terminal`] is what says there are no more.
pub fn public_values(
    domain: &DeploymentDomain,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    batch_bytes: &[u8],
    old_inbox_chain: &[u8; 32],
    new_inbox_chain: &[u8; 32],
    withdrawal_chain: &[u8; 32],
) -> [u8; PUBLIC_VALUES_SIZE] {
    let mut buf = [0u8; PUBLIC_VALUES_SIZE];

    buf[..32].copy_from_slice(old_root);
    buf[32..64].copy_from_slice(new_root);
    buf[64..96].copy_from_slice(&batch_commitment(domain, batch_bytes));
    buf[96..128].copy_from_slice(old_inbox_chain);
    buf[128..160].copy_from_slice(new_inbox_chain);
    buf[160..192].copy_from_slice(withdrawal_chain);

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
/// and `inbox_anchor`, and lay out the public values. The guest is a wrapper that reads its five
/// inputs, calls this, and commits what comes back -- so there is one implementation of "what this
/// proof says", and a host can reach the committed values without proving anything.
///
/// Note there is still no expected root among the inputs, and for the same reason no expected
/// inbox chain. The replay reports where it landed on both, and the settlement contract is the
/// only thing that decides whether those are the values it was holding.
pub fn execute(
    domain: DeploymentDomain,
    old_root: [u8; 32],
    inbox_anchor: [u8; 32],
    batch_bytes: &[u8],
    sidecar_bytes: &[u8],
) -> Result<[u8; PUBLIC_VALUES_SIZE], ExecutionError> {
    let batch = Batch::decode(batch_bytes)?;
    let sidecar = Sidecar::decode(sidecar_bytes, &batch)?;

    let (new_root, new_inbox_chain, withdrawal_chain) =
        verify_batch(&domain, old_root, inbox_anchor, &batch, &sidecar)?;

    Ok(public_values(
        &domain,
        &old_root,
        &new_root,
        batch_bytes,
        &inbox_anchor,
        &new_inbox_chain,
        &withdrawal_chain,
    ))
}

/// Replay a whole [`Block`] and check it reaches its claimed roots and inbox chain.
///
/// The sequencer-side convenience wrapper around [`verify_batch`]: a block already carries the
/// values it claims, so this is the one place `RootMismatch` can come from. The guest calls
/// [`verify_batch`] directly and lets the settlement contract make the comparison.
pub fn verify_block(block: &Block) -> Result<(), VerificationError> {
    let (root, inbox_chain, withdrawal_chain) = verify_batch(
        &block.domain,
        block.old_root,
        block.old_inbox_chain,
        &block.batch,
        &block.sidecar,
    )?;

    if root == block.new_root
        && inbox_chain == block.new_inbox_chain
        && withdrawal_chain == block.withdrawal_chain
    {
        Ok(())
    } else {
        Err(VerificationError::RootMismatch)
    }
}

pub struct Ledger {
    domain: DeploymentDomain,
    accounts: HashMap<Address, Account>,
    /// Commitment to `accounts`, kept in step with every write so [`Ledger::state_root`] is always
    /// current.
    tree: SparseMerkleTree,
    /// Fold over every L1 inbox item this ledger has applied. Never reset across blocks.
    inbox_chain: [u8; 32],
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

impl Ledger {
    /// An empty ledger in the all-zero domain, primarily useful for domain-agnostic state tests.
    /// Deployment code should use [`Ledger::with_domain`].
    pub fn new() -> Self {
        Self::with_domain([0u8; 32])
    }

    pub fn with_domain(domain: DeploymentDomain) -> Self {
        Self {
            domain,
            accounts: HashMap::new(),
            tree: SparseMerkleTree::new(),
            inbox_chain: INBOX_CHAIN_GENESIS,
        }
    }

    pub fn domain(&self) -> DeploymentDomain {
        self.domain
    }

    /// The inbox chain as it stands, which is what the next block will anchor to.
    pub fn inbox_chain(&self) -> [u8; 32] {
        self.inbox_chain
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
        // Copied out because the signature checks below run inside a mutable borrow of the ledger,
        // and the domain is part of every message a signature covers.
        let domain = self.domain;
        let old_root = self.state_root();
        let old_inbox_chain = self.inbox_chain;
        let mut payouts = Vec::new();
        let mut txns = Vec::with_capacity(stxns.len());
        let mut entries = Vec::with_capacity(stxns.len());

        for stxn in stxns {
            let txn = match stxn {
                SignedTransaction::Payment { payment, sig } => {
                    let sender_witness =
                        self.debit(payment.header.sender, payment.amount, &sig, |nonce| {
                            payment.bytes_to_sign(&domain, nonce)
                        });

                    // Captured after the sender write, so a self-payment witnesses the debited balance.
                    let receiver_witness = self.credit(payment.receiver, payment.amount);

                    entries.push(TxnSidecar::Payment(PaymentSidecar {
                        sig,
                        sender_witness,
                        receiver_witness,
                    }));

                    Transaction::Payment(payment)
                }
                SignedTransaction::Deposit { deposit } => {
                    let receiver_witness = self.credit(deposit.receiver, deposit.amount);

                    self.inbox_chain =
                        accumulate_deposit(&self.inbox_chain, &deposit.receiver, deposit.amount);

                    entries.push(TxnSidecar::Deposit(DepositSidecar { receiver_witness }));

                    Transaction::Deposit(deposit)
                }
                SignedTransaction::Withdrawal { withdrawal, sig } => {
                    assert!(
                        withdrawal.amount >= MIN_WITHDRAWAL,
                        "a withdrawal below MIN_WITHDRAWAL could not be paid out on L1",
                    );

                    let sender_witness =
                        self.debit(withdrawal.header.sender, withdrawal.amount, &sig, |nonce| {
                            withdrawal.bytes_to_sign(&domain, nonce)
                        });

                    payouts.push((withdrawal.recipient, withdrawal.amount));

                    entries.push(TxnSidecar::Withdrawal(WithdrawalSidecar {
                        sig,
                        sender_witness,
                    }));

                    Transaction::Withdrawal(withdrawal)
                }
                SignedTransaction::ForcedWithdrawal { forced } => {
                    let address = forced.header.sender;

                    let sender_witness = LeafWitness {
                        old_account: self.accounts.get(&address).copied(),
                        proof: self.tree.proof(&address),
                    };

                    // Whatever is there, which is what the request asked for. Mirrors the
                    // forced-withdrawal arm of `verify_batch`, including its one drop case.
                    let balance = self
                        .accounts
                        .get(&address)
                        .map_or(0, |account| account.amount());

                    if balance >= MIN_WITHDRAWAL {
                        let account = self.accounts.get_mut(&address).unwrap();
                        account.amount = 0;
                        account.bump_nonce().unwrap();
                        let account = *account;
                        self.tree.update(&address, Some(&account));

                        payouts.push((forced.recipient, balance));
                    }

                    self.inbox_chain =
                        accumulate_request(&self.inbox_chain, &address, &forced.recipient);

                    entries.push(TxnSidecar::ForcedWithdrawal(ForcedWithdrawalSidecar {
                        sender_witness,
                    }));

                    Transaction::ForcedWithdrawal(forced)
                }
            };

            txns.push(txn);
        }

        Block {
            domain: self.domain,
            old_root,
            new_root: self.state_root(),
            old_inbox_chain,
            new_inbox_chain: self.inbox_chain,
            withdrawal_chain: withdrawal_chain(&self.domain, &payouts),
            batch: Batch { txns },
            sidecar: Sidecar { entries },
        }
    }

    /// Debit `amount` from `sender`, returning the witness for the slot as it stood beforehand.
    ///
    /// Mirrors the free-standing [`debit`] on the verifying side, down to the order the checks are
    /// made in and the nonce the signature is checked against, and like [`Ledger::credit`] captures
    /// the witness before the write and after everything preceding it.
    ///
    /// Panics rather than returning an error, as the rest of this path does: a sequencer is assumed
    /// to only build blocks it has already decided are valid. Checking the signature here rather
    /// than trusting the submitter is what makes that assumption true -- a block whose signatures do
    /// not verify cannot be proved, so the useful place to find out is while it is being built.
    fn debit(
        &mut self,
        sender: Address,
        amount: u64,
        sig: &Signature,
        bytes_to_sign: impl FnOnce(u64) -> [u8; ENCODED_TX_SIZE],
    ) -> LeafWitness {
        let witness = LeafWitness {
            old_account: self.accounts.get(&sender).copied(),
            proof: self.tree.proof(&sender),
        };

        let account = self.accounts.get_mut(&sender).unwrap();
        account.bump_nonce().unwrap();
        sig.verify(account, &bytes_to_sign(account.nonce)).unwrap();
        account.amount = account.amount.checked_sub(amount).unwrap();
        let account = *account;
        self.tree.update(&sender, Some(&account));

        witness
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
    const TEST_DOMAIN: DeploymentDomain = [0x42; 32];

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
            other => panic!("entry {index} is {other:?}, not a payment"),
        }
    }

    /// A withdrawal of `amount` to `recipient` on L1, from the account for `key`, signed by `key`.
    fn withdrawal(key: &[u8], recipient: L1Address, amount: u64) -> SignedTransaction {
        SignedTransaction::withdrawal(
            Withdrawal::new(address_from_public_key(SCHEME, key), recipient, amount),
            signature(key),
        )
    }

    /// An L1 address, which is only ever 32 opaque bytes to this crate.
    fn l1(seed: u8) -> L1Address {
        [seed; 32]
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
                &block.domain,
                block.old_root,
                block.old_inbox_chain,
                &block.batch,
                &block.sidecar
            ),
            Err(VerificationError::SidecarLengthMismatch)
        );
    }

    // The settlement contract reads these 192 bytes by offset, so the layout is as load-bearing as
    // the roots themselves.
    #[test]
    fn public_values_lay_out_the_transition_and_the_batch_commitment() {
        let (block, ..) = three_txn_block();
        let batch_bytes = block.batch().encode();

        let values = public_values(
            &block.domain(),
            &block.old_root(),
            &block.new_root(),
            &batch_bytes,
            &block.old_inbox_chain(),
            &block.new_inbox_chain(),
            &block.withdrawal_chain(),
        );

        assert_eq!(values.len(), PUBLIC_VALUES_SIZE);
        assert_eq!(&values[..32], &block.old_root());
        assert_eq!(&values[32..64], &block.new_root());
        assert_eq!(
            &values[64..96],
            &batch_commitment(&block.domain(), &batch_bytes)
        );
        assert_eq!(&values[96..128], &block.old_inbox_chain());
        assert_eq!(&values[128..160], &block.new_inbox_chain());
        assert_eq!(&values[160..192], &block.withdrawal_chain());

        // The commitment is domain-separated and covers every byte, so a batch that differs
        // anywhere cannot be presented against this proof.
        let mut tampered = batch_bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_ne!(
            batch_commitment(&block.domain(), &tampered),
            batch_commitment(&block.domain(), &batch_bytes)
        );
    }

    /// What a settlement contract does: seed from the declared length, fold each chunk as it
    /// arrives, and end up with something to compare against the proof's public values.
    fn accumulate_as_a_contract_would(domain: &DeploymentDomain, batch_bytes: &[u8]) -> [u8; 32] {
        let mut accumulator = chunk_accumulator_seed(domain, batch_bytes.len());
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
    fn an_empty_batch_leaves_the_inbox_chain_unchanged() {
        let block = Ledger::new().get_block(vec![]);

        assert_eq!(block.old_inbox_chain(), INBOX_CHAIN_GENESIS);
        assert_eq!(block.new_inbox_chain(), block.old_inbox_chain());
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
            &posted.new_inbox_chain(),
            &address_from_public_key(SCHEME, b"b key"),
            500,
        );

        assert_ne!(posted.new_inbox_chain(), contract_chain);
    }

    #[test]
    fn the_inbox_chain_pins_deposit_order() {
        let ab = Ledger::new()
            .get_block(vec![deposit(b"a key", 1_000), deposit(b"b key", 500)])
            .new_inbox_chain();
        let ba = Ledger::new()
            .get_block(vec![deposit(b"b key", 500), deposit(b"a key", 1_000)])
            .new_inbox_chain();

        assert_ne!(ab, ba);
    }

    #[test]
    fn the_inbox_chain_pins_deposit_count() {
        let one = Ledger::new()
            .get_block(vec![deposit(b"a key", 1_000)])
            .new_inbox_chain();
        let two = Ledger::new()
            .get_block(vec![deposit(b"a key", 1_000), deposit(b"a key", 1_000)])
            .new_inbox_chain();

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
            &INBOX_CHAIN_GENESIS,
            &address_from_public_key(SCHEME, b"a key"),
            1_000,
        );

        assert_ne!(first, block.new_inbox_chain());
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
        assert_ne!(forged.new_inbox_chain(), real.new_inbox_chain());
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
                &block.domain,
                block.old_root,
                block.old_inbox_chain,
                &block.batch,
                &block.sidecar
            ),
            Err(VerificationError::SidecarKindMismatch)
        );
    }

    #[test]
    fn a_withdrawal_debits_the_sender_and_credits_nobody() {
        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", 1_000_000);

        let block = ledger.get_block(vec![withdrawal(b"a key", l1(7), 400_000)]);

        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(ledger.account(&a).unwrap().amount(), 600_000);
        // The debit is authorized by a signature, so it bumps the nonce like any other spend.
        assert_eq!(ledger.account(&a).unwrap().nonce(), 1);
        // Nothing in the tree received the funds: the recipient is an L1 address and has no slot.
        assert_eq!(block.batch().txns()[0].receiver(), None);
    }

    #[test]
    fn a_withdrawal_below_the_minimum_does_not_verify() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 1_000_000);

        // Built by hand: `get_block` refuses to sequence one at all, so this is the shape only a
        // hostile sequencer could produce.
        let mut block = ledger.get_block(vec![withdrawal(b"a key", l1(7), MIN_WITHDRAWAL)]);
        let Transaction::Withdrawal(w) = &mut block.batch.txns[0] else {
            panic!("the fixture block is a single withdrawal")
        };
        w.amount = MIN_WITHDRAWAL - 1;

        assert_eq!(
            verify_batch(
                &block.domain,
                block.old_root,
                block.old_inbox_chain,
                &block.batch,
                &block.sidecar
            ),
            Err(VerificationError::WithdrawalTooSmall)
        );
    }

    #[test]
    fn a_withdrawal_cannot_spend_more_than_the_account_holds() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 1_000_000);
        let mut block = ledger.get_block(vec![withdrawal(b"a key", l1(7), 100_000)]);

        let Transaction::Withdrawal(w) = &mut block.batch.txns[0] else {
            panic!("the fixture block is a single withdrawal")
        };
        w.amount = 2_000_000;

        assert_eq!(
            verify_block(&block),
            Err(VerificationError::InsufficientFunds)
        );
    }

    // A withdrawal is the inverse of a deposit, and the ledger has to balance either way: what a
    // block mints must equal what L1 accepted, and what it burns must equal what L1 will pay out.
    #[test]
    fn a_block_can_deposit_pay_and_withdraw_at_once() {
        let mut ledger = Ledger::new();
        let b = address_from_public_key(SCHEME, b"b key");

        let block = ledger.get_block(vec![
            deposit(b"a key", 1_000_000),
            stxn(b"a key", b, 400_000),
            withdrawal(b"b key", l1(9), 250_000),
        ]);

        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(
            ledger
                .account(&address_from_public_key(SCHEME, b"a key"))
                .unwrap()
                .amount(),
            600_000
        );
        assert_eq!(ledger.account(&b).unwrap().amount(), 150_000);

        // Both commitments moved, and neither is the other's.
        assert_ne!(block.new_inbox_chain(), block.old_inbox_chain());
        assert_ne!(
            block.withdrawal_chain(),
            withdrawal_chain_terminal(&block.domain())
        );
        assert_ne!(block.withdrawal_chain(), block.new_inbox_chain());
    }

    #[test]
    fn the_domain_separates_identical_payouts_between_deployments() {
        let mut first_ledger = Ledger::with_domain([1u8; 32]);
        let mut second_ledger = Ledger::with_domain([2u8; 32]);
        fund(&mut first_ledger, b"a key", 10_000_000);
        fund(&mut second_ledger, b"a key", 10_000_000);

        let first = first_ledger.get_block(vec![withdrawal(b"a key", l1(1), 100_000)]);
        let second = second_ledger.get_block(vec![withdrawal(b"a key", l1(1), 100_000)]);

        assert_eq!(first.batch().encode(), second.batch().encode());
        assert_ne!(first.withdrawal_chain(), second.withdrawal_chain());
    }

    #[test]
    fn a_block_with_no_withdrawals_lands_on_the_terminal() {
        let block = Ledger::new().get_block(vec![deposit(b"a key", 1_000)]);

        assert_eq!(
            block.withdrawal_chain(),
            withdrawal_chain_terminal(&block.domain())
        );
        assert_eq!(verify_block(&block), Ok(()));
    }

    // The whole of what the settlement contract does, in the order it does it: hold the head, take
    // the next link, check it reproduces the head, and step to its tail. Reaching the terminal after
    // exactly as many steps as there were payouts is what says the chain committed those payouts and
    // no others.
    #[test]
    fn the_links_walk_the_chain_from_its_head_to_the_terminal() {
        let payouts = [(l1(1), 100_000u64), (l1(2), 250_000), (l1(3), 999_999)];
        let links = withdrawal_links(&TEST_DOMAIN, &payouts);

        assert_eq!(links.len(), payouts.len());

        let mut head = withdrawal_chain(&TEST_DOMAIN, &payouts);
        for (link, (recipient, amount)) in links.iter().zip(&payouts) {
            assert_eq!(link.recipient, *recipient);
            assert_eq!(link.amount, *amount);
            assert_eq!(
                accumulate_withdrawal(&link.tail, &link.recipient, link.amount),
                head,
                "the link does not reproduce the head the contract is holding"
            );
            head = link.tail;
        }

        assert_eq!(head, withdrawal_chain_terminal(&TEST_DOMAIN));
    }

    // A payout can only be made against the head, so offering the second link while the first is
    // still outstanding has to fail -- this is what replaces the claim bitmap. It is also what makes
    // a payout unrepeatable: once the head has stepped past a link, that link never matches again.
    #[test]
    fn a_link_only_matches_the_head_it_belongs_to() {
        let payouts = [(l1(1), 100_000u64), (l1(2), 250_000)];
        let head = withdrawal_chain(&TEST_DOMAIN, &payouts);
        let links = withdrawal_links(&TEST_DOMAIN, &payouts);

        // Out of order.
        assert_ne!(
            accumulate_withdrawal(&links[1].tail, &links[1].recipient, links[1].amount),
            head
        );
        // Replayed after the head has moved on.
        assert_ne!(
            accumulate_withdrawal(&links[0].tail, &links[0].recipient, links[0].amount),
            links[0].tail
        );
        // Right position, wrong recipient or amount.
        assert_ne!(
            accumulate_withdrawal(&links[0].tail, &l1(9), links[0].amount),
            head
        );
        assert_ne!(
            accumulate_withdrawal(&links[0].tail, &links[0].recipient, links[0].amount + 1),
            head
        );
    }

    #[test]
    fn empty_and_single_withdrawal_chains_are_canonical() {
        assert_eq!(
            withdrawal_chain(&TEST_DOMAIN, &[]),
            withdrawal_chain_terminal(&TEST_DOMAIN)
        );

        assert_eq!(
            withdrawal_chain(&TEST_DOMAIN, &[(l1(1), 100_000)]),
            accumulate_withdrawal(&withdrawal_chain_terminal(&TEST_DOMAIN), &l1(1), 100_000)
        );

        // A one-payout chain drains in a single step, so its only link points straight at the
        // terminal.
        assert_eq!(
            withdrawal_links(&TEST_DOMAIN, &[(l1(1), 100_000)])[0].tail,
            withdrawal_chain_terminal(&TEST_DOMAIN)
        );
    }

    #[test]
    fn the_withdrawal_chain_pins_domain_recipient_amount_and_order() {
        let a = [(l1(1), 100_000), (l1(2), 200_000)];
        let b = [(l1(2), 200_000), (l1(1), 100_000)];

        assert_ne!(
            withdrawal_chain(&[1; 32], &a),
            withdrawal_chain(&[1; 32], &b)
        );
        assert_ne!(
            withdrawal_chain(&[1; 32], &[(l1(1), 100_000)]),
            withdrawal_chain(&[1; 32], &[(l1(1), 100_001)])
        );
        assert_ne!(
            withdrawal_chain(&[1; 32], &[(l1(1), 100_000)]),
            withdrawal_chain(&[1; 32], &[(l1(2), 100_000)])
        );
        assert_ne!(
            withdrawal_chain(&[1; 32], &a),
            withdrawal_chain(&[2; 32], &a)
        );

        // And a prefix is not the whole: dropping the last payout cannot reach the same head, which
        // is what stops a sequencer stopping short of the chain it committed.
        assert_ne!(
            withdrawal_chain(&[1; 32], &a),
            withdrawal_chain(&[1; 32], &a[..1])
        );
    }

    // Without the tags a payment and a withdrawal of the same amount, from the same sender at the
    // same nonce, to the same 32 bytes, would produce identical preimages -- so one signature would
    // authorize either, and a payment could be replayed as a withdrawal out of the rollup.
    #[test]
    fn a_payment_and_a_withdrawal_never_sign_the_same_bytes() {
        let sender = address_from_public_key(SCHEME, b"a key");
        let destination = [9u8; 32];

        let payment = Payment::new(sender, destination, 100_000);
        let withdrawal = Withdrawal::new(sender, destination, 100_000);
        let payment_message = payment.bytes_to_sign(&TEST_DOMAIN, 3);

        assert_eq!(&payment_message[..3], b"PAY");
        assert_eq!(&payment_message[3..35], &TEST_DOMAIN);
        assert_eq!(&payment_message[35..67], &sender);
        assert_eq!(&payment_message[67..75], &3u64.to_be_bytes());
        assert_eq!(&payment_message[75..107], &destination);
        assert_eq!(&payment_message[107..], &100_000u64.to_be_bytes());

        assert_ne!(payment_message, withdrawal.bytes_to_sign(&TEST_DOMAIN, 3));
        // And the nonce still separates two otherwise identical transactions of the same kind.
        assert_ne!(
            withdrawal.bytes_to_sign(&TEST_DOMAIN, 3),
            withdrawal.bytes_to_sign(&TEST_DOMAIN, 4)
        );
        assert_ne!(
            payment.bytes_to_sign(&TEST_DOMAIN, 3),
            payment.bytes_to_sign(&[0x43; 32], 3)
        );
    }

    #[test]
    fn deployment_domain_derivation_is_stable() {
        assert_eq!(
            deployment_domain(&[0u8; 32], 7),
            [
                0x45, 0x91, 0x15, 0xf1, 0xbe, 0x8e, 0x47, 0x7f, 0x1e, 0x20, 0x0d, 0x70, 0x2a, 0xc5,
                0xf9, 0xc5, 0x64, 0x3f, 0xf4, 0x30, 0xc3, 0x10, 0xd3, 0xff, 0x44, 0xb0, 0x62, 0x73,
                0xcb, 0x5d, 0xaa, 0x15,
            ]
        );
        assert_ne!(
            deployment_domain(&[0u8; 32], 7),
            deployment_domain(&[0u8; 32], 8)
        );
    }

    /// A withdrawal L1 ordered, emptying the account for `key` to `recipient`.
    fn forced(key: &[u8], recipient: L1Address) -> SignedTransaction {
        SignedTransaction::forced_withdrawal(ForcedWithdrawal::new(
            address_from_public_key(SCHEME, key),
            recipient,
        ))
    }

    #[test]
    fn a_forced_withdrawal_empties_the_account() {
        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", 1_000_000);

        let block = ledger.get_block(vec![forced(b"a key", l1(7))]);

        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(ledger.account(&a).unwrap().amount(), 0);
        // The account stays in the tree with its nonce advanced, so a payment its owner signed
        // earlier cannot be held back and replayed against a balance somebody deposits later.
        assert_eq!(ledger.account(&a).unwrap().nonce(), 1);
        // The payout is queued for the whole balance, without the amount ever being on the wire.
        assert_eq!(block.batch().txns()[0].amount(), None);
        assert_eq!(
            block.withdrawal_chain(),
            withdrawal_chain(&block.domain(), &[(l1(7), 1_000_000)])
        );
    }

    // There is no cap on how many payouts one block may commit -- the claim bitmap that used to
    // impose one is gone -- so a backlog of forced withdrawals larger than any old limit is
    // answerable in a single block. What bounds it now is only that the sequencer has to make every
    // one of these payouts on L1 before its next block may open.
    #[test]
    fn one_block_can_answer_a_large_forced_withdrawal_backlog() {
        let mut ledger = Ledger::new();
        let keys: Vec<_> = (0..300)
            .map(|index| format!("forced account {index}").into_bytes())
            .collect();

        for key in &keys {
            fund(&mut ledger, key, MIN_WITHDRAWAL);
        }

        let block = ledger.get_block(keys.iter().map(|key| forced(key, l1(1))).collect());

        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(block.old_inbox_chain(), INBOX_CHAIN_GENESIS);
        assert_ne!(block.new_inbox_chain(), block.old_inbox_chain());
        assert_eq!(
            withdrawal_links(
                &block.domain(),
                &withdrawal_payouts(block.batch(), block.sidecar())
            )
            .len(),
            keys.len()
        );
    }

    // The property the whole mechanism exists for. An ordinary withdrawal can be dropped by the
    // sequencer and nothing outside would know; a forced one leaves the chain short of what L1 is
    // holding, so no batch settles again until it is answered.
    #[test]
    fn a_batch_that_ignores_a_request_lands_short_of_the_chain() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 1_000_000);

        // What L1 holds once it has accepted one request.
        let demanded = accumulate_request(
            &INBOX_CHAIN_GENESIS,
            &address_from_public_key(SCHEME, b"a key"),
            &l1(7),
        );

        // A batch that quietly does something else instead.
        let evasive = ledger.get_block(vec![stxn(b"a key", l1(3), 500_000)]);

        assert_eq!(verify_block(&evasive), Ok(()));
        assert_eq!(evasive.new_inbox_chain(), INBOX_CHAIN_GENESIS);
        assert_ne!(evasive.new_inbox_chain(), demanded);
    }

    #[test]
    fn the_inbox_chain_pins_request_account_recipient_and_order() {
        let (a, b) = (
            address_from_public_key(SCHEME, b"a key"),
            address_from_public_key(SCHEME, b"b key"),
        );

        let ab = accumulate_request(
            &accumulate_request(&INBOX_CHAIN_GENESIS, &a, &l1(1)),
            &b,
            &l1(2),
        );
        let ba = accumulate_request(
            &accumulate_request(&INBOX_CHAIN_GENESIS, &b, &l1(2)),
            &a,
            &l1(1),
        );

        assert_ne!(ab, ba, "order must be committed to");
        assert_ne!(
            accumulate_request(&INBOX_CHAIN_GENESIS, &a, &l1(1)),
            accumulate_request(&INBOX_CHAIN_GENESIS, &b, &l1(1)),
            "the account must be committed to"
        );
        assert_ne!(
            accumulate_request(&INBOX_CHAIN_GENESIS, &a, &l1(1)),
            accumulate_request(&INBOX_CHAIN_GENESIS, &a, &l1(2)),
            "the recipient must be committed to"
        );
    }

    // The one case a request does not move value, and the reason it still has to be consumed:
    // leaving it pending would wedge the rollup on an account that can never be worth emptying.
    #[test]
    fn a_request_against_a_dust_balance_is_consumed_without_a_payout() {
        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", MIN_WITHDRAWAL - 1);

        let block = ledger.get_block(vec![forced(b"a key", l1(7))]);

        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(
            block.withdrawal_chain(),
            withdrawal_chain_terminal(&block.domain())
        );
        assert_ne!(block.new_inbox_chain(), block.old_inbox_chain());
        // Untouched, including the nonce -- nothing happened to it.
        assert_eq!(ledger.account(&a).unwrap().amount(), MIN_WITHDRAWAL - 1);
        assert_eq!(ledger.account(&a).unwrap().nonce(), 0);
    }

    #[test]
    fn a_request_against_an_account_that_does_not_exist_is_consumed() {
        let mut ledger = Ledger::new();
        let block = ledger.get_block(vec![forced(b"never funded", l1(7))]);

        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(block.old_root(), block.new_root());
        assert_eq!(
            block.withdrawal_chain(),
            withdrawal_chain_terminal(&block.domain())
        );
        assert_ne!(block.new_inbox_chain(), block.old_inbox_chain());
    }

    // The witness decides the payout here, which is a job it does nowhere else. It is safe for the
    // usual reason -- it is pinned to the running root before it is read -- and this is the test
    // that says so.
    #[test]
    fn a_forced_withdrawal_cannot_understate_the_balance_it_pays_out() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 1_000_000);
        let mut block = ledger.get_block(vec![forced(b"a key", l1(7))]);

        // Claim the account held dust, so the payout would be suppressed and the balance left
        // behind for the sequencer to keep custody of.
        let TxnSidecar::ForcedWithdrawal(entry) = &mut block.sidecar.entries[0] else {
            panic!("the fixture block is a single forced withdrawal")
        };
        entry.sender_witness.old_account = Some(account_at(b"a key", 0, 1).1);

        assert_eq!(verify_block(&block), Err(VerificationError::StaleWitness));
    }

    #[test]
    fn a_forced_withdrawal_cannot_overstate_the_balance_it_pays_out() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 1_000_000);
        let mut block = ledger.get_block(vec![forced(b"a key", l1(7))]);

        let TxnSidecar::ForcedWithdrawal(entry) = &mut block.sidecar.entries[0] else {
            panic!("the fixture block is a single forced withdrawal")
        };
        entry.sender_witness.old_account = Some(account_at(b"a key", 0, 9_000_000).1);

        assert_eq!(verify_block(&block), Err(VerificationError::StaleWitness));
    }

    // Deposits and requests share one L1-ordered chain, so swapping their kinds must change it.
    #[test]
    fn cross_kind_order_changes_the_inbox_chain() {
        let address = address_from_public_key(SCHEME, b"a key");
        let deposit_then_request = accumulate_request(
            &accumulate_deposit(&INBOX_CHAIN_GENESIS, &address, 1_000_000),
            &address,
            &l1(7),
        );
        let request_then_deposit = accumulate_deposit(
            &accumulate_request(&INBOX_CHAIN_GENESIS, &address, &l1(7)),
            &address,
            1_000_000,
        );

        assert_ne!(deposit_then_request, request_then_deposit);

        let mut ledger = Ledger::new();
        let block = ledger.get_block(vec![deposit(b"a key", 1_000_000), forced(b"a key", l1(7))]);
        assert_eq!(verify_block(&block), Ok(()));
        assert_eq!(block.new_inbox_chain(), deposit_then_request);
        // Deposited and emptied in the same batch, so the payout is the whole deposit.
        assert_eq!(
            block.withdrawal_chain(),
            withdrawal_chain(&block.domain(), &[(l1(7), 1_000_000)])
        );
    }

    // `withdrawal_payouts` repeats the drop rule from `verify_batch`, so the two have to be held
    // together by something. This is that something: the reported payouts have to reproduce the
    // chain the replay committed.
    #[test]
    fn the_reported_payouts_reproduce_the_committed_chain() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"rich", 5_000_000);
        fund(&mut ledger, b"dust", MIN_WITHDRAWAL - 1);
        let b = address_from_public_key(SCHEME, b"b key");

        // The forced withdrawal of `rich` comes last, because it leaves nothing behind to spend.
        let block = ledger.get_block(vec![
            withdrawal(b"rich", l1(1), 250_000),
            forced(b"dust", l1(2)),
            stxn(b"rich", b, 1),
            forced(b"rich", l1(3)),
        ]);

        assert_eq!(verify_block(&block), Ok(()));

        let payouts = withdrawal_payouts(block.batch(), block.sidecar());
        // The dust request queued nothing, so only two of the three withdrawals are payable.
        assert_eq!(payouts.len(), 2);

        assert_eq!(
            withdrawal_chain(&block.domain(), &payouts),
            block.withdrawal_chain()
        );

        // And the links built from them walk that chain to its terminal, which is the sequence of
        // calls L1 will actually accept.
        let mut head = block.withdrawal_chain();
        for link in withdrawal_links(&block.domain(), &payouts) {
            assert_eq!(
                accumulate_withdrawal(&link.tail, &link.recipient, link.amount),
                head
            );
            head = link.tail;
        }
        assert_eq!(head, withdrawal_chain_terminal(&block.domain()));
    }

    #[test]
    fn every_preimage_a_contract_must_hash_fits_in_one_avm_value() {
        let seed_preimage = b"BATCH".len() + 32 + size_of::<u64>();
        let digest_preimage = CHUNK_SIZE;
        let fold_preimage = b"CHUNK".len() + 32 + 32;
        let deposit_preimage = b"INBOXD".len() + 32 + 32 + size_of::<u64>();
        let withdrawal_terminal_preimage = b"WEND".len() + 32;
        let withdrawal_fold_preimage = b"WPAY".len() + 32 + 32 + size_of::<u64>();
        let request_preimage = b"INBOXW".len() + 32 + 32 + 32;

        for (name, len) in [
            ("seed", seed_preimage),
            ("chunk digest", digest_preimage),
            ("fold step", fold_preimage),
            ("deposit fold", deposit_preimage),
            ("withdrawal terminal", withdrawal_terminal_preimage),
            ("withdrawal fold", withdrawal_fold_preimage),
            ("request fold", request_preimage),
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
            accumulate_as_a_contract_would(&ledger.domain(), &batch_bytes),
            batch_commitment(&ledger.domain(), &batch_bytes),
            "the contract's fold must land where the guest's commitment did"
        );
    }

    #[test]
    fn a_partially_posted_batch_does_not_match() {
        let (block, ..) = three_txn_block();
        let batch_bytes = block.batch().encode();

        // Stopping one chunk short must not accumulate to the commitment, or a sequencer could
        // advance the root having published only part of the batch.
        let mut accumulator = chunk_accumulator_seed(&block.domain(), batch_bytes.len());
        let chunks: Vec<_> = batch_bytes.chunks(CHUNK_SIZE).collect();
        for chunk in &chunks[..chunks.len() - 1] {
            accumulator = accumulate_chunk(&accumulator, &chunk_digest(chunk));
        }

        assert_ne!(accumulator, batch_commitment(&block.domain(), &batch_bytes));
    }

    #[test]
    fn the_declared_length_pins_the_chunking() {
        let bytes = vec![0u8; CHUNK_SIZE + 1];

        // Two chunks, and re-cutting them is not open to the sequencer: the seed commits to the
        // total length, which fixes where every boundary falls.
        assert_eq!(chunk_count(bytes.len()), 2);
        assert_ne!(
            batch_commitment(&TEST_DOMAIN, &bytes),
            accumulate_chunk(
                &chunk_accumulator_seed(&TEST_DOMAIN, bytes.len()),
                &Sha256::digest(&bytes).into()
            ),
            "one oversized chunk must not reach the same commitment as the canonical two"
        );

        // And a batch of a different length starts from a different seed, so no two lengths share
        // an accumulator at any point.
        assert_ne!(
            chunk_accumulator_seed(&TEST_DOMAIN, bytes.len()),
            chunk_accumulator_seed(&TEST_DOMAIN, bytes.len() - 1)
        );
    }

    #[test]
    fn the_deployment_domain_pins_the_batch_commitment() {
        let bytes = b"same batch";
        assert_ne!(
            batch_commitment(&[1u8; 32], bytes),
            batch_commitment(&[2u8; 32], bytes)
        );
        assert_ne!(
            chunk_accumulator_seed(&[1u8; 32], bytes.len()),
            chunk_accumulator_seed(&[2u8; 32], bytes.len())
        );
    }

    #[test]
    fn chunk_counts_cover_the_boundaries() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_SIZE), 1);
        assert_eq!(chunk_count(CHUNK_SIZE + 1), 2);

        // An empty batch is the zero-step fold, which is just the seed.
        assert_eq!(
            batch_commitment(&TEST_DOMAIN, &[]),
            chunk_accumulator_seed(&TEST_DOMAIN, 0)
        );
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
