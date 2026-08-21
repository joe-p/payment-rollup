use std::collections::HashMap;

use sha2::{Digest, Sha256};

mod merkle;

pub use merkle::{MerkleProof, Slot, SparseMerkleTree, verify_proof};

pub type Address = [u8; 32];

const SCHEME_SIZE: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Ed25519,
    Falcon1024HybridEd25519,
}

impl Scheme {
    pub fn identifier(&self) -> [u8; SCHEME_SIZE] {
        match self {
            Scheme::Ed25519 => *b"edd",
            Scheme::Falcon1024HybridEd25519 => *b"f1h",
        }
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

const ENCODED_ACCOUNT_SIZE: usize = 8 + 8 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidAuthAddress,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    nonce: u64,
    amount: u64,
    auth_address: Address,
}

impl Account {
    fn new(nonce: u64, amount: u64, auth_address: Address) -> Self {
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

    fn update_nonce(&mut self, new_nonce: u64) -> Result<(), VerificationError> {
        if self.nonce >= new_nonce {
            return Err(VerificationError::InvalidNonce);
        }

        self.nonce = new_nonce;
        Ok(())
    }
}

pub struct TransactionHeader {
    sender: Address,
    nonce: u64,
}

pub struct Payment {
    header: TransactionHeader,
    receiver: Address,
    amount: u64,
}

impl Payment {
    pub fn bytes_to_sign(&self) -> [u8; ENCODED_TX_SIZE] {
        let mut buf = [0u8; ENCODED_TX_SIZE];
        let mut offset = 0;

        buf[offset..offset + self.header.sender.len()].copy_from_slice(&self.header.sender);
        offset += self.header.sender.len();

        let nonce_bytes = self.header.nonce.to_be_bytes();
        buf[offset..offset + nonce_bytes.len()].copy_from_slice(&nonce_bytes);
        offset += nonce_bytes.len();

        buf[offset..offset + self.receiver.len()].copy_from_slice(&self.receiver);
        offset += self.receiver.len();

        let amount_bytes = self.amount.to_be_bytes();
        buf[offset..offset + amount_bytes.len()].copy_from_slice(&amount_bytes);

        buf
    }
}

pub enum Transaction {
    Payment(Payment),
}

impl Transaction {
    pub fn sender(&self) -> Address {
        match self {
            Transaction::Payment(payment) => payment.header.sender,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Transaction::Payment(payment) => payment.header.nonce,
        }
    }

    pub fn receiver(&self) -> Address {
        match self {
            Transaction::Payment(payment) => payment.receiver,
        }
    }

    pub fn amount(&self) -> u64 {
        match self {
            Transaction::Payment(payment) => payment.amount,
        }
    }

    pub fn bytes_to_sign(&self) -> [u8; ENCODED_TX_SIZE] {
        match self {
            Transaction::Payment(payment) => payment.bytes_to_sign(),
        }
    }
}

pub struct Signature {
    scheme: Scheme,
    pub_key: Vec<u8>,
    sig: Vec<u8>,
}

impl Signature {
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

pub struct SignedTransaction {
    txn: Transaction,
    sig: Signature,
}

/// Everything a verifier needs to know about one leaf slot at the moment it is written.
///
/// `proof` serves twice: with `old_account` it pins the pre-state against the running root, and
/// with the computed post-state it yields the next root. The siblings are never checked directly
/// -- a witness carrying the wrong ones simply fails to reproduce the running root -- and neither
/// is the depth the proof implies, for the same reason. The one thing checked outright is a
/// [`Slot::Neighbor`]'s address, which has to be consistent with the path that reached it; see
/// [`merkle::root_from_proof`].
pub struct LeafWitness {
    /// State of the slot immediately before the write, or `None` for an empty slot.
    old_account: Option<Account>,
    proof: MerkleProof,
}

/// A transaction together with the two leaf slots it writes.
///
/// Pairing them in one struct is what makes a witness count mismatch unrepresentable: there is no
/// way to build a block whose witnesses have drifted out of step with its transactions.
pub struct SignedTransactionWithWitnesses {
    stxn: SignedTransaction,
    sender_witness: LeafWitness,
    receiver_witness: LeafWitness,
}

impl SignedTransactionWithWitnesses {
    pub fn stxn(&self) -> &SignedTransaction {
        &self.stxn
    }
}

/// A batch of transactions and the root transition they produce.
///
/// The witnesses make the transition verifiable by [`verify_block`] without any account state, so
/// a verifier holding nothing but these bytes can confirm that `old_root` becomes `new_root`.
pub struct Block {
    old_root: [u8; 32],
    new_root: [u8; 32],
    txns: Vec<SignedTransactionWithWitnesses>,
}

impl Block {
    pub fn old_root(&self) -> [u8; 32] {
        self.old_root
    }

    pub fn new_root(&self) -> [u8; 32] {
        self.new_root
    }

    pub fn txns(&self) -> &[SignedTransactionWithWitnesses] {
        &self.txns
    }
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

/// Replay `block` against its own witnesses, with no access to a [`Ledger`].
///
/// Each transaction writes two slots -- sender then receiver -- and every write both checks the
/// pre-state against the running root and advances it. Chaining the roots this way means a
/// self-payment needs no special case: the receiver write reads the slot the sender write just
/// produced, and the root comparison enforces that it agrees.
///
/// Nothing here trusts the witness. Addresses come from the transactions, post-states are computed
/// rather than supplied, and a created account is pinned to [`Account::empty`], so a prover cannot
/// choose the `auth_address` of an account it brings into existence.
pub fn verify_block(block: &Block) -> Result<(), VerificationError> {
    let mut root = block.old_root;

    for entry in &block.txns {
        let txn = &entry.stxn.txn;
        let (sender_addr, receiver_addr, amt) = (txn.sender(), txn.receiver(), txn.amount());

        expect_pre_state(&sender_addr, &entry.sender_witness, root)?;
        let mut sender = entry
            .sender_witness
            .old_account
            .ok_or(VerificationError::UnknownSender)?;
        // TODO: crypto verification
        entry.stxn.sig.verify_auth(&sender)?;
        sender.amount = sender
            .amount
            .checked_sub(amt)
            .ok_or(VerificationError::InsufficientFunds)?;
        sender.update_nonce(txn.nonce())?;
        root = root_with(&sender_addr, Some(&sender), &entry.sender_witness.proof)?;

        // Read against the root the sender write just produced, so a self-payment sees the debited
        // balance and the bumped nonce.
        expect_pre_state(&receiver_addr, &entry.receiver_witness, root)?;
        let mut receiver = entry
            .receiver_witness
            .old_account
            .unwrap_or_else(|| Account::empty(receiver_addr));
        receiver.amount = receiver
            .amount
            .checked_add(amt)
            .ok_or(VerificationError::AmountOverflow)?;
        root = root_with(
            &receiver_addr,
            Some(&receiver),
            &entry.receiver_witness.proof,
        )?;
    }

    if root == block.new_root {
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
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
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

    pub fn get_block(&mut self, stxns: Vec<SignedTransaction>) -> Block {
        let old_root = self.state_root();
        let mut txns = Vec::with_capacity(stxns.len());

        for stxn in stxns {
            match &stxn.txn {
                Transaction::Payment(pay) => {
                    let sender_addr = pay.header.sender;

                    let sender_witness = LeafWitness {
                        old_account: self.accounts.get(&sender_addr).copied(),
                        proof: self.tree.proof(&sender_addr),
                    };

                    let receiver_addr = pay.receiver;
                    let amt = pay.amount;

                    let sender = self.accounts.get_mut(&sender_addr).unwrap();
                    stxn.sig.verify_auth(sender).unwrap();
                    // TODO: crypto verification
                    sender.amount = sender.amount.checked_sub(amt).unwrap();
                    sender.update_nonce(pay.header.nonce).unwrap();
                    let sender = *sender;
                    self.tree.update(&sender_addr, Some(&sender));

                    // Captured after the sender write, so a self-payment witnesses the debited balance.
                    let receiver_witness = LeafWitness {
                        old_account: self.accounts.get(&receiver_addr).copied(),
                        proof: self.tree.proof(&receiver_addr),
                    };

                    let receiver = self
                        .accounts
                        .entry(receiver_addr)
                        .or_insert_with(|| Account::empty(receiver_addr));
                    receiver.amount = receiver.amount.checked_add(amt).unwrap();
                    let receiver = *receiver;
                    self.tree.update(&receiver_addr, Some(&receiver));

                    txns.push(SignedTransactionWithWitnesses {
                        stxn,
                        sender_witness,
                        receiver_witness,
                    });
                }
            }
        }

        Block {
            old_root,
            new_root: self.state_root(),
            txns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEME: Scheme = Scheme::Ed25519;

    fn signature(pub_key: &[u8]) -> Signature {
        Signature {
            scheme: SCHEME,
            pub_key: pub_key.to_vec(),
            sig: Vec::new(),
        }
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
    fn stxn(key: &[u8], nonce: u64, receiver: Address, amount: u64) -> SignedTransaction {
        SignedTransaction {
            txn: Transaction::Payment(Payment {
                header: TransactionHeader {
                    sender: address_from_public_key(SCHEME, key),
                    nonce,
                },
                receiver,
                amount,
            }),
            sig: signature(key),
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
            stxn(b"a key", 1, b, 100),
            stxn(b"b key", 1, fresh, 50),
            stxn(b"a key", 2, a, 25),
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
        let block = ledger.get_block(vec![stxn(b"sender key", 1, receiver, 250)]);

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
        block.txns[0].sender_witness.old_account = Some(account_at(b"a key", 0, 1_000_000).1);

        assert_eq!(verify_block(&block), Err(VerificationError::StaleWitness));
    }

    #[test]
    fn a_created_account_cannot_have_its_auth_address_chosen() {
        let (mut block, ..) = three_txn_block();
        let attacker = address_from_public_key(SCHEME, b"attacker key");

        // The second transaction creates `fresh`, so its receiver slot is empty. Claiming it
        // already held an account the attacker can sign for would hand them the balance.
        block.txns[1].receiver_witness.old_account = Some(Account::new(0, 0, attacker));

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

        // A witness can no longer go missing on its own -- it travels with its transaction. Drop
        // the whole entry and the remaining two no longer reach the claimed `new_root`.
        block.txns.pop();

        assert_eq!(verify_block(&block), Err(VerificationError::RootMismatch));
    }

    #[test]
    fn verify_block_rejects_reordered_transactions() {
        let (mut block, ..) = three_txn_block();

        // The swap carries each transaction's own witnesses with it, and it still fails: a witness
        // describes one specific point in the root chain, so order is load-bearing on its own.
        block.txns.swap(0, 1);

        assert!(verify_block(&block).is_err());
    }

    #[test]
    fn verify_block_rejects_spending_from_an_empty_slot() {
        let mut ledger = Ledger::new();
        let receiver = fund(&mut ledger, b"receiver key", 10);
        let funded = fund(&mut ledger, b"sender key", 100);

        let mut block = ledger.get_block(vec![stxn(b"sender key", 1, receiver, 40)]);

        // Rewrite the transaction to spend from an address with no account, and hand it the
        // matching absence proof from before the block -- the strongest witness there is for that
        // slot. A missing sender must still be rejected outright.
        let empty = address_from_public_key(SCHEME, b"no account here");
        let mut fresh_ledger = Ledger::new();
        fresh_ledger.insert_account(receiver, account_at(b"receiver key", 0, 10).1);
        fresh_ledger.insert_account(funded, account_at(b"sender key", 0, 100).1);

        let Transaction::Payment(payment) = &mut block.txns[0].stxn.txn;
        payment.header.sender = empty;
        block.txns[0].sender_witness = LeafWitness {
            old_account: None,
            proof: fresh_ledger.proof(&empty),
        };

        assert_eq!(verify_block(&block), Err(VerificationError::UnknownSender));
    }

    #[test]
    fn process_block_keeps_the_state_root_in_step() {
        let sender_sig = signature(b"sender key");

        let mut ledger = Ledger::new();
        let sender_addr = fund(&mut ledger, b"sender key", 1_000);
        let receiver_addr = fund(&mut ledger, b"receiver key", 5);

        let before = ledger.state_root();

        ledger.get_block(vec![SignedTransaction {
            txn: Transaction::Payment(Payment {
                header: TransactionHeader {
                    sender: sender_addr,
                    nonce: 1,
                },
                receiver: receiver_addr,
                amount: 250,
            }),
            sig: sender_sig,
        }]);

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
            signature(key).address(),
            "Signature::address must agree with the standalone derivation"
        );
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
        assert!(signature(key).verify_auth(&account).is_ok());
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
        let sender_sig = signature(b"sender key");
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

        ledger.get_block(vec![SignedTransaction {
            txn: Transaction::Payment(Payment {
                header: TransactionHeader {
                    sender: sender_addr,
                    nonce: 1,
                },
                receiver: new_addr,
                amount: 300,
            }),
            sig: sender_sig,
        }]);

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
        let a_sig = signature(b"a key");
        let b_sig = signature(b"b key");

        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", 1_000);
        let b = fund(&mut ledger, b"b key", 500);
        // `c` starts empty, so plain account creation is all it needs.
        let c = ledger.create_account(SCHEME, b"c key");

        // `a` and `b` are each written by more than one transaction, so their leaf slots are
        // rehashed repeatedly. The end state must still match a ledger built directly from it: an
        // address has one fixed slot, so the root depends only on the final account set.
        let block = ledger.get_block(vec![
            SignedTransaction {
                txn: Transaction::Payment(Payment {
                    header: TransactionHeader {
                        sender: a,
                        nonce: 1,
                    },
                    receiver: b,
                    amount: 100,
                }),
                sig: a_sig,
            },
            SignedTransaction {
                txn: Transaction::Payment(Payment {
                    header: TransactionHeader {
                        sender: b,
                        nonce: 1,
                    },
                    receiver: c,
                    amount: 50,
                }),
                sig: b_sig,
            },
            SignedTransaction {
                txn: Transaction::Payment(Payment {
                    header: TransactionHeader {
                        sender: signature(b"a key").address(),
                        nonce: 2,
                    },
                    receiver: b,
                    amount: 25,
                }),
                sig: signature(b"a key"),
            },
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
        let sig = signature(b"self key");

        let mut ledger = Ledger::new();
        let addr = fund(&mut ledger, b"self key", 100);

        ledger.get_block(vec![SignedTransaction {
            txn: Transaction::Payment(Payment {
                header: TransactionHeader {
                    sender: addr,
                    nonce: 1,
                },
                receiver: addr,
                amount: 40,
            }),
            sig,
        }]);

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
