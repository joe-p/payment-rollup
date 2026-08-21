use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha512_256};

mod merkle;

pub use merkle::{MerkleProof, SparseMerkleTree, verify_proof};

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
    let mut hash_input = Vec::new();
    hash_input.extend(b"ADDR");
    hash_input.extend(scheme.identifier());
    hash_input.extend(pub_key);

    Sha512_256::digest(hash_input).into()
}

const ENCODED_TX_SIZE: usize = 32 + 8 + 32 + 8;

const ENCODED_ACCOUNT_SIZE: usize = 8 + 8 + 32;

#[derive(Debug)]
pub enum VerificationError {
    InvalidAuthAddress,
    InvalidNonce,
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

pub struct Transaction {
    sender: Address,
    nonce: u64,
    receiver: Address,
    amount: u64,
}

impl Transaction {
    pub fn bytes_to_sign(&self) -> [u8; ENCODED_TX_SIZE] {
        let mut buf = [0u8; ENCODED_TX_SIZE];
        let mut offset = 0;

        buf[offset..offset + self.sender.len()].copy_from_slice(&self.sender);
        offset += self.sender.len();

        let nonce_bytes = self.nonce.to_be_bytes();
        buf[offset..offset + nonce_bytes.len()].copy_from_slice(&nonce_bytes);
        offset += nonce_bytes.len();

        buf[offset..offset + self.receiver.len()].copy_from_slice(&self.receiver);
        offset += self.receiver.len();

        let amount_bytes = self.amount.to_be_bytes();
        buf[offset..offset + amount_bytes.len()].copy_from_slice(&amount_bytes);

        buf
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

pub struct Block {
    txns: Vec<SignedTransaction>,
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

    pub fn process_block(&mut self, block: Block) {
        let mut touched: HashSet<Address> = HashSet::new();

        for stxn in &block.txns {
            let sender_addr = stxn.txn.sender;
            let receiver_addr = stxn.txn.receiver;
            let amt = stxn.txn.amount;

            let sender = self.accounts.get_mut(&sender_addr).unwrap();
            stxn.sig.verify_auth(sender).unwrap();
            // TODO: crypto verification
            sender.amount = sender.amount.checked_sub(amt).unwrap();
            sender.update_nonce(stxn.txn.nonce).unwrap();
            touched.insert(sender_addr);

            let receiver = self
                .accounts
                .entry(receiver_addr)
                .or_insert_with(|| Account::empty(receiver_addr));
            receiver.amount = receiver.amount.checked_add(amt).unwrap();
            touched.insert(receiver_addr);
        }

        self.commit(touched);
    }

    /// Rehash the tree for each touched address, reading its final state from `accounts`. The
    /// order of `touched` does not matter: an address has one fixed leaf slot, so the root depends
    /// only on the account set.
    fn commit(&mut self, touched: HashSet<Address>) {
        for address in touched {
            let account = self.accounts.get(&address).copied();
            self.tree.update(&address, account.as_ref());
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

    #[test]
    fn process_block_keeps_the_state_root_in_step() {
        let sender_sig = signature(b"sender key");

        let mut ledger = Ledger::new();
        let sender_addr = fund(&mut ledger, b"sender key", 1_000);
        let receiver_addr = fund(&mut ledger, b"receiver key", 5);

        let before = ledger.state_root();

        ledger.process_block(Block {
            txns: vec![SignedTransaction {
                txn: Transaction {
                    sender: sender_addr,
                    nonce: 1,
                    receiver: receiver_addr,
                    amount: 250,
                },
                sig: sender_sig,
            }],
        });

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

        ledger.process_block(Block {
            txns: vec![SignedTransaction {
                txn: Transaction {
                    sender: sender_addr,
                    nonce: 1,
                    receiver: new_addr,
                    amount: 300,
                },
                sig: sender_sig,
            }],
        });

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
    fn batched_commit_matches_rebuilding_from_final_state() {
        let a_sig = signature(b"a key");
        let b_sig = signature(b"b key");

        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", 1_000);
        let b = fund(&mut ledger, b"b key", 500);
        // `c` starts empty, so plain account creation is all it needs.
        let c = ledger.create_account(SCHEME, b"c key");

        // `a` and `b` are each touched by more than one transaction, so the batched commit
        // rehashes their paths once instead of twice and three times respectively.
        ledger.process_block(Block {
            txns: vec![
                SignedTransaction {
                    txn: Transaction {
                        sender: a,
                        nonce: 1,
                        receiver: b,
                        amount: 100,
                    },
                    sig: a_sig,
                },
                SignedTransaction {
                    txn: Transaction {
                        sender: b,
                        nonce: 1,
                        receiver: c,
                        amount: 50,
                    },
                    sig: b_sig,
                },
                SignedTransaction {
                    txn: Transaction {
                        sender: signature(b"a key").address(),
                        nonce: 2,
                        receiver: b,
                        amount: 25,
                    },
                    sig: signature(b"a key"),
                },
            ],
        });

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

        ledger.process_block(Block {
            txns: vec![SignedTransaction {
                txn: Transaction {
                    sender: addr,
                    nonce: 1,
                    receiver: addr,
                    amount: 40,
                },
                sig,
            }],
        });

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
