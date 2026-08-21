use std::collections::HashMap;

use sha2::{Digest, Sha512_256};

pub type Address = [u8; 32];

const SCHEME_SIZE: usize = 3;

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

const ENCODED_TX_SIZE: usize = 32 + 8 + 32 + 8;

#[derive(Debug)]
pub enum VerificationError {
    InvalidAuthAddress,
    InvalidNonce,
}

pub struct Account {
    nonce: u64,
    amount: u64,
    auth_address: Address,
}

impl Account {
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
    fn address(&self) -> Address {
        let mut hash_input = Vec::new();
        hash_input.extend(b"ADDR");
        hash_input.extend(self.scheme.identifier());
        hash_input.extend(self.pub_key.clone());
        let hash = Sha512_256::digest(hash_input);

        hash.into()
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

pub struct Ledger {
    accounts: HashMap<Address, Account>,
}

impl Ledger {
    pub fn process_block(&mut self, block: Block) {
        for stxn in &block.txns {
            let sender_addr = stxn.txn.sender;
            let receiver_addr = stxn.txn.receiver;
            let amt = stxn.txn.amount;

            let sender = self.accounts.get_mut(&sender_addr).unwrap();
            stxn.sig.verify_auth(sender).unwrap();
            // TODO: crypto verification
            sender.amount = sender.amount.checked_sub(amt).unwrap();
            sender.update_nonce(stxn.txn.nonce).unwrap();

            let receiver = self.accounts.get_mut(&receiver_addr).unwrap();
            receiver.amount = receiver.amount.checked_add(amt).unwrap();
        }
    }
}
