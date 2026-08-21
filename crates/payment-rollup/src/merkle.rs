use std::collections::HashMap;
use std::sync::OnceLock;

use sha2::{Digest, Sha512_256};

use crate::{Account, Address};

/// Number of levels between the leaves and the root. An [`Address`] is 32 bytes, so every bit of
/// the address is one step down the tree and each address has its own leaf.
const DEPTH: u16 = 256;

/// Hash of a slot that holds no account.
const EMPTY_LEAF: [u8; 32] = [0u8; 32];

/// `EMPTY[l]` is the hash of a subtree of height `l` containing no accounts at all. `EMPTY[DEPTH]`
/// is the root of an empty tree.
fn empty_hashes() -> &'static [[u8; 32]; DEPTH as usize + 1] {
    static EMPTY: OnceLock<[[u8; 32]; DEPTH as usize + 1]> = OnceLock::new();

    EMPTY.get_or_init(|| {
        let mut table = [EMPTY_LEAF; DEPTH as usize + 1];
        for level in 1..=DEPTH as usize {
            table[level] = node_hash(&table[level - 1], &table[level - 1]);
        }
        table
    })
}

fn leaf_hash(address: &Address, account: &Account) -> [u8; 32] {
    let mut hash_input = Vec::new();
    hash_input.extend(b"LEAF");
    hash_input.extend(address);
    hash_input.extend(account.encode());

    Sha512_256::digest(hash_input).into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hash_input = Vec::new();
    hash_input.extend(b"NODE");
    hash_input.extend(left);
    hash_input.extend(right);

    Sha512_256::digest(hash_input).into()
}

/// The bit of `address` at `index`, reading most significant bit first.
fn bit_at(address: &Address, index: usize) -> u8 {
    (address[index / 8] >> (7 - index % 8)) & 1
}

fn flip_bit(address: &mut Address, index: usize) {
    address[index / 8] ^= 1 << (7 - index % 8);
}

/// The key of the node at `level` that `address` descends through: the top `DEPTH - level` bits of
/// the address, with the rest zeroed.
fn prefix(address: &Address, level: u16) -> Address {
    let significant_bits = (DEPTH - level) as usize;
    let full_bytes = significant_bits / 8;
    let leftover_bits = significant_bits % 8;

    let mut key = [0u8; 32];
    key[..full_bytes].copy_from_slice(&address[..full_bytes]);
    if leftover_bits > 0 {
        key[full_bytes] = address[full_bytes] & (0xffu8 << (8 - leftover_bits));
    }

    key
}

/// The key of the sibling that the `address` node at `level` is hashed with.
fn sibling_key(address: &Address, level: u16) -> Address {
    let mut key = prefix(address, level);
    flip_bit(&mut key, (DEPTH - 1 - level) as usize);

    key
}

/// A sparse Merkle tree over account state, keyed by [`Address`].
///
/// Every address has a fixed leaf slot, so the root depends only on the set of accounts and not on
/// the order they were written. Subtrees holding no accounts collapse to the precomputed constants
/// in [`empty_hashes`] and are never stored, which keeps the node map proportional to the number
/// of accounts rather than to the size of the address space.
pub struct SparseMerkleTree {
    /// Non-empty nodes at levels `0..DEPTH`, keyed by `(level, prefix)`. Nodes equal to their
    /// empty-subtree constant are pruned, so a present entry always means a non-empty subtree.
    nodes: HashMap<(u16, Address), [u8; 32]>,
    root: [u8; 32],
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root: empty_hashes()[DEPTH as usize],
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Write `account` into the slot for `address`, or clear the slot when it is `None`, then
    /// rehash the path up to the root. Costs `DEPTH` hashes.
    pub fn update(&mut self, address: &Address, account: Option<&Account>) {
        let empty = empty_hashes();

        let mut current = match account {
            Some(account) => leaf_hash(address, account),
            None => EMPTY_LEAF,
        };
        self.store(0, *address, current);

        for level in 0..DEPTH {
            let sibling = self
                .nodes
                .get(&(level, sibling_key(address, level)))
                .copied()
                .unwrap_or(empty[level as usize]);

            current = if bit_at(address, (DEPTH - 1 - level) as usize) == 0 {
                node_hash(&current, &sibling)
            } else {
                node_hash(&sibling, &current)
            };

            if level + 1 < DEPTH {
                self.store(level + 1, prefix(address, level + 1), current);
            }
        }

        self.root = current;
    }

    /// Prove what the tree holds for `address`. An address with no account yields a non-inclusion
    /// proof, which [`verify_proof`] checks by passing `None` as the account.
    pub fn proof(&self, address: &Address) -> MerkleProof {
        let mut bitmap = [0u8; 32];
        let mut siblings = Vec::new();

        for level in 0..DEPTH {
            if let Some(sibling) = self.nodes.get(&(level, sibling_key(address, level))) {
                bitmap[(level / 8) as usize] |= 1 << (level % 8);
                siblings.push(*sibling);
            }
        }

        MerkleProof { bitmap, siblings }
    }

    fn store(&mut self, level: u16, key: Address, hash: [u8; 32]) {
        if hash == empty_hashes()[level as usize] {
            self.nodes.remove(&(level, key));
        } else {
            self.nodes.insert((level, key), hash);
        }
    }
}

/// A path from a leaf slot to the root.
///
/// Most of the `DEPTH` siblings on any real path are empty-subtree constants, so only the
/// non-empty ones are carried. Bit `l` of `bitmap` (byte `l / 8`, bit `l % 8`) is set when the
/// sibling at level `l` is non-empty and consumes the next entry of `siblings`; when it is clear
/// the sibling is `empty_hashes()[l]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    bitmap: [u8; 32],
    siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    fn sibling_at(&self, level: u16) -> Option<usize> {
        if self.bitmap[(level / 8) as usize] & (1 << (level % 8)) == 0 {
            return None;
        }

        // The index into `siblings` is how many bits are set below `level`.
        let whole_bytes = (level / 8) as usize;
        let set_below: u32 = self.bitmap[..whole_bytes]
            .iter()
            .map(|byte| byte.count_ones())
            .sum::<u32>()
            + (self.bitmap[whole_bytes] & ((1u8 << (level % 8)) - 1)).count_ones();

        Some(set_below as usize)
    }

    fn non_empty_count(&self) -> usize {
        self.bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }
}

/// Check `proof` against `root` without access to the tree, so a verifier holding only the state
/// root can run it.
///
/// Pass `Some(account)` to prove that `address` holds exactly that account, or `None` to prove
/// that it holds no account at all.
pub fn verify_proof(
    root: &[u8; 32],
    address: &Address,
    account: Option<&Account>,
    proof: &MerkleProof,
) -> bool {
    if proof.non_empty_count() != proof.siblings.len() {
        return false;
    }

    let empty = empty_hashes();

    let mut current = match account {
        Some(account) => leaf_hash(address, account),
        None => EMPTY_LEAF,
    };

    for level in 0..DEPTH {
        let sibling = match proof.sibling_at(level) {
            Some(index) => proof.siblings[index],
            None => empty[level as usize],
        };

        current = if bit_at(address, (DEPTH - 1 - level) as usize) == 0 {
            node_hash(&current, &sibling)
        } else {
            node_hash(&sibling, &current)
        };
    }

    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(byte: u8) -> Address {
        [byte; 32]
    }

    fn account(amount: u64) -> Account {
        Account {
            nonce: 1,
            amount,
            auth_address: address(0xaa),
        }
    }

    // Pin the hashing scheme -- node tag, empty-leaf constant, depth -- against accidental change.
    // Cross-checked against an independent implementation.
    #[test]
    fn empty_root_is_stable() {
        assert_eq!(
            hex(&SparseMerkleTree::new().root()),
            "fe97272becc2fc97ef3e38b630eb0addc17fe30cdf38c7d2ed1ff382e05321b3"
        );
    }

    // Pins the rest of the scheme: leaf tag, account encoding, and the MSB-first path order.
    #[test]
    fn single_account_root_is_stable() {
        let mut tree = SparseMerkleTree::new();
        tree.update(&address(1), Some(&account(100)));

        assert_eq!(
            hex(&tree.root()),
            "d4cf2f7596438543714fdcb768db08cd27b052fc32951e0e2f39a69e6376f9d3"
        );
    }

    #[test]
    fn writing_and_clearing_a_slot_round_trips() {
        let mut tree = SparseMerkleTree::new();
        let empty_root = tree.root();

        tree.update(&address(1), Some(&account(100)));
        assert_ne!(tree.root(), empty_root);

        tree.update(&address(1), None);
        assert_eq!(tree.root(), empty_root);
        assert!(tree.nodes.is_empty(), "cleared slots must not leave nodes");
    }

    #[test]
    fn root_is_independent_of_write_order() {
        let mut forwards = SparseMerkleTree::new();
        forwards.update(&address(1), Some(&account(100)));
        forwards.update(&address(2), Some(&account(200)));

        let mut backwards = SparseMerkleTree::new();
        backwards.update(&address(2), Some(&account(200)));
        backwards.update(&address(1), Some(&account(100)));

        assert_eq!(forwards.root(), backwards.root());
    }

    #[test]
    fn amount_change_changes_the_root() {
        let mut tree = SparseMerkleTree::new();
        tree.update(&address(1), Some(&account(100)));
        let before = tree.root();

        tree.update(&address(1), Some(&account(101)));
        assert_ne!(tree.root(), before);
    }

    #[test]
    fn inclusion_proof_verifies() {
        let mut tree = SparseMerkleTree::new();
        tree.update(&address(1), Some(&account(100)));
        tree.update(&address(2), Some(&account(200)));
        tree.update(&address(0xff), Some(&account(300)));

        let proof = tree.proof(&address(2));
        assert!(verify_proof(
            &tree.root(),
            &address(2),
            Some(&account(200)),
            &proof
        ));
    }

    #[test]
    fn inclusion_proof_rejects_wrong_inputs() {
        let mut tree = SparseMerkleTree::new();
        tree.update(&address(1), Some(&account(100)));
        tree.update(&address(2), Some(&account(200)));

        let root = tree.root();
        let proof = tree.proof(&address(2));

        assert!(
            !verify_proof(&root, &address(2), Some(&account(201)), &proof),
            "wrong account must not verify"
        );
        assert!(
            !verify_proof(&root, &address(3), Some(&account(200)), &proof),
            "wrong address must not verify"
        );
        assert!(
            !verify_proof(&[0u8; 32], &address(2), Some(&account(200)), &proof),
            "wrong root must not verify"
        );
        assert!(
            !verify_proof(&root, &address(2), None, &proof),
            "an occupied slot must not prove absence"
        );
    }

    #[test]
    fn non_inclusion_proof_verifies_until_the_slot_is_filled() {
        let mut tree = SparseMerkleTree::new();
        tree.update(&address(1), Some(&account(100)));

        let proof = tree.proof(&address(2));
        assert!(verify_proof(&tree.root(), &address(2), None, &proof));

        tree.update(&address(2), Some(&account(200)));
        assert!(
            !verify_proof(&tree.root(), &address(2), None, &proof),
            "a stale absence proof must not verify against the new root"
        );
    }

    #[test]
    fn malformed_proof_is_rejected() {
        let mut tree = SparseMerkleTree::new();
        tree.update(&address(1), Some(&account(100)));
        tree.update(&address(2), Some(&account(200)));

        let mut proof = tree.proof(&address(2));
        assert!(!proof.siblings.is_empty());
        proof.siblings.pop();

        assert!(!verify_proof(
            &tree.root(),
            &address(2),
            Some(&account(200)),
            &proof
        ));
    }

    #[test]
    fn proof_carries_only_non_empty_siblings() {
        let mut tree = SparseMerkleTree::new();
        tree.update(&address(1), Some(&account(100)));
        tree.update(&address(2), Some(&account(200)));

        // Two accounts differ in the first bit where their addresses diverge, so exactly one
        // sibling on the path is non-empty.
        assert_eq!(tree.proof(&address(1)).siblings.len(), 1);
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
