use sha2::{Digest, Sha256};

use crate::{Account, Address};

/// Longest path the tree can produce. An [`Address`] is 32 bytes, so 256 levels give every address
/// a position of its own. Paths only run that deep when two addresses agree on all but their last
/// bit; in practice they run about `log2(accounts)` deep. See [`SparseMerkleTree`].
pub(crate) const DEPTH: usize = 256;

/// Hash of a subtree holding no accounts.
///
/// One constant serves every depth. Making it depth-dependent would buy nothing: a subtree hash is
/// only ever reached by descending a fixed number of levels from the root, so the path that leads
/// to it already pins its depth.
const EMPTY_SUBTREE: [u8; 32] = [0u8; 32];

/// Commitment to one account, which doubles as the hash of any subtree holding only that account.
///
/// The whole address is committed to, not just the path bits below the point where the leaf sits,
/// so a leaf cannot be relocated: a verifier that reaches this hash by descending `d` levels knows
/// the address it names really does start with those `d` bits.
fn leaf_hash(address: &Address, account: &Account) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"LEAF");
    hasher.update(address);
    hasher.update(account.encode());

    hasher.finalize().into()
}

/// Commitment to a subtree holding two or more accounts.
///
/// The tag domain-separates this from [`leaf_hash`], which is what makes a leaf's depth
/// unforgeable: short of a collision, a hash cannot pass as both a leaf and a branch, so a prover
/// cannot claim a leaf sits higher or lower than it does.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"NODE");
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().into()
}

/// The bit of `address` that decides which way to go at `depth`, reading most significant first.
fn bit_at(address: &Address, depth: usize) -> usize {
    ((address[depth / 8] >> (7 - depth % 8)) & 1) as usize
}

/// How many leading bits `a` and `b` share, or [`DEPTH`] when they are equal.
///
/// This is the depth of the branch that separates two addresses, and so the length of the paths
/// leading to them.
fn common_prefix_len(a: &Address, b: &Address) -> usize {
    for (index, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        if x != y {
            return index * 8 + (x ^ y).leading_zeros() as usize;
        }
    }

    DEPTH
}

/// One position in the tree.
///
/// The three cases are exactly the three things a subtree can hold -- nothing, one account, or two
/// or more -- and each has its own hash, so the shape of the tree is determined by its contents
/// alone.
#[derive(Debug)]
enum Node {
    Empty,
    Leaf { address: Address, account: Account },
    Branch(Box<Branch>),
}

#[derive(Debug)]
struct Branch {
    /// Cached [`node_hash`] of the two children, kept current by [`Branch::rehash`].
    hash: [u8; 32],
    children: [Node; 2],
}

impl Branch {
    fn rehash(&mut self) {
        self.hash = node_hash(&self.children[0].hash(), &self.children[1].hash());
    }
}

impl Node {
    fn branch(left: Node, right: Node) -> Node {
        Node::Branch(Box::new(Branch {
            hash: node_hash(&left.hash(), &right.hash()),
            children: [left, right],
        }))
    }

    fn hash(&self) -> [u8; 32] {
        match self {
            Node::Empty => EMPTY_SUBTREE,
            Node::Leaf { address, account } => leaf_hash(address, account),
            Node::Branch(branch) => branch.hash,
        }
    }

    /// Write `account` into the slot for `address` within this subtree, which sits at `depth`.
    fn insert(&mut self, depth: usize, address: &Address, account: &Account) {
        match self {
            Node::Empty => {
                *self = Node::Leaf {
                    address: *address,
                    account: *account,
                };
            }
            Node::Leaf {
                address: held,
                account: held_account,
            } => {
                if *held == *address {
                    *held_account = *account;
                } else {
                    // The slot is taken by someone else, so the leaf sitting here has to move down
                    // far enough that the two addresses part ways.
                    *self = Node::split(depth, (*held, *held_account), (*address, *account));
                }
            }
            Node::Branch(branch) => {
                branch.children[bit_at(address, depth)].insert(depth + 1, address, account);
                branch.rehash();
            }
        }
    }

    /// Clear the slot for `address`, then pull the tree back into shape.
    fn remove(&mut self, depth: usize, address: &Address) {
        match self {
            Node::Empty => {}
            Node::Leaf { address: held, .. } => {
                if *held == *address {
                    *self = Node::Empty;
                }
            }
            Node::Branch(branch) => {
                branch.children[bit_at(address, depth)].remove(depth + 1, address);
                branch.rehash();
                self.collapse();
            }
        }
    }

    /// Replace a branch that has been emptied down to one account or none with what it holds.
    ///
    /// Without this a removal would leave branches standing over a single leaf, and the tree would
    /// no longer be the canonical shape for its contents -- two ledgers holding the same accounts
    /// would disagree on the root.
    fn collapse(&mut self) {
        let Node::Branch(branch) = self else { return };

        let promoted = match &mut branch.children {
            [Node::Empty, Node::Empty] => Node::Empty,
            [leaf @ Node::Leaf { .. }, Node::Empty] | [Node::Empty, leaf @ Node::Leaf { .. }] => {
                std::mem::replace(leaf, Node::Empty)
            }
            _ => return,
        };

        *self = promoted;
    }

    /// A subtree at `depth` holding exactly `a` and `b`, whose addresses must differ.
    ///
    /// The two leaves sit just under the bit where their addresses first diverge, with a chain of
    /// one-child branches above them -- the shortest arrangement the addresses allow.
    fn split(depth: usize, a: (Address, Account), b: (Address, Account)) -> Node {
        let split_depth = common_prefix_len(&a.0, &b.0);

        let a_leaf = Node::Leaf {
            address: a.0,
            account: a.1,
        };
        let b_leaf = Node::Leaf {
            address: b.0,
            account: b.1,
        };

        let mut node = if bit_at(&a.0, split_depth) == 0 {
            Node::branch(a_leaf, b_leaf)
        } else {
            Node::branch(b_leaf, a_leaf)
        };

        // Above the split the two addresses agree, so either one gives the same path back up.
        for level in (depth..split_depth).rev() {
            node = if bit_at(&a.0, level) == 0 {
                Node::branch(node, Node::Empty)
            } else {
                Node::branch(Node::Empty, node)
            };
        }

        node
    }

    /// Walk towards `address`, pushing the sibling hash passed at each level, and report what the
    /// path runs into.
    fn prove(&self, depth: usize, address: &Address, siblings: &mut Vec<[u8; 32]>) -> Slot {
        match self {
            Node::Empty => Slot::Own,
            Node::Leaf {
                address: held,
                account,
            } => {
                if *held == *address {
                    Slot::Own
                } else {
                    Slot::Neighbor {
                        address: *held,
                        account: *account,
                    }
                }
            }
            Node::Branch(branch) => {
                let taken = bit_at(address, depth);
                siblings.push(branch.children[1 - taken].hash());

                branch.children[taken].prove(depth + 1, address, siblings)
            }
        }
    }
}

/// A sparse Merkle tree over account state, keyed by [`Address`].
///
/// Every address has one fixed position, so the root depends only on the set of accounts and not on
/// the order they were written.
///
/// Subtrees are compressed: one holding no accounts is [`EMPTY_SUBTREE`] and one holding a single
/// account is just that account's [`leaf_hash`], whatever depth it sits at. A path therefore stops
/// as soon as it has separated its address from every other account in the tree -- about
/// `log2(accounts)` levels -- rather than running the full [`DEPTH`]. Since verifying one proof
/// costs one hash per level, that is the difference between a few dozen hashes and 256, which is
/// what makes [`crate::verify_block`] affordable inside a zkVM.
pub struct SparseMerkleTree {
    root: Node,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self { root: Node::Empty }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root.hash()
    }

    /// Write `account` into the slot for `address`, or clear the slot when it is `None`.
    pub fn update(&mut self, address: &Address, account: Option<&Account>) {
        match account {
            Some(account) => self.root.insert(0, address, account),
            None => self.root.remove(0, address),
        }
    }

    /// Prove what the tree holds for `address`. An address with no account yields a non-inclusion
    /// proof, which [`verify_proof`] checks by passing `None` as the account.
    pub fn proof(&self, address: &Address) -> MerkleProof {
        let mut siblings = Vec::new();
        let slot = self.root.prove(0, address, &mut siblings);

        MerkleProof { siblings, slot }
    }
}

/// What the end of a [`MerkleProof`]'s path holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    /// The proven address's own position: empty, or holding that address's account.
    Own,
    /// Another account's leaf, occupying the position the proven address descends into because no
    /// third account forces the two of them apart yet.
    ///
    /// This is the second shape a non-inclusion proof takes, and the reason a proof reveals a
    /// neighboring account. Writing to the proven address pushes this leaf down; see
    /// [`root_from_proof`].
    Neighbor { address: Address, account: Account },
}

/// A path from the root down to one position in the tree.
///
/// `siblings[i]` is the hash of the subtree turned away from at depth `i`, so `siblings.len()` is
/// the depth of the position the path ends at -- there is no separate depth field to disagree with
/// it. The siblings themselves are never checked: a proof carrying the wrong ones simply fails to
/// reproduce the root it is measured against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    siblings: Vec<[u8; 32]>,
    slot: Slot,
}

impl MerkleProof {
    /// A proof from its parts, for a decoder rebuilding one off the wire.
    ///
    /// Nothing is validated here, and nothing needs to be: a proof that does not describe a real
    /// position simply fails to reproduce the root it is measured against. See [`root_from_proof`].
    pub(crate) fn from_parts(siblings: Vec<[u8; 32]>, slot: Slot) -> Self {
        Self { siblings, slot }
    }

    /// How deep the proven position sits, and so how many hashes verifying costs.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }

    pub fn slot(&self) -> &Slot {
        &self.slot
    }
}

/// A neighbor has to be a different address that genuinely descends alongside `address` as far as
/// `depth`, or the proof is describing a leaf in a position its own address contradicts.
fn check_neighbor(address: &Address, neighbor: &Address, depth: usize) -> Option<()> {
    if neighbor != address && common_prefix_len(address, neighbor) >= depth {
        Some(())
    } else {
        None
    }
}

/// Hash of the subtree at `depth` once `address` moves in beside the neighbor already there.
///
/// The neighbor is pushed down to just below the bit where the two addresses diverge, which is
/// fixed by the addresses themselves -- a prover has no say in the resulting shape.
fn subtree_with_both(
    depth: usize,
    (address, account): (&Address, &Account),
    (neighbor, held): (&Address, &Account),
) -> [u8; 32] {
    let split_depth = common_prefix_len(address, neighbor);
    let (own, other) = (leaf_hash(address, account), leaf_hash(neighbor, held));

    let mut current = if bit_at(address, split_depth) == 0 {
        node_hash(&own, &other)
    } else {
        node_hash(&other, &own)
    };

    for level in (depth..split_depth).rev() {
        current = if bit_at(address, level) == 0 {
            node_hash(&current, &EMPTY_SUBTREE)
        } else {
            node_hash(&EMPTY_SUBTREE, &current)
        };
    }

    current
}

/// The root implied by putting `account` in the slot for `address` and hashing up along `proof`,
/// or `None` if `proof` is malformed.
///
/// The same `proof` describes the position both before and after a write, so a caller replaying a
/// state transition can verify the pre-state and compute the post-state root from one witness:
/// call this with the old account and compare against the current root, then call it again with
/// the new account to get the next root. Compression does not cost that property, because each of
/// the four combinations of slot and account is a state the position can actually be in:
///
/// - `Own` with no account -- the position is empty, so nothing in the tree shares its prefix.
/// - `Own` with an account -- the account is there, or is being written into the empty position.
/// - `Neighbor` with no account -- the position is held by someone else, so `address` is absent.
/// - `Neighbor` with an account -- `address` is being written in, pushing the neighbor down.
pub(crate) fn root_from_proof(
    address: &Address,
    account: Option<&Account>,
    proof: &MerkleProof,
) -> Option<[u8; 32]> {
    let depth = proof.siblings.len();
    if depth > DEPTH {
        return None;
    }

    let mut current = match (&proof.slot, account) {
        (Slot::Own, None) => EMPTY_SUBTREE,
        (Slot::Own, Some(account)) => leaf_hash(address, account),
        (
            Slot::Neighbor {
                address: neighbor,
                account: held,
            },
            None,
        ) => {
            check_neighbor(address, neighbor, depth)?;

            leaf_hash(neighbor, held)
        }
        (
            Slot::Neighbor {
                address: neighbor,
                account: held,
            },
            Some(account),
        ) => {
            check_neighbor(address, neighbor, depth)?;

            subtree_with_both(depth, (address, account), (neighbor, held))
        }
    };

    for level in (0..depth).rev() {
        current = if bit_at(address, level) == 0 {
            node_hash(&current, &proof.siblings[level])
        } else {
            node_hash(&proof.siblings[level], &current)
        };
    }

    Some(current)
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
    root_from_proof(address, account, proof) == Some(*root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(byte: u8) -> Address {
        [byte; 32]
    }

    /// A spread-out address, so a set of them behaves like real ones rather than sharing long
    /// prefixes the way `address` does.
    fn hashed_address(index: u8) -> Address {
        Sha256::digest([index]).into()
    }

    fn account(amount: u64) -> Account {
        Account {
            nonce: 1,
            amount,
            auth_address: address(0xaa),
        }
    }

    fn tree_of(accounts: &[(Address, Account)]) -> SparseMerkleTree {
        let mut tree = SparseMerkleTree::new();
        for (address, account) in accounts {
            tree.update(address, Some(account));
        }

        tree
    }

    // The compressed shape shows up directly in the root for the two smallest trees: no accounts
    // is the empty constant, and one account is that account's leaf with nothing hashed on top.
    #[test]
    fn an_empty_tree_is_the_empty_subtree_constant() {
        assert_eq!(SparseMerkleTree::new().root(), EMPTY_SUBTREE);
    }

    #[test]
    fn a_lone_account_is_the_root() {
        let tree = tree_of(&[(address(1), account(100))]);

        assert_eq!(tree.root(), leaf_hash(&address(1), &account(100)));
        assert_eq!(tree.proof(&address(1)).depth(), 0);
    }

    // Pins the whole scheme -- tags, account encoding, MSB-first paths, and where compression puts
    // each leaf -- against accidental change. Both roots are cross-checked against an independent
    // implementation written from the recursive definition of a subtree rather than from
    // `Node::insert`, so a bug in the incremental path would show up here.
    #[test]
    fn multi_account_root_is_stable() {
        let tree = tree_of(&[
            (address(1), account(100)),
            (address(2), account(200)),
            (address(0xff), account(300)),
        ]);

        assert_eq!(
            hex(&tree.root()),
            "26e30a25a264091a00f99f703695a6d67fddbbbae981762863882907302211ee"
        );
    }

    // The same, over enough spread-out addresses to exercise branches at many depths rather than
    // the one long shared prefix the `address` helper produces.
    #[test]
    fn a_wide_tree_root_is_stable() {
        let tree = tree_of(
            &(0..64u8)
                .map(|index| (hashed_address(index), account(index as u64)))
                .collect::<Vec<_>>(),
        );

        assert_eq!(
            hex(&tree.root()),
            "139e97278186c78129ecc582dc3a93575948afcf35831b747d3044bcac6b2fd3"
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
        assert!(
            matches!(tree.root, Node::Empty),
            "cleared slots must not leave nodes"
        );
    }

    #[test]
    fn root_is_independent_of_write_order() {
        let accounts = [
            (address(1), account(100)),
            (address(2), account(200)),
            (address(0xff), account(300)),
        ];
        let mut reversed = accounts;
        reversed.reverse();

        assert_eq!(tree_of(&accounts).root(), tree_of(&reversed).root());
    }

    #[test]
    fn amount_change_changes_the_root() {
        let mut tree = tree_of(&[(address(1), account(100)), (address(2), account(200))]);
        let before = tree.root();

        tree.update(&address(1), Some(&account(101)));
        assert_ne!(tree.root(), before);
    }

    // The point of compressing: a path stops once it has separated its address from the others, so
    // proof cost tracks the account count rather than the 256-bit address space.
    #[test]
    fn proof_depth_tracks_the_account_count_not_the_address_space() {
        let accounts: Vec<_> = (0..64u8)
            .map(|index| (hashed_address(index), account(index as u64)))
            .collect();
        let tree = tree_of(&accounts);

        let deepest = accounts
            .iter()
            .map(|(address, _)| tree.proof(address).depth())
            .max()
            .unwrap();

        assert!(
            (6..24).contains(&deepest),
            "64 accounts should sit around log2(64) deep, got {deepest}"
        );
        assert!(
            deepest < DEPTH,
            "a compressed path must beat the full depth"
        );
    }

    #[test]
    fn inclusion_proof_verifies() {
        let tree = tree_of(&[
            (address(1), account(100)),
            (address(2), account(200)),
            (address(0xff), account(300)),
        ]);

        assert!(verify_proof(
            &tree.root(),
            &address(2),
            Some(&account(200)),
            &tree.proof(&address(2))
        ));
    }

    #[test]
    fn inclusion_proof_rejects_wrong_inputs() {
        let tree = tree_of(&[(address(1), account(100)), (address(2), account(200))]);

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

    // Absence proved by reaching an empty subtree: the address parts from everything in the tree
    // before anything is sitting in its way.
    #[test]
    fn non_inclusion_by_empty_subtree_verifies_until_the_slot_is_filled() {
        let mut tree = tree_of(&[(address(1), account(100)), (address(2), account(200))]);

        let absent = address(0xff);
        let proof = tree.proof(&absent);
        assert_eq!(proof.slot(), &Slot::Own);
        assert!(verify_proof(&tree.root(), &absent, None, &proof));

        tree.update(&absent, Some(&account(300)));
        assert!(
            !verify_proof(&tree.root(), &absent, None, &proof),
            "a stale absence proof must not verify against the new root"
        );
    }

    // The other shape: absence proved by naming the account already sitting where the address
    // would go.
    #[test]
    fn non_inclusion_by_neighbor_verifies_until_the_slot_is_filled() {
        let mut tree = tree_of(&[(address(1), account(100))]);

        let absent = address(2);
        let proof = tree.proof(&absent);
        assert_eq!(
            proof.slot(),
            &Slot::Neighbor {
                address: address(1),
                account: account(100),
            }
        );
        assert!(verify_proof(&tree.root(), &absent, None, &proof));

        tree.update(&absent, Some(&account(200)));
        assert!(
            !verify_proof(&tree.root(), &absent, None, &proof),
            "a stale absence proof must not verify against the new root"
        );
    }

    // Writing through a neighbor witness has to land on the same root as inserting normally --
    // this is what lets `verify_block` compute a post-state root from a single witness.
    #[test]
    fn writing_beside_a_neighbor_reaches_the_real_root() {
        let mut tree = tree_of(&[(address(1), account(100)), (address(0xff), account(300))]);

        let new = address(2);
        let proof = tree.proof(&new);
        assert!(matches!(proof.slot(), Slot::Neighbor { .. }));

        let computed = root_from_proof(&new, Some(&account(200)), &proof);
        tree.update(&new, Some(&account(200)));

        assert_eq!(computed, Some(tree.root()));
        assert!(verify_proof(
            &tree.root(),
            &new,
            Some(&account(200)),
            &tree.proof(&new)
        ));
    }

    #[test]
    fn a_neighbor_must_share_the_proven_prefix() {
        let tree = tree_of(&[
            (address(1), account(100)),
            (address(2), account(200)),
            (address(0xff), account(300)),
        ]);

        let absent = address(3);
        let mut proof = tree.proof(&absent);
        assert!(proof.depth() > 0, "the check only bites below the root");

        // Point the neighbor at an account that parts from `absent` above where the proof claims
        // it sits, which would put a leaf somewhere its own address says it cannot be.
        proof.slot = Slot::Neighbor {
            address: address(0xff),
            account: account(300),
        };
        assert_eq!(root_from_proof(&absent, None, &proof), None);
        assert_eq!(root_from_proof(&absent, Some(&account(1)), &proof), None);
    }

    #[test]
    fn a_neighbor_cannot_be_the_proven_address() {
        let tree = tree_of(&[(address(1), account(100)), (address(2), account(200))]);

        let mut proof = tree.proof(&address(2));
        proof.slot = Slot::Neighbor {
            address: address(2),
            account: account(200),
        };

        assert_eq!(root_from_proof(&address(2), None, &proof), None);
    }

    #[test]
    fn a_proof_deeper_than_the_address_space_is_rejected() {
        let tree = tree_of(&[(address(1), account(100)), (address(2), account(200))]);

        let mut proof = tree.proof(&address(1));
        proof.siblings = vec![EMPTY_SUBTREE; DEPTH + 1];

        assert_eq!(root_from_proof(&address(1), None, &proof), None);
    }

    #[test]
    fn malformed_proof_is_rejected() {
        let tree = tree_of(&[(address(1), account(100)), (address(2), account(200))]);

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

    // Removal has to collapse the branches it empties, or the tree stops being the canonical shape
    // for its contents and two ledgers holding the same accounts disagree on the root.
    #[test]
    fn removal_restores_the_shape_a_fresh_tree_would_have() {
        let keep: Vec<_> = (0..16u8)
            .map(|index| (hashed_address(index), account(index as u64)))
            .collect();
        let mut tree = tree_of(&keep);

        let extras: Vec<_> = (16..32u8)
            .map(|index| (hashed_address(index), account(index as u64)))
            .collect();
        for (address, account) in &extras {
            tree.update(address, Some(account));
        }
        for (address, _) in &extras {
            tree.update(address, None);
        }

        assert_eq!(tree.root(), tree_of(&keep).root());
        for (address, account) in &keep {
            assert!(verify_proof(
                &tree.root(),
                address,
                Some(account),
                &tree.proof(address)
            ));
        }
        for (address, _) in &extras {
            assert!(verify_proof(
                &tree.root(),
                address,
                None,
                &tree.proof(address)
            ));
        }
    }

    // `Node::split` and `subtree_with_both` are the prover-side and verifier-side halves of the
    // same rule, so they must not drift apart.
    #[test]
    fn split_matches_the_verifier_side_computation() {
        let (a, b) = (address(1), address(2));
        let (a_account, b_account) = (account(100), account(200));

        for depth in 0..=common_prefix_len(&a, &b) {
            assert_eq!(
                Node::split(depth, (a, a_account), (b, b_account)).hash(),
                subtree_with_both(depth, (&a, &a_account), (&b, &b_account)),
                "disagreement at depth {depth}"
            );
        }
    }

    #[test]
    fn a_leaf_and_a_branch_hash_differently() {
        let leaf = leaf_hash(&address(1), &account(100));

        assert_ne!(leaf, node_hash(&leaf, &EMPTY_SUBTREE));
        assert_ne!(leaf, EMPTY_SUBTREE);
        assert_ne!(node_hash(&EMPTY_SUBTREE, &EMPTY_SUBTREE), EMPTY_SUBTREE);
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
