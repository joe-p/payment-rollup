//! Wire formats for the two halves of a block.
//!
//! The halves are encoded to opposite standards, because they are paid for in different units:
//!
//! - A [`Batch`] is published on the settlement chain, so every byte costs money. Addresses are
//!   deduplicated against a per-block dictionary, amounts are varints, and the nonce is not
//!   transmitted at all -- see [`Account::bump_nonce`].
//! - A [`Sidecar`] never leaves the prover, so its bytes are free and it is encoded for a simple
//!   decoder instead: fixed-width fields, no dictionary, nothing to look up.
//!
//! The guest reads the batch bytes *the chain will record* and decodes them with the same decoder
//! a replaying full node runs. Nothing re-encodes them, so there is no encoder/decoder pair to
//! keep as exact inverses, and no canonicity requirement: any byte string [`Batch::decode`]
//! accepts is a valid block, because the bytes are the source of truth rather than a re-derivation
//! of it.

use std::collections::HashMap;
use std::fmt;

use crate::{
    Account, Address, Batch, Deposit, DepositSidecar, ENCODED_ACCOUNT_SIZE, LeafWitness,
    MerkleProof, Payment, PaymentSidecar, SCHEME_SIZE, Scheme, Sidecar, Signature, Slot,
    ForcedWithdrawal, ForcedWithdrawalSidecar, Transaction, TransactionHeader, TxnSidecar,
    Withdrawal, WithdrawalSidecar, merkle::DEPTH,
};

const BATCH_VERSION: u8 = 0;
const SIDECAR_VERSION: u8 = 0;

const KIND_PAYMENT: u8 = 0;
const KIND_DEPOSIT: u8 = 1;
const KIND_WITHDRAWAL: u8 = 2;
const KIND_FORCED_WITHDRAWAL: u8 = 3;

const ABSENT: u8 = 0;
const PRESENT: u8 = 1;

const SLOT_OWN: u8 = 0;
const SLOT_NEIGHBOR: u8 = 1;

/// Smallest a witness can encode to: an absent account, depth zero, and its own slot.
const MIN_ENCODED_WITNESS_SIZE: usize = 1 + 1 + 1;

/// Smallest a transaction can encode to: a deposit, being a kind tag, a one-byte address reference,
/// and a one-byte amount. Used to reject a count no remaining input could back.
///
/// This is the minimum over every kind, not the size of any particular one. [`Reader::count`]
/// rejects when `count * stride` exceeds what is left, so a stride larger than the smallest kind
/// would reject *valid* input -- a batch of nothing but deposits, for instance.
const MIN_ENCODED_TXN_SIZE: usize = 1 + 1 + 1;

/// Smallest a sidecar entry can encode to: a deposit entry, being a single witness.
///
/// The minimum over every kind, for the reason given on [`MIN_ENCODED_TXN_SIZE`].
const MIN_ENCODED_ENTRY_SIZE: usize = MIN_ENCODED_WITNESS_SIZE;

/// Why a byte string is not a [`Batch`] or a [`Sidecar`].
///
/// Every variant is a decode failure, never a verification failure -- a well-formed encoding of a
/// block that does not verify decodes fine and is rejected by [`crate::verify_batch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnsupportedVersion(u8),
    /// The input ran out mid-field.
    UnexpectedEnd,
    /// The input decoded fully but bytes were left over.
    TrailingBytes,
    /// A varint ran past ten bytes or overflowed a `u64`.
    MalformedVarint,
    /// A length or count that does not fit a `usize` -- the guest is a 32-bit machine -- or that
    /// the remaining input could not possibly back. Checking it before allocating is what keeps a
    /// hostile count from becoming a huge reservation.
    ImplausibleLength,
    UnknownTransactionKind(u8),
    UnknownScheme([u8; SCHEME_SIZE]),
    UnknownSlotKind(u8),
    /// A presence tag that is neither absent nor present.
    UnknownPresenceTag(u8),
    /// An address reference pointing past the end of the dictionary built so far.
    UnknownAddressRef(u64),
    /// A proof claiming to sit deeper than the address space allows.
    ProofTooDeep(usize),
    /// The sidecar carries a different number of entries than its batch has transactions.
    SidecarLengthMismatch {
        expected: usize,
        found: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnsupportedVersion(version) => write!(f, "unsupported version {version}"),
            DecodeError::UnexpectedEnd => write!(f, "input ended mid-field"),
            DecodeError::TrailingBytes => write!(f, "trailing bytes after the last item"),
            DecodeError::MalformedVarint => write!(f, "malformed varint"),
            DecodeError::ImplausibleLength => write!(f, "implausible length or count"),
            DecodeError::UnknownTransactionKind(kind) => {
                write!(f, "unknown transaction kind {kind}")
            }
            DecodeError::UnknownScheme(id) => {
                write!(f, "unknown signature scheme {:?}", id.escape_ascii())
            }
            DecodeError::UnknownSlotKind(kind) => write!(f, "unknown slot kind {kind}"),
            DecodeError::UnknownPresenceTag(tag) => write!(f, "unknown presence tag {tag}"),
            DecodeError::UnknownAddressRef(reference) => {
                write!(f, "address reference {reference} is not in the dictionary")
            }
            DecodeError::ProofTooDeep(depth) => write!(f, "proof depth {depth} exceeds {DEPTH}"),
            DecodeError::SidecarLengthMismatch { expected, found } => write!(
                f,
                "sidecar carries {found} entries for a batch of {expected} transactions"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// LEB128, little-endian base-128 with a continuation bit.
///
/// Amounts and counts are small in practice and 64 bits wide in the worst case, which is exactly
/// what a varint is for. Non-minimal encodings are accepted: the batch bytes are the record, so
/// there is nothing for a second encoding of the same number to disagree with.
fn put_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;

        if value == 0 {
            buf.push(byte);
            return;
        }

        buf.push(byte | 0x80);
    }
}

fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// A cursor that cannot read past the end of its input.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn remaining(&self) -> usize {
        self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.bytes.len() < len {
            return Err(DecodeError::UnexpectedEnd);
        }

        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;

        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        let mut shift = 0u32;

        loop {
            let byte = self.byte()?;
            let payload = u64::from(byte & 0x7f);

            if shift >= 64 || payload > u64::MAX >> shift {
                return Err(DecodeError::MalformedVarint);
            }
            value |= payload << shift;

            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn expect_version(&mut self, expected: u8) -> Result<(), DecodeError> {
        let version = self.byte()?;
        if version == expected {
            Ok(())
        } else {
            Err(DecodeError::UnsupportedVersion(version))
        }
    }

    /// A count whose items need at least `stride` bytes each.
    ///
    /// Rejecting a count the remaining input cannot back is what makes it safe to reserve for it:
    /// otherwise a three-byte input could ask for a billion-element vector.
    fn count(&mut self, stride: usize) -> Result<usize, DecodeError> {
        let count = usize::try_from(self.varint()?).map_err(|_| DecodeError::ImplausibleLength)?;

        if count
            .checked_mul(stride)
            .is_none_or(|needed| needed > self.remaining())
        {
            return Err(DecodeError::ImplausibleLength);
        }

        Ok(count)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.count(1)?;

        Ok(self.take(len)?.to_vec())
    }

    fn account(&mut self) -> Result<Account, DecodeError> {
        Ok(Account::decode(&self.array::<ENCODED_ACCOUNT_SIZE>()?))
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Per-block address dictionary, encoder side.
///
/// An address costs 33 bytes the first time it appears in a block and one or two after that, which
/// is what makes a self-payment or a busy account cheap. The dictionary is scoped to the block and
/// never committed to state, so this buys its saving without adding anything the guest has to
/// prove.
#[derive(Default)]
struct Dictionary {
    positions: HashMap<Address, u64>,
}

impl Dictionary {
    fn put(&mut self, buf: &mut Vec<u8>, address: &Address) {
        match self.positions.get(address) {
            // References are one-based, leaving zero to mean "a literal follows".
            Some(position) => put_varint(buf, *position),
            None => {
                buf.push(0);
                buf.extend_from_slice(address);
                self.positions
                    .insert(*address, self.positions.len() as u64 + 1);
            }
        }
    }
}

/// The same dictionary, decoder side, where position *is* the index.
#[derive(Default)]
struct DictionaryReader {
    seen: Vec<Address>,
}

impl DictionaryReader {
    fn take(&mut self, reader: &mut Reader) -> Result<Address, DecodeError> {
        match reader.varint()? {
            0 => {
                let address = reader.array::<32>()?;
                self.seen.push(address);

                Ok(address)
            }
            reference => usize::try_from(reference - 1)
                .ok()
                .and_then(|index| self.seen.get(index))
                .copied()
                .ok_or(DecodeError::UnknownAddressRef(reference)),
        }
    }
}

impl Batch {
    /// The bytes the settlement chain records.
    ///
    /// ```text
    /// version    u8 = 0
    /// count      varint
    /// count x, kind u8, then one of:
    ///   kind 0 (payment)
    ///     sender   address reference
    ///     receiver address reference
    ///     amount   varint
    ///   kind 1 (deposit)
    ///     receiver address reference
    ///     amount   varint
    ///   kind 2 (withdrawal)
    ///     sender    address reference
    ///     recipient 32 literal bytes, an L1 address
    ///     amount    varint
    ///   kind 3 (forced withdrawal)
    ///     address   address reference
    ///     recipient 32 literal bytes, an L1 address
    ///
    /// address reference:
    ///   varint 0 -> 32 literal bytes follow, appended to the dictionary
    ///   varint n -> the nth address added to the dictionary, one-based
    /// ```
    ///
    /// No roots, no nonces, no signatures, no witnesses: a replaying node derives all of them. A
    /// deposit's sender is derived too -- it is always [`crate::ZERO_ADDRESS`], so writing it would
    /// be paying for a constant. A payment between two addresses the block has already mentioned
    /// costs four bytes; a deposit to one costs three.
    ///
    /// Deposits share the address dictionary with payments, so a deposit and a later payment to the
    /// same account cost one reference between them.
    ///
    /// A withdrawal's recipient is written out in full every time and deliberately kept out of the
    /// dictionary. It is an [`crate::L1Address`], not a position in this tree, and the dictionary is
    /// a namespace of rollup addresses -- letting the two share it would mean a later payment could
    /// address a rollup account by a reference that was created by an L1 address, silently
    /// converting between the two. Withdrawing twice to the same L1 account is rare enough that the
    /// 32 bytes are worth paying to keep the namespaces apart.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut dictionary = Dictionary::default();

        buf.push(BATCH_VERSION);
        put_varint(&mut buf, self.txns.len() as u64);

        for txn in &self.txns {
            match txn {
                Transaction::Payment(payment) => {
                    buf.push(KIND_PAYMENT);
                    dictionary.put(&mut buf, &payment.header.sender);
                    dictionary.put(&mut buf, &payment.receiver);
                    put_varint(&mut buf, payment.amount);
                }
                Transaction::Deposit(deposit) => {
                    buf.push(KIND_DEPOSIT);
                    dictionary.put(&mut buf, &deposit.receiver);
                    put_varint(&mut buf, deposit.amount);
                }
                Transaction::Withdrawal(withdrawal) => {
                    buf.push(KIND_WITHDRAWAL);
                    dictionary.put(&mut buf, &withdrawal.header.sender);
                    buf.extend_from_slice(&withdrawal.recipient());
                    put_varint(&mut buf, withdrawal.amount);
                }
                // No amount: a forced withdrawal empties the account, and what that came to is
                // read out of the pre-state during replay. The same move as the omitted nonce and
                // the omitted deposit sender -- if a replaying node can derive it, the chain does
                // not pay to record it.
                Transaction::ForcedWithdrawal(forced) => {
                    buf.push(KIND_FORCED_WITHDRAWAL);
                    dictionary.put(&mut buf, &forced.header.sender);
                    buf.extend_from_slice(&forced.recipient());
                }
            }
        }

        buf
    }

    /// Rebuild a batch from the bytes the chain records.
    ///
    /// This runs in the guest and in every replaying full node, and it is the only place either
    /// one learns what the transactions are.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let mut dictionary = DictionaryReader::default();

        reader.expect_version(BATCH_VERSION)?;
        let count = reader.count(MIN_ENCODED_TXN_SIZE)?;

        let mut txns = Vec::with_capacity(count);
        for _ in 0..count {
            txns.push(match reader.byte()? {
                KIND_PAYMENT => Transaction::Payment(Payment {
                    header: TransactionHeader {
                        sender: dictionary.take(&mut reader)?,
                    },
                    receiver: dictionary.take(&mut reader)?,
                    amount: reader.varint()?,
                }),
                // The sender is not on the wire; `Deposit::new` is what fills it in, so there is
                // one place the marker address is written and no way for the two sides to drift.
                KIND_DEPOSIT => {
                    let receiver = dictionary.take(&mut reader)?;

                    Transaction::Deposit(Deposit::new(receiver, reader.varint()?))
                }
                // The recipient is read literally rather than through the dictionary, so an L1
                // address never enters it and can never be handed back as a rollup address.
                KIND_WITHDRAWAL => {
                    let sender = dictionary.take(&mut reader)?;
                    let recipient = reader.array::<32>()?;

                    Transaction::Withdrawal(Withdrawal::new(
                        sender,
                        recipient,
                        reader.varint()?,
                    ))
                }
                KIND_FORCED_WITHDRAWAL => {
                    let address = dictionary.take(&mut reader)?;

                    Transaction::ForcedWithdrawal(ForcedWithdrawal::new(
                        address,
                        reader.array::<32>()?,
                    ))
                }
                kind => return Err(DecodeError::UnknownTransactionKind(kind)),
            });
        }
        reader.finish()?;

        Ok(Self { txns })
    }
}

fn put_witness(buf: &mut Vec<u8>, witness: &LeafWitness) {
    match &witness.old_account {
        None => buf.push(ABSENT),
        Some(account) => {
            buf.push(PRESENT);
            buf.extend_from_slice(&account.encode());
        }
    }

    let siblings = witness.proof.siblings();
    put_varint(buf, siblings.len() as u64);
    for sibling in siblings {
        buf.extend_from_slice(sibling);
    }

    match witness.proof.slot() {
        Slot::Own => buf.push(SLOT_OWN),
        Slot::Neighbor { address, account } => {
            buf.push(SLOT_NEIGHBOR);
            buf.extend_from_slice(address);
            buf.extend_from_slice(&account.encode());
        }
    }
}

fn take_optional_account(reader: &mut Reader) -> Result<Option<Account>, DecodeError> {
    match reader.byte()? {
        ABSENT => Ok(None),
        PRESENT => Ok(Some(reader.account()?)),
        tag => Err(DecodeError::UnknownPresenceTag(tag)),
    }
}

/// The signature on an entry whose transaction is one somebody had to authorize.
///
/// Shared by the payment and withdrawal entries, which carry identical signature encodings and
/// differ only in how many witnesses follow.
fn take_signature(reader: &mut Reader) -> Result<Signature, DecodeError> {
    let identifier = reader.array::<SCHEME_SIZE>()?;
    let scheme =
        Scheme::from_identifier(&identifier).ok_or(DecodeError::UnknownScheme(identifier))?;

    Ok(Signature {
        scheme,
        pub_key: reader.bytes()?,
        sig: reader.bytes()?,
    })
}

fn take_witness(reader: &mut Reader) -> Result<LeafWitness, DecodeError> {
    let old_account = take_optional_account(reader)?;

    let depth = reader.count(32)?;
    if depth > DEPTH {
        return Err(DecodeError::ProofTooDeep(depth));
    }
    let mut siblings = Vec::with_capacity(depth);
    for _ in 0..depth {
        siblings.push(reader.array::<32>()?);
    }

    let slot = match reader.byte()? {
        SLOT_OWN => Slot::Own,
        SLOT_NEIGHBOR => Slot::Neighbor {
            address: reader.array::<32>()?,
            account: reader.account()?,
        },
        kind => return Err(DecodeError::UnknownSlotKind(kind)),
    };

    Ok(LeafWitness {
        old_account,
        proof: MerkleProof::from_parts(siblings, slot),
    })
}

impl Sidecar {
    /// The bytes handed to the prover alongside the batch, and to nobody else.
    ///
    /// ```text
    /// version    u8 = 0
    /// count      varint
    /// count x, in the shape the batch's transaction of the same index calls for:
    ///   payment
    ///     scheme   3 bytes (Scheme::identifier)
    ///     pub_key  varint length, then bytes
    ///     sig      varint length, then bytes
    ///     sender   witness
    ///     receiver witness
    ///   deposit
    ///     receiver witness
    ///   withdrawal
    ///     scheme   3 bytes (Scheme::identifier)
    ///     pub_key  varint length, then bytes
    ///     sig      varint length, then bytes
    ///     sender   witness
    ///   forced withdrawal
    ///     address  witness
    ///
    /// witness:
    ///   present  u8: 0 absent, 1 followed by a 48-byte account
    ///   depth    varint, then depth x 32-byte siblings
    ///   slot     u8: 0 own, 1 followed by a 32-byte address and a 48-byte account
    /// ```
    ///
    /// There is no kind tag on an entry. The batch already says what each transaction is, and
    /// reading each entry in the shape its transaction demands means an entry paired with the wrong
    /// kind cannot be written down at all -- the same move as taking the count from the batch
    /// rather than the wire, one step further.
    ///
    /// The scheme is written as its [`Scheme::identifier`] rather than a compact tag so there is
    /// no second scheme mapping to drift out of step with address derivation. The three bytes are
    /// free here.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.push(SIDECAR_VERSION);
        put_varint(&mut buf, self.entries.len() as u64);

        for entry in &self.entries {
            match entry {
                TxnSidecar::Payment(entry) => {
                    buf.extend_from_slice(&entry.sig.scheme.identifier());
                    put_bytes(&mut buf, &entry.sig.pub_key);
                    put_bytes(&mut buf, &entry.sig.sig);
                    put_witness(&mut buf, &entry.sender_witness);
                    put_witness(&mut buf, &entry.receiver_witness);
                }
                TxnSidecar::Deposit(entry) => {
                    put_witness(&mut buf, &entry.receiver_witness);
                }
                TxnSidecar::Withdrawal(entry) => {
                    buf.extend_from_slice(&entry.sig.scheme.identifier());
                    put_bytes(&mut buf, &entry.sig.pub_key);
                    put_bytes(&mut buf, &entry.sig.sig);
                    put_witness(&mut buf, &entry.sender_witness);
                }
                TxnSidecar::ForcedWithdrawal(entry) => {
                    put_witness(&mut buf, &entry.sender_witness);
                }
            }
        }

        buf
    }

    /// Rebuild the sidecar belonging to `batch`.
    ///
    /// Taking both the count and the shapes from the batch is what replaces the old pairing of a
    /// transaction with its witnesses in one struct: the batch decodes first, and a sidecar that
    /// does not line up with it is rejected here rather than reaching [`crate::verify_batch`]
    /// misaligned.
    pub fn decode(bytes: &[u8], batch: &Batch) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let expected = batch.len();

        reader.expect_version(SIDECAR_VERSION)?;
        let found = reader.count(MIN_ENCODED_ENTRY_SIZE)?;
        if found != expected {
            return Err(DecodeError::SidecarLengthMismatch { expected, found });
        }

        let mut entries = Vec::with_capacity(found);
        for txn in batch.txns() {
            entries.push(match txn {
                Transaction::Payment(_) => TxnSidecar::Payment(PaymentSidecar {
                    sig: take_signature(&mut reader)?,
                    sender_witness: take_witness(&mut reader)?,
                    receiver_witness: take_witness(&mut reader)?,
                }),
                Transaction::Deposit(_) => TxnSidecar::Deposit(DepositSidecar {
                    receiver_witness: take_witness(&mut reader)?,
                }),
                Transaction::Withdrawal(_) => TxnSidecar::Withdrawal(WithdrawalSidecar {
                    sig: take_signature(&mut reader)?,
                    sender_witness: take_witness(&mut reader)?,
                }),
                Transaction::ForcedWithdrawal(_) => {
                    TxnSidecar::ForcedWithdrawal(ForcedWithdrawalSidecar {
                        sender_witness: take_witness(&mut reader)?,
                    })
                }
            });
        }
        reader.finish()?;

        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{Block, Ledger, SignedTransaction, address_from_public_key, verify_batch};

    const SCHEME: Scheme = Scheme::Managed;

    fn signed(key: &[u8], receiver: Address, amount: u64) -> SignedTransaction {
        SignedTransaction::payment(
            Payment {
                header: TransactionHeader {
                    sender: address_from_public_key(SCHEME, key),
                },
                receiver,
                amount,
            },
            Signature {
                scheme: SCHEME,
                pub_key: key.to_vec(),
                sig: Vec::new(),
            },
        )
    }

    fn deposit(key: &[u8], amount: u64) -> SignedTransaction {
        SignedTransaction::deposit(Deposit::new(address_from_public_key(SCHEME, key), amount))
    }

    fn fund(ledger: &mut Ledger, key: &[u8], amount: u64) -> Address {
        let (address, mut account) = Account::from_public_key(SCHEME, key);
        account.amount = amount;
        ledger.insert_account(address, account);

        address
    }

    /// The payment entry at `index`, for tests that doctor one of its witnesses.
    fn payment_entry(sidecar: &mut Sidecar, index: usize) -> &mut PaymentSidecar {
        match &mut sidecar.entries[index] {
            TxnSidecar::Payment(entry) => entry,
            other => panic!("entry {index} is {other:?}, not a payment"),
        }
    }

    /// A block covering the three witness shapes -- a plain payment, one that brings an account
    /// into existence, and a self-payment -- and, on the encoding side, all three ways an address
    /// can appear: fresh, repeated, and repeated as both sender and receiver.
    fn block() -> Block {
        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", 1_000);
        let b = fund(&mut ledger, b"b key", 500);
        let fresh = address_from_public_key(SCHEME, b"fresh key");

        ledger.get_block(vec![
            signed(b"a key", b, 100),
            signed(b"b key", fresh, 50),
            signed(b"a key", a, 25),
        ])
    }

    #[test]
    fn batch_round_trips() {
        let block = block();

        assert_eq!(Batch::decode(&block.batch.encode()), Ok(block.batch));
    }

    #[test]
    fn sidecar_round_trips() {
        let block = block();
        let bytes = block.sidecar.encode();

        assert_eq!(Sidecar::decode(&bytes, &block.batch), Ok(block.sidecar));
    }

    #[test]
    fn an_empty_block_round_trips() {
        let batch = Batch::default();
        let sidecar = Sidecar::default();

        assert_eq!(Batch::decode(&batch.encode()), Ok(batch.clone()));
        assert_eq!(Sidecar::decode(&sidecar.encode(), &batch), Ok(sidecar));
    }

    // The whole point of the split: the guest is handed the bytes the chain will record, decodes
    // them with the decoder a replaying full node runs, and reaches the root the sequencer claimed
    // -- without ever being told what that root was.
    #[test]
    fn a_block_verifies_from_its_encoded_halves_alone() {
        let block = block();
        let (batch_bytes, sidecar_bytes) = (block.batch.encode(), block.sidecar.encode());

        let batch = Batch::decode(&batch_bytes).unwrap();
        let sidecar = Sidecar::decode(&sidecar_bytes, &batch).unwrap();

        assert_eq!(
            verify_batch(
                block.old_root,
                block.old_deposit_chain,
                block.old_request_chain,
                &batch,
                &sidecar
            ),
            Ok((
                block.new_root,
                block.new_deposit_chain,
                block.withdrawal_chain,
                block.new_request_chain
            ))
        );
    }

    // An address costs 33 bytes the first time a block mentions it and one byte after that, so the
    // three-payment block above -- which mentions three distinct addresses across six slots --
    // comes to:
    //
    //   2   version and count
    //  68   payment 1: kind, two fresh addresses, amount
    //  36   payment 2: kind, a repeat, a fresh address, amount
    //   4   payment 3: kind, two repeats, amount
    #[test]
    fn a_batch_costs_what_the_format_says_it_does() {
        let block = block();
        let batch_bytes = block.batch.encode();

        assert_eq!(batch_bytes.len(), 110);

        // And the sidecar, which nobody pays for, is already an order of magnitude larger over a
        // three-account tree -- where proofs are about one level deep. The gap widens by 64 bytes
        // per transaction for every level the tree grows, so at a million accounts the sidecar runs
        // to roughly 1.4 kB per transaction while the batch stays where it is.
        let sidecar_bytes = block.sidecar.encode();
        assert!(
            sidecar_bytes.len() > 8 * batch_bytes.len(),
            "expected the sidecar to dwarf the batch, got {} vs {}",
            sidecar_bytes.len(),
            batch_bytes.len()
        );
    }

    #[test]
    fn amounts_round_trip_at_the_extremes() {
        let receiver = address_from_public_key(SCHEME, b"receiver");
        for amount in [0, 1, 127, 128, u32::MAX as u64, u64::MAX] {
            let batch = Batch {
                txns: vec![Transaction::Payment(Payment {
                    header: TransactionHeader {
                        sender: address_from_public_key(SCHEME, b"sender"),
                    },
                    receiver,
                    amount,
                })],
            };

            assert_eq!(
                Batch::decode(&batch.encode()),
                Ok(batch),
                "amount {amount} must survive the varint"
            );
        }
    }

    #[test]
    fn a_repeated_address_decodes_to_the_same_address() {
        let block = block();
        let batch = Batch::decode(&block.batch.encode()).unwrap();

        // The third payment is a self-payment encoded as two one-byte references to the same
        // dictionary entry, so a decoder that mishandled references would show up right here.
        assert_eq!(Some(batch.txns[2].sender()), batch.txns[2].receiver());
        assert_eq!(batch.txns[2].sender(), batch.txns[0].sender());
    }

    // A sidecar can only make a transaction fail to prove, never change what it does: the
    // addresses and the amount come from the batch, which is untouched here.
    #[test]
    fn a_doctored_sidecar_cannot_redirect_a_payment() {
        let block = block();
        let mut sidecar = Sidecar::decode(&block.sidecar.encode(), &block.batch).unwrap();
        let TxnSidecar::Payment(entry) = &mut sidecar.entries[0] else {
            panic!("the first transaction of the fixture block is a payment")
        };
        std::mem::swap(&mut entry.sender_witness, &mut entry.receiver_witness);

        assert_eq!(
            verify_batch(
                block.old_root,
                block.old_deposit_chain,
                block.old_request_chain,
                &block.batch,
                &sidecar
            ),
            Err(crate::VerificationError::StaleWitness)
        );
    }

    #[test]
    fn a_batch_with_the_wrong_version_is_rejected() {
        let mut bytes = block().batch.encode();
        bytes[0] = 1;

        assert_eq!(
            Batch::decode(&bytes),
            Err(DecodeError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn an_unknown_transaction_kind_is_rejected() {
        let mut bytes = block().batch.encode();
        // Byte 0 is the version, byte 1 the count, byte 2 the first transaction's kind.
        bytes[2] = 0xff;

        assert_eq!(
            Batch::decode(&bytes),
            Err(DecodeError::UnknownTransactionKind(0xff))
        );
    }

    #[test]
    fn an_unknown_scheme_is_rejected() {
        let block = block();
        let mut bytes = block.sidecar.encode();
        // Byte 0 is the version, byte 1 the count, bytes 2..5 the first entry's scheme.
        bytes[2..5].copy_from_slice(b"???");

        assert_eq!(
            Sidecar::decode(&bytes, &block.batch),
            Err(DecodeError::UnknownScheme(*b"???"))
        );
    }

    #[test]
    fn a_truncated_batch_is_rejected() {
        let bytes = block().batch.encode();

        assert_eq!(
            Batch::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::UnexpectedEnd)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = block().batch.encode();
        bytes.push(0);

        assert_eq!(Batch::decode(&bytes), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn an_address_reference_with_nothing_behind_it_is_rejected() {
        // One payment whose sender is reference 1, with an empty dictionary. The trailing padding
        // is only there to get past the count check.
        let bytes = [BATCH_VERSION, 1, KIND_PAYMENT, 1, 0, 0];

        assert_eq!(
            Batch::decode(&bytes),
            Err(DecodeError::UnknownAddressRef(1))
        );
    }

    #[test]
    fn a_count_the_input_cannot_back_is_rejected_before_allocating() {
        // 65,535 transactions, and nothing at all to decode them from.
        let bytes = [BATCH_VERSION, 0xff, 0xff, 0x03];

        assert_eq!(Batch::decode(&bytes), Err(DecodeError::ImplausibleLength));
    }

    #[test]
    fn an_overlong_varint_is_rejected() {
        let mut bytes = vec![BATCH_VERSION];
        bytes.extend_from_slice(&[0x80; 11]);
        bytes.push(0);

        assert_eq!(Batch::decode(&bytes), Err(DecodeError::MalformedVarint));
    }

    #[test]
    fn a_proof_deeper_than_the_address_space_is_rejected() {
        let mut block = block();
        payment_entry(&mut block.sidecar, 0).sender_witness.proof =
            MerkleProof::from_parts(vec![[0u8; 32]; DEPTH + 1], Slot::Own);

        assert_eq!(
            Sidecar::decode(&block.sidecar.encode(), &block.batch),
            Err(DecodeError::ProofTooDeep(DEPTH + 1))
        );
    }

    /// One payment per pair, all for the same amount.
    fn batch_of(pairs: impl Iterator<Item = (Address, Address)>, amount: u64) -> Batch {
        Batch {
            txns: pairs
                .map(|(sender, receiver)| {
                    Transaction::Payment(Payment {
                        header: TransactionHeader { sender },
                        receiver,
                        amount,
                    })
                })
                .collect(),
        }
    }

    fn distinct_address(n: usize) -> Address {
        crate::address_from_public_key(SCHEME, &n.to_be_bytes())
    }

    /// Bytes per transaction for a thousand payments of one whole unit at six decimals.
    fn per_txn(pairs: impl Iterator<Item = (Address, Address)>) -> f64 {
        batch_of(pairs, 1_000_000).encode().len() as f64 / 1000.0
    }

    // What a payment actually costs, which is:
    //
    //   1 (kind) + sender ref + receiver ref + amount varint + 32 * distinct addresses / txns
    //
    // A reference is one byte for the first 127 addresses a block mentions and two after that. The
    // last term is the whole story: the dictionary only pays off within a block, so a workload
    // where addresses do not repeat is carrying two raw 32-byte addresses per payment. That is a
    // deliberate floor -- addresses are published in full, so a batch can be read on its own
    // without replaying state to find out who was paid.
    #[test]
    fn a_payment_costs_what_address_reuse_says_it_does() {
        let close = |actual: f64, expected: f64| {
            assert!(
                (actual - expected).abs() < 0.01,
                "expected {expected} B/txn, got {actual}"
            );
        };

        // No reuse at all: 1 + 33 + 33 + 3. The realistic case for payments between strangers.
        close(
            per_txn((0..1000).map(|i| (distinct_address(i * 2), distinct_address(i * 2 + 1)))),
            70.00,
        );

        // A hot receiver -- an exchange or a merchant -- halves it: 1 + 33 + 1 + 3.
        close(
            per_txn((0..1000).map(|i| (distinct_address(i), distinct_address(usize::MAX)))),
            38.03,
        );

        // Churn among 128 addresses, where references have just spilled to two bytes.
        close(
            per_txn(
                (0..1000).map(|i| (distinct_address(i % 128), distinct_address((i + 1) % 128))),
            ),
            10.11,
        );

        // Churn among 20: 1 + 1 + 1 + 3, plus 640 literal bytes spread over a thousand payments.
        close(
            per_txn((0..1000).map(|i| (distinct_address(i % 20), distinct_address((i + 1) % 20)))),
            6.64,
        );
    }

    // The amount is the one field whose cost tracks its own magnitude rather than the workload.
    #[test]
    fn the_amount_varint_costs_one_byte_per_seven_bits() {
        let warm = || (0..1000).map(|i| (distinct_address(i % 20), distinct_address((i + 1) % 20)));

        for (amount, expected) in [
            (0u64, 4.64),
            (1_000, 5.64),
            (1_000_000, 6.64),
            (1_000_000_000, 8.64),
            (u64::MAX, 13.64),
        ] {
            let actual = batch_of(warm(), amount).encode().len() as f64 / 1000.0;
            assert!(
                (actual - expected).abs() < 0.01,
                "amount {amount}: expected {expected} B/txn, got {actual}"
            );
        }
    }

    // The pairing that `SignedTransactionWithWitnesses` used to enforce in the type system now
    // lives here, at the wire boundary.
    #[test]
    fn a_sidecar_that_does_not_match_its_batch_is_rejected() {
        let mut block = block();
        let bytes = block.sidecar.encode();
        block.batch.txns.pop();

        assert_eq!(
            Sidecar::decode(&bytes, &block.batch),
            Err(DecodeError::SidecarLengthMismatch {
                expected: 2,
                found: 3,
            })
        );
    }

    #[test]
    fn a_deposit_round_trips() {
        let block = Ledger::new().get_block(vec![deposit(b"a key", 1_000)]);
        let decoded = Batch::decode(&block.batch.encode()).unwrap();

        assert_eq!(decoded, block.batch);

        // The sender is the one field the wire does not carry, so it is the one that can silently
        // drift between the encoder and the decoder.
        assert_eq!(decoded.txns[0].sender(), crate::ZERO_ADDRESS);
    }

    #[test]
    fn a_mixed_batch_round_trips() {
        let mut ledger = Ledger::new();
        let b = address_from_public_key(SCHEME, b"b key");

        let block = ledger.get_block(vec![
            deposit(b"a key", 1_000),
            signed(b"a key", b, 100),
            deposit(b"b key", 7),
        ]);

        assert_eq!(
            Batch::decode(&block.batch.encode()),
            Ok(block.batch.clone())
        );
        assert_eq!(
            Sidecar::decode(&block.sidecar.encode(), &block.batch),
            Ok(block.sidecar)
        );
    }

    // A deposit encodes to three bytes at its smallest, below the four a payment needs. The stride
    // `Reader::count` screens with has to be the minimum over kinds or it rejects valid input --
    // and a batch of nothing but deposits is exactly the shape that trips it.
    #[test]
    fn a_deposit_dense_batch_is_not_rejected_by_the_count_check() {
        let mut ledger = Ledger::new();
        let deposits: Vec<_> = (0..64u8).map(|i| deposit(&[b'k', i], 1_000)).collect();

        let block = ledger.get_block(deposits);
        let bytes = block.batch.encode();

        assert_eq!(Batch::decode(&bytes), Ok(block.batch.clone()));
        assert_eq!(
            Sidecar::decode(&block.sidecar.encode(), &block.batch),
            Ok(block.sidecar)
        );
    }

    fn withdrawal(key: &[u8], recipient: [u8; 32], amount: u64) -> SignedTransaction {
        SignedTransaction::withdrawal(
            Withdrawal::new(address_from_public_key(SCHEME, key), recipient, amount),
            Signature {
                scheme: SCHEME,
                pub_key: key.to_vec(),
                sig: Vec::new(),
            },
        )
    }

    #[test]
    fn a_withdrawal_round_trips() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 10_000_000);
        let block = ledger.get_block(vec![withdrawal(b"a key", [9u8; 32], 250_000)]);

        assert_eq!(
            Batch::decode(&block.batch.encode()),
            Ok(block.batch.clone())
        );
        assert_eq!(
            Sidecar::decode(&block.sidecar.encode(), &block.batch),
            Ok(block.sidecar)
        );
    }

    #[test]
    fn a_batch_of_every_kind_round_trips() {
        let mut ledger = Ledger::new();
        let b = address_from_public_key(SCHEME, b"b key");

        let block = ledger.get_block(vec![
            deposit(b"a key", 10_000_000),
            signed(b"a key", b, 1_000_000),
            withdrawal(b"b key", [9u8; 32], 250_000),
            deposit(b"b key", 7),
        ]);

        let batch = Batch::decode(&block.batch.encode()).unwrap();
        assert_eq!(batch, block.batch);
        assert_eq!(
            Sidecar::decode(&block.sidecar.encode(), &block.batch),
            Ok(block.sidecar)
        );

        // The one thing a round-trip alone would not catch: a withdrawal has no receiver in this
        // tree, and must not come back claiming one.
        assert_eq!(batch.txns[2].receiver(), None);
        assert_eq!(batch.txns[2].sender(), b);
    }

    // The recipient is written literally rather than through the dictionary, so an L1 address never
    // becomes a reference a later *rollup* address could resolve to. Here the two are the same 32
    // bytes, which is the case that would break if the namespaces were shared.
    #[test]
    fn an_l1_recipient_never_enters_the_address_dictionary() {
        let mut ledger = Ledger::new();
        let a = fund(&mut ledger, b"a key", 10_000_000);

        // Withdraw to an L1 address whose bytes happen to equal a rollup address, then pay that
        // rollup address. If the withdrawal had inserted a dictionary entry, the payment's
        // reference numbering would shift and the receiver would decode to the wrong account.
        let block = ledger.get_block(vec![
            withdrawal(b"a key", a, 250_000),
            signed(b"a key", address_from_public_key(SCHEME, b"b key"), 1_000),
        ]);

        let batch = Batch::decode(&block.batch.encode()).unwrap();
        assert_eq!(batch, block.batch);
        assert_eq!(
            batch.txns[1].receiver(),
            Some(address_from_public_key(SCHEME, b"b key"))
        );
    }

    // A withdrawal is a kind tag, a sender reference, 32 literal recipient bytes, and an amount.
    #[test]
    fn a_withdrawal_costs_what_the_format_says_it_does() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 10_000_000);

        // 1 version + 1 count + 1 kind + 33 fresh sender + 32 literal recipient + 3 amount varint
        let cold = ledger.get_block(vec![withdrawal(b"a key", [9u8; 32], 250_000)]);
        assert_eq!(cold.batch.encode().len(), 71);

        // The sender reference warms up; the recipient never does, by design. So a second
        // withdrawal to the same L1 account costs 37 bytes where a second deposit costs 4 -- the
        // price of keeping the two address namespaces apart.
        let warm = ledger.get_block(vec![
            withdrawal(b"a key", [9u8; 32], 250_000),
            withdrawal(b"a key", [9u8; 32], 250_000),
        ]);
        assert_eq!(warm.batch.encode().len(), 71 + 1 + 1 + 32 + 3);
    }

    fn forced(key: &[u8], recipient: [u8; 32]) -> SignedTransaction {
        SignedTransaction::forced_withdrawal(ForcedWithdrawal::new(
            address_from_public_key(SCHEME, key),
            recipient,
        ))
    }

    #[test]
    fn a_forced_withdrawal_round_trips() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 10_000_000);
        let block = ledger.get_block(vec![forced(b"a key", [9u8; 32])]);

        let batch = Batch::decode(&block.batch.encode()).unwrap();
        assert_eq!(batch, block.batch);
        assert_eq!(
            Sidecar::decode(&block.sidecar.encode(), &block.batch),
            Ok(block.sidecar)
        );

        // The amount is the one field the wire does not carry, so it is the one that could drift
        // between the encoder and the decoder without a round-trip noticing.
        assert_eq!(batch.txns[0].amount(), None);
        assert_eq!(
            batch.txns[0].sender(),
            address_from_public_key(SCHEME, b"a key")
        );
    }

    // A forced withdrawal is a kind tag, an address reference, and 32 literal recipient bytes --
    // and no amount at all, which makes it cheaper on-chain than the withdrawal it replaces.
    #[test]
    fn a_forced_withdrawal_costs_what_the_format_says_it_does() {
        let mut ledger = Ledger::new();
        fund(&mut ledger, b"a key", 10_000_000);

        // 1 version + 1 count + 1 kind + 33 fresh address + 32 literal recipient
        let cold = ledger.get_block(vec![forced(b"a key", [9u8; 32])]);
        assert_eq!(cold.batch.encode().len(), 68);
    }

    #[test]
    fn a_batch_of_all_four_kinds_round_trips() {
        let mut ledger = Ledger::new();
        let b = address_from_public_key(SCHEME, b"b key");

        let block = ledger.get_block(vec![
            deposit(b"a key", 10_000_000),
            signed(b"a key", b, 1_000_000),
            withdrawal(b"b key", [9u8; 32], 250_000),
            forced(b"a key", [8u8; 32]),
        ]);

        assert_eq!(
            Batch::decode(&block.batch.encode()),
            Ok(block.batch.clone())
        );
        assert_eq!(
            Sidecar::decode(&block.sidecar.encode(), &block.batch),
            Ok(block.sidecar)
        );
    }

    // A forced withdrawal encodes to 34 bytes at its smallest, above the 3 a deposit needs, so it
    // does not move the floor `Reader::count` screens with. This pins that the floor is still the
    // minimum over every kind.
    #[test]
    fn a_forced_withdrawal_dense_batch_is_not_rejected_by_the_count_check() {
        let mut ledger = Ledger::new();
        let mut stxns = Vec::new();
        for i in 0..32u8 {
            stxns.push(deposit(&[b'k', i], 10_000_000));
        }
        for i in 0..32u8 {
            stxns.push(forced(&[b'k', i], [i; 32]));
        }

        let block = ledger.get_block(stxns);
        assert_eq!(Batch::decode(&block.batch.encode()), Ok(block.batch.clone()));
        assert_eq!(
            Sidecar::decode(&block.sidecar.encode(), &block.batch),
            Ok(block.sidecar)
        );
    }

    // A deposit is a kind tag, an address reference, and an amount -- 37 bytes to an address the
    // batch has not mentioned, 5 to one it has.
    #[test]
    fn a_deposit_costs_what_the_format_says_it_does() {
        let cold = Ledger::new().get_block(vec![deposit(b"a key", 1_000)]);
        // 1 version + 1 count + 1 kind + 33 fresh address + 2 amount varint
        assert_eq!(cold.batch.encode().len(), 38);

        let mut ledger = Ledger::new();
        let warm = ledger.get_block(vec![deposit(b"a key", 1_000), deposit(b"a key", 1_000)]);
        // The second deposit reuses the dictionary entry the first one made: kind, a one-byte
        // reference, and the same two-byte amount.
        assert_eq!(warm.batch.encode().len(), 38 + 4);
    }
}
