//! What a [`Scheme`] means: the key and signature layouts, and the checks a signature has to pass.
//!
//! Everything here is reached through [`crate::Signature::verify`], which the replay calls once per
//! spend. It is the only part of a block that is expensive: a state write is a handful of hashes, a
//! signature is an elliptic curve or a lattice.
//!
//! Nothing in this module knows what is being signed. The message arrives already built by
//! [`crate::Payment::bytes_to_sign`] or [`crate::Withdrawal::bytes_to_sign`], which is where the
//! transaction tag, the deployment domain and the nonce are committed to; a scheme only decides
//! whether a key stands behind those bytes.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};

use crate::{Scheme, VerificationError};

/// An Ed25519 public key: one compressed curve point.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// An Ed25519 signature: a compressed point and a scalar.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// A Falcon-1024 public key, as the deterministic variant encodes one.
pub const FALCON_PUBLIC_KEY_SIZE: usize = falcon_det1024::PUBLIC_KEY_SIZE;

/// The public key of [`Scheme::Falcon1024HybridEd25519`]: the Ed25519 key, then the Falcon key.
///
/// Fixed-width on both sides, and the Ed25519 half first. Every part of that is chosen so the split
/// can be made at a constant offset by whoever has to make it -- including the settlement contract,
/// where `extract` takes constant operands and a variable-length prefix would cost real opcodes.
///
/// One key, not two, because [`crate::address_from_public_key`] hashes the whole thing: an account
/// commits to both halves at once, so there is no way to present one half of a hybrid key and no
/// way for a holder to be talked into registering a Falcon key that does not go with their Ed25519
/// one.
pub const HYBRID_PUBLIC_KEY_SIZE: usize = ED25519_PUBLIC_KEY_SIZE + FALCON_PUBLIC_KEY_SIZE;

/// The shortest thing that could be a hybrid signature: an Ed25519 signature and a Falcon header.
///
/// The Falcon half is variable-length -- see [`falcon_det1024::MAX_SIGNATURE_SIZE`] -- so only the
/// Ed25519 half fixes an offset. That is enough: it comes first, so the split is still at a constant
/// offset and everything after it is the Falcon signature, however long it turned out.
pub const MIN_HYBRID_SIGNATURE_SIZE: usize =
    ED25519_SIGNATURE_SIZE + falcon_det1024::MIN_SIGNATURE_SIZE;

/// The longest a hybrid signature can be.
pub const MAX_HYBRID_SIGNATURE_SIZE: usize =
    ED25519_SIGNATURE_SIZE + falcon_det1024::MAX_SIGNATURE_SIZE;

/// Check that `sig` is `pub_key`'s signature over `message` under `scheme`.
///
/// The key and the signature are both untrusted byte strings of unchecked length: they come off the
/// wire in a [`crate::Sidecar`], which nothing outside this crate has any reason to trust. Every
/// scheme therefore starts by deciding whether it was handed something of the right shape at all --
/// [`VerificationError::MalformedKey`] and [`VerificationError::MalformedSignature`] -- before it
/// asks whether it verifies.
///
/// A key that fails to parse is not a scheme-level accident, incidentally. The address is the hash
/// of the key bytes, so an account whose key is not a key is an account nobody can spend from, and
/// the error is the shape of that: unspendable, not misparsed.
pub(crate) fn verify(
    scheme: Scheme,
    pub_key: &[u8],
    sig: &[u8],
    message: &[u8],
) -> Result<(), VerificationError> {
    match scheme {
        // Nothing to check. A managed account has no key behind its `auth_address` -- the sequencer
        // moves it, and a batch that moves it is a batch the sequencer built -- so there is no
        // signature for a verifier to hold it to. What still holds is everything else in the
        // replay: the witnessed pre-state, the derived nonce, and the roots.
        Scheme::Managed => Ok(()),
        Scheme::Ed25519 => verify_ed25519(as_key(pub_key)?, sig, message),
        Scheme::Falcon1024HybridEd25519 => {
            if pub_key.len() != HYBRID_PUBLIC_KEY_SIZE {
                return Err(VerificationError::MalformedKey);
            }
            if !(MIN_HYBRID_SIGNATURE_SIZE..=MAX_HYBRID_SIGNATURE_SIZE).contains(&sig.len()) {
                return Err(VerificationError::MalformedSignature);
            }

            let (ed25519_key, falcon_key) = pub_key.split_at(ED25519_PUBLIC_KEY_SIZE);
            let (ed25519_sig, falcon_sig) = sig.split_at(ED25519_SIGNATURE_SIZE);

            // Both halves, over the same message, and both have to pass: the point of the hybrid is
            // that forging one signature requires breaking Ed25519 *and* Falcon -- the classical
            // half in case the lattice assumption falls, the post-quantum half in case the curve
            // does.
            //
            // Ed25519 first because it is the cheap one, and this runs in a zkVM where the
            // difference is measured in cycles. A hybrid signature that fails both is rejected for
            // whichever failure was reached first, which nothing depends on.
            verify_ed25519(as_key(ed25519_key)?, ed25519_sig, message)?;

            if falcon_det1024::verify_compressed(falcon_sig, as_key(falcon_key)?, message) {
                Ok(())
            } else {
                Err(VerificationError::InvalidSignature)
            }
        }
    }
}

/// Reinterpret an untrusted key as the fixed-size key a scheme's verifier takes.
fn as_key<const SIZE: usize>(pub_key: &[u8]) -> Result<&[u8; SIZE], VerificationError> {
    pub_key
        .try_into()
        .map_err(|_| VerificationError::MalformedKey)
}

/// Check one Ed25519 signature, strictly.
///
/// Strictly meaning [`VerifyingKey::verify_strict`]: small-order and non-canonically encoded keys
/// and `R` values are refused rather than verified around. That matters here because the settlement
/// contract checks signatures too -- `ed25519verify_bare`, over libsodium, which makes the same
/// refusals -- and a key the rollup accepted but L1 would not is a key whose holder could spend
/// inside the rollup and then be unable to prove ownership on the way out.
///
/// It costs nothing to be strict: the excluded keys are keys nobody chooses and nobody can spend
/// from, since the address commits to the key bytes.
fn verify_ed25519(
    pub_key: &[u8; ED25519_PUBLIC_KEY_SIZE],
    sig: &[u8],
    message: &[u8],
) -> Result<(), VerificationError> {
    let sig: &[u8; ED25519_SIGNATURE_SIZE] = sig
        .try_into()
        .map_err(|_| VerificationError::MalformedSignature)?;

    VerifyingKey::from_bytes(pub_key)
        .map_err(|_| VerificationError::MalformedKey)?
        .verify_strict(message, &Ed25519Signature::from_bytes(sig))
        .map_err(|_| VerificationError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        Account, Address, Block, DeploymentDomain, Deposit, L1Address, LeafWitness, Ledger,
        Payment, PaymentSidecar, Signature, SignedTransaction, TxnSidecar, Withdrawal,
        verify_block,
    };

    /// A domain with no zero bytes in it, so a test that dropped the domain from a preimage would
    /// have to notice.
    const TEST_DOMAIN: DeploymentDomain = [0x42; 32];

    const MESSAGE: &[u8] = b"the bytes a sender signs";

    /// A key pair for one scheme, derived from a seed.
    ///
    /// Every key here comes from `Sha256(seed)`, so a test names a key by what it is for rather
    /// than by 1825 bytes of key material, and two runs of the suite use the same keys. Falcon key
    /// generation is deterministic for the same reason its signing is -- see the note on
    /// determinism in `falcon-det1024` -- so "the same keys" means the same bytes, not merely keys
    /// that work.
    // A Falcon private key is 2305 bytes and the enum is as large as its largest variant, which is
    // nothing to a test holding one key at a time.
    #[allow(clippy::large_enum_variant)]
    enum TestKey {
        Managed(Vec<u8>),
        Ed25519(SigningKey),
        Hybrid(SigningKey, falcon_det1024::SigningKey),
    }

    impl TestKey {
        fn new(scheme: Scheme, seed: &[u8]) -> Self {
            let seed: [u8; 32] = Sha256::digest(seed).into();

            match scheme {
                Scheme::Managed => TestKey::Managed(seed.to_vec()),
                Scheme::Ed25519 => TestKey::Ed25519(SigningKey::from_bytes(&seed)),
                Scheme::Falcon1024HybridEd25519 => TestKey::Hybrid(
                    SigningKey::from_bytes(&seed),
                    falcon_det1024::SigningKey::from_seed(&seed),
                ),
            }
        }

        fn scheme(&self) -> Scheme {
            match self {
                TestKey::Managed(_) => Scheme::Managed,
                TestKey::Ed25519(_) => Scheme::Ed25519,
                TestKey::Hybrid(..) => Scheme::Falcon1024HybridEd25519,
            }
        }

        fn pub_key(&self) -> Vec<u8> {
            match self {
                TestKey::Managed(key) => key.clone(),
                TestKey::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
                TestKey::Hybrid(ed25519, falcon) => {
                    let mut key = ed25519.verifying_key().to_bytes().to_vec();
                    key.extend_from_slice(falcon.public_key());

                    key
                }
            }
        }

        fn address(&self) -> Address {
            crate::address_from_public_key(self.scheme(), &self.pub_key())
        }

        /// The signature bytes alone, in the layout the scheme calls for.
        fn sign_bytes(&self, message: &[u8]) -> Vec<u8> {
            match self {
                TestKey::Managed(_) => Vec::new(),
                TestKey::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
                TestKey::Hybrid(ed25519, falcon) => {
                    let mut sig = ed25519.sign(message).to_bytes().to_vec();
                    sig.extend_from_slice(&falcon.sign_compressed(message));

                    sig
                }
            }
        }

        fn sign(&self, message: &[u8]) -> Signature {
            Signature::new(self.scheme(), self.pub_key(), self.sign_bytes(message))
        }
    }

    /// Check a signature the way [`crate::Signature::verify`] would, minus the account.
    fn check(key: &TestKey, sig: &[u8], message: &[u8]) -> Result<(), VerificationError> {
        verify(key.scheme(), &key.pub_key(), sig, message)
    }

    #[test]
    fn every_scheme_accepts_a_signature_over_the_message_it_was_made_for() {
        for scheme in Scheme::ALL {
            let key = TestKey::new(scheme, b"a signing key");

            assert_eq!(check(&key, &key.sign_bytes(MESSAGE), MESSAGE), Ok(()));
        }
    }

    #[test]
    fn a_signature_does_not_carry_over_to_another_message() {
        // Managed is absent on purpose: it has no signature to be about a message, which is what
        // the next test is about.
        for scheme in [Scheme::Ed25519, Scheme::Falcon1024HybridEd25519] {
            let key = TestKey::new(scheme, b"a signing key");
            let sig = key.sign_bytes(MESSAGE);

            assert_eq!(
                check(&key, &sig, b"different bytes"),
                Err(VerificationError::InvalidSignature)
            );
        }
    }

    #[test]
    fn a_signature_does_not_carry_over_to_another_key() {
        for scheme in [Scheme::Ed25519, Scheme::Falcon1024HybridEd25519] {
            let key = TestKey::new(scheme, b"a signing key");
            let other = TestKey::new(scheme, b"another signing key");

            assert_eq!(
                check(&other, &key.sign_bytes(MESSAGE), MESSAGE),
                Err(VerificationError::InvalidSignature)
            );
        }
    }

    // A managed account is the sequencer's, so there is no key to check and nothing presented here
    // can be wrong. Pinned by a test because it is the one scheme where "verified" means "not
    // checked", and that had better be deliberate.
    #[test]
    fn a_managed_account_accepts_anything_because_nothing_stands_behind_it() {
        let key = TestKey::new(Scheme::Managed, b"a managed account");

        for sig in [[].as_slice(), b"not a signature", &[0xff; 64]] {
            assert_eq!(check(&key, sig, MESSAGE), Ok(()));
        }
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_malformed_rather_than_invalid() {
        let ed25519 = TestKey::new(Scheme::Ed25519, b"a signing key");
        let sig = ed25519.sign_bytes(MESSAGE);

        for length in [0, 1, ED25519_SIGNATURE_SIZE - 1, ED25519_SIGNATURE_SIZE + 1] {
            let mut truncated = sig.clone();
            truncated.resize(length, 0);

            assert_eq!(
                check(&ed25519, &truncated, MESSAGE),
                Err(VerificationError::MalformedSignature)
            );
        }

        let hybrid = TestKey::new(Scheme::Falcon1024HybridEd25519, b"a signing key");
        let sig = hybrid.sign_bytes(MESSAGE);

        // The Falcon half is variable-length, so what is checked is the range it may fall in: an
        // Ed25519 signature with nothing after it at one end, and the format's own bound at the
        // other.
        for length in [
            0,
            ED25519_SIGNATURE_SIZE,
            MIN_HYBRID_SIGNATURE_SIZE - 1,
            MAX_HYBRID_SIGNATURE_SIZE + 1,
        ] {
            let mut resized = sig.clone();
            resized.resize(length, 0);

            assert_eq!(
                check(&hybrid, &resized, MESSAGE),
                Err(VerificationError::MalformedSignature)
            );
        }

        // Inside the range but not the signature it was: a truncated Falcon half is a signature of
        // a plausible length that does not verify.
        let mut truncated = sig.clone();
        truncated.truncate(sig.len() - 1);
        assert_eq!(
            check(&hybrid, &truncated, MESSAGE),
            Err(VerificationError::InvalidSignature)
        );
    }

    #[test]
    fn a_key_of_the_wrong_length_is_malformed() {
        for scheme in Scheme::ALL {
            let key = TestKey::new(scheme, b"a signing key");
            let sig = key.sign_bytes(MESSAGE);

            for length in [0, key.pub_key().len() - 1, key.pub_key().len() + 1] {
                let mut resized = key.pub_key();
                resized.resize(length, 0);

                let result = verify(scheme, &resized, &sig, MESSAGE);

                // Managed reads neither the key nor the signature, so it has no length to be wrong
                // about. Every other scheme does.
                if scheme == Scheme::Managed {
                    assert_eq!(result, Ok(()));
                } else {
                    assert_eq!(result, Err(VerificationError::MalformedKey));
                }
            }
        }
    }

    // The address is a hash of the key bytes, so nothing stops an account from being created at the
    // address of 32 bytes that are not a public key. Such an account is simply unspendable, and
    // this is the error that says so -- rather than a panic, or an accepted signature.
    #[test]
    fn a_key_that_is_not_a_curve_point_is_malformed() {
        // Not a decompressible Edwards y-coordinate.
        let not_a_point = [0x02u8; ED25519_PUBLIC_KEY_SIZE];

        assert_eq!(
            verify(
                Scheme::Ed25519,
                &not_a_point,
                &[0u8; ED25519_SIGNATURE_SIZE],
                MESSAGE
            ),
            Err(VerificationError::MalformedKey)
        );
    }

    // `verify_strict` refuses small-order keys, which is what the settlement contract's
    // `ed25519verify_bare` does too. Agreement between the two is the point: a key that could spend
    // inside the rollup but not prove itself on L1 would be a hole in the escape hatch.
    #[test]
    fn a_small_order_key_cannot_be_signed_for() {
        // The identity point: y = 1, which decompresses fine and has order one.
        let mut identity = [0u8; ED25519_PUBLIC_KEY_SIZE];
        identity[0] = 1;

        assert_eq!(
            verify(
                Scheme::Ed25519,
                &identity,
                &[0u8; ED25519_SIGNATURE_SIZE],
                MESSAGE
            ),
            Err(VerificationError::InvalidSignature)
        );
    }

    // The claim the hybrid exists for: neither half is decorative. Each is replaced in turn with
    // one that is perfectly valid on its own terms but made by the wrong key, and each replacement
    // has to be caught -- otherwise the scheme is only as strong as the half that is really checked.
    #[test]
    fn a_hybrid_signature_needs_both_of_its_halves() {
        let key = TestKey::new(Scheme::Falcon1024HybridEd25519, b"a signing key");
        let other = TestKey::new(Scheme::Falcon1024HybridEd25519, b"another signing key");

        let sig = key.sign_bytes(MESSAGE);
        let (ed25519, falcon) = sig.split_at(ED25519_SIGNATURE_SIZE);
        let (other_ed25519, other_falcon) = {
            let other_sig = other.sign_bytes(MESSAGE);
            let (left, right) = other_sig.split_at(ED25519_SIGNATURE_SIZE);

            (left.to_vec(), right.to_vec())
        };

        let mut wrong_curve_half = other_ed25519;
        wrong_curve_half.extend_from_slice(falcon);
        assert_eq!(
            check(&key, &wrong_curve_half, MESSAGE),
            Err(VerificationError::InvalidSignature)
        );

        let mut wrong_lattice_half = ed25519.to_vec();
        wrong_lattice_half.extend_from_slice(&other_falcon);
        assert_eq!(
            check(&key, &wrong_lattice_half, MESSAGE),
            Err(VerificationError::InvalidSignature)
        );

        // And the halves cannot be swapped for each other's positions, which the fixed-width
        // Ed25519 prefix is what rules out.
        let mut swapped = falcon.to_vec();
        swapped.extend_from_slice(ed25519);
        assert!(check(&key, &swapped, MESSAGE).is_err());
    }

    /// A block containing a deposit to `key`, a payment out of it, and a withdrawal of what is
    /// left, all signed by `key` at the nonces the sequencer will assign.
    ///
    /// The nonces are written out rather than derived: a deposit does not advance one, so the
    /// payment signs nonce 1 and the withdrawal signs nonce 2. Getting either wrong is a panic out
    /// of the ledger rather than a silent pass -- see [`Ledger::debit`].
    fn signed_block(key: &TestKey, receiver: Address) -> Block {
        let mut ledger = Ledger::with_domain(TEST_DOMAIN);

        let payment = Payment::new(key.address(), receiver, 400_000);
        let withdrawal = Withdrawal::new(key.address(), l1(7), 500_000);

        ledger.get_block(vec![
            SignedTransaction::deposit(Deposit::new(key.address(), 1_000_000)),
            SignedTransaction::payment(payment, key.sign(&payment.bytes_to_sign(&TEST_DOMAIN, 1))),
            SignedTransaction::withdrawal(
                withdrawal,
                key.sign(&withdrawal.bytes_to_sign(&TEST_DOMAIN, 2)),
            ),
        ])
    }

    fn l1(seed: u8) -> L1Address {
        [seed; 32]
    }

    /// The signature on the payment in a block from [`signed_block`], for a test that replaces it.
    fn payment_sig(block: &mut Block) -> &mut Signature {
        match &mut block.sidecar.entries[1] {
            TxnSidecar::Payment(entry) => &mut entry.sig,
            other => panic!("the second entry is {other:?}, not a payment"),
        }
    }

    // The end-to-end claim, for every scheme: a block whose spends are signed by real keys replays
    // from its own roots. Managed included, where "signed" means the sequencer said so.
    #[test]
    fn a_block_signed_by_every_scheme_verifies() {
        for scheme in Scheme::ALL {
            let key = TestKey::new(scheme, b"a signing key");
            let block = signed_block(&key, TestKey::new(scheme, b"a receiver").address());

            assert_eq!(verify_block(&block), Ok(()), "{scheme:?}");
        }
    }

    // What the nonce is for. It is not on the wire -- the replay derives it from the witnessed
    // account -- so a signature is only ever valid at one exact point in that account's history,
    // and a replayed one lands at a different point and fails.
    #[test]
    fn a_signature_is_valid_at_exactly_one_nonce() {
        let key = TestKey::new(Scheme::Ed25519, b"a signing key");
        let receiver = TestKey::new(Scheme::Ed25519, b"a receiver").address();

        for nonce in [0, 2, 3] {
            let mut block = signed_block(&key, receiver);
            let payment = Payment::new(key.address(), receiver, 400_000);
            *payment_sig(&mut block) = key.sign(&payment.bytes_to_sign(&TEST_DOMAIN, nonce));

            assert_eq!(
                verify_block(&block),
                Err(VerificationError::InvalidSignature),
                "a signature over nonce {nonce} was accepted at nonce 1"
            );
        }
    }

    // What the deployment domain is for: a signature made for one rollup cannot spend in another,
    // even one holding an account at the same address with the same key.
    #[test]
    fn a_signature_does_not_cross_deployments() {
        let key = TestKey::new(Scheme::Ed25519, b"a signing key");
        let receiver = TestKey::new(Scheme::Ed25519, b"a receiver").address();

        let mut block = signed_block(&key, receiver);
        let payment = Payment::new(key.address(), receiver, 400_000);
        *payment_sig(&mut block) = key.sign(&payment.bytes_to_sign(&[0x43; 32], 1));

        assert_eq!(
            verify_block(&block),
            Err(VerificationError::InvalidSignature)
        );
    }

    // What the transaction tag is for. The two preimages agree in every field -- sender, nonce, the
    // 32-byte destination, the amount -- so without the tag this signature would authorize moving
    // the money out of the rollup instead of across it.
    #[test]
    fn a_withdrawal_signature_cannot_authorize_a_payment() {
        let key = TestKey::new(Scheme::Ed25519, b"a signing key");
        let receiver = TestKey::new(Scheme::Ed25519, b"a receiver").address();

        let mut block = signed_block(&key, receiver);
        let same_by_another_name = Withdrawal::new(key.address(), receiver, 400_000);
        *payment_sig(&mut block) = key.sign(&same_by_another_name.bytes_to_sign(&TEST_DOMAIN, 1));

        assert_eq!(
            verify_block(&block),
            Err(VerificationError::InvalidSignature)
        );
    }

    // A signature that is valid, over the right message, by a key that does not control the
    // account. Caught before the curve is touched, which is why the error names the authority
    // rather than the signature.
    #[test]
    fn a_valid_signature_by_the_wrong_key_is_an_authority_failure() {
        let key = TestKey::new(Scheme::Ed25519, b"a signing key");
        let receiver = TestKey::new(Scheme::Ed25519, b"a receiver").address();
        let attacker = TestKey::new(Scheme::Ed25519, b"an attacker");

        let mut block = signed_block(&key, receiver);
        let payment = Payment::new(key.address(), receiver, 400_000);
        *payment_sig(&mut block) = attacker.sign(&payment.bytes_to_sign(&TEST_DOMAIN, 1));

        assert_eq!(
            verify_block(&block),
            Err(VerificationError::InvalidAuthAddress)
        );
    }

    // Flipping one bit anywhere in the signature is enough, which is the whole point of asking.
    #[test]
    fn a_doctored_signature_is_rejected() {
        let key = TestKey::new(Scheme::Ed25519, b"a signing key");
        let receiver = TestKey::new(Scheme::Ed25519, b"a receiver").address();

        for byte in [0, 32, ED25519_SIGNATURE_SIZE - 1] {
            let mut block = signed_block(&key, receiver);
            payment_sig(&mut block).sig[byte] ^= 1;

            assert_eq!(
                verify_block(&block),
                Err(VerificationError::InvalidSignature),
                "byte {byte} of the signature was not covered"
            );
        }
    }

    // A withdrawal is signed like any other spend, and the sidecar is where its signature lives, so
    // the withdrawal arm needs its own version of the check above rather than inheriting it.
    #[test]
    fn a_withdrawal_needs_a_signature_of_its_own() {
        let key = TestKey::new(Scheme::Ed25519, b"a signing key");
        let mut block = signed_block(&key, TestKey::new(Scheme::Ed25519, b"a receiver").address());

        match &mut block.sidecar.entries[2] {
            TxnSidecar::Withdrawal(entry) => entry.sig.sig[0] ^= 1,
            other => panic!("the third entry is {other:?}, not a withdrawal"),
        }

        assert_eq!(
            verify_block(&block),
            Err(VerificationError::InvalidSignature)
        );
    }

    // Authorization is settled before the balance is, so an unaffordable spend nobody signed for is
    // reported as the forgery it is. Both checks would reject this block; which one answers is what
    // says where the rule lives.
    #[test]
    fn an_unsigned_spend_is_a_forgery_before_it_is_a_shortfall() {
        let key = TestKey::new(Scheme::Ed25519, b"a signing key");
        let receiver = TestKey::new(Scheme::Ed25519, b"a receiver").address();
        let mut ledger = Ledger::with_domain(TEST_DOMAIN);

        // Hand-built, because the ledger would refuse to build it: the account holds one
        // microALGO and the payment spends four hundred thousand of them.
        let payment = Payment::new(key.address(), receiver, 400_000);
        let block = ledger.get_block(vec![SignedTransaction::deposit(Deposit::new(
            key.address(),
            1,
        ))]);

        let sender_witness = LeafWitness {
            old_account: Some(Account::new(0, 1, key.address())),
            proof: ledger.proof(&key.address()),
        };
        let receiver_witness = LeafWitness {
            old_account: None,
            proof: ledger.proof(&receiver),
        };

        let batch = crate::Batch {
            txns: vec![crate::Transaction::Payment(payment)],
        };
        let sidecar = crate::Sidecar {
            entries: vec![TxnSidecar::Payment(PaymentSidecar {
                sig: key.sign(b"something else entirely"),
                sender_witness,
                receiver_witness,
            })],
        };

        assert_eq!(
            crate::verify_batch(
                &TEST_DOMAIN,
                block.new_root(),
                block.new_inbox_chain(),
                &batch,
                &sidecar
            ),
            Err(VerificationError::InvalidSignature)
        );
    }

    // The sequencer checks signatures as it builds, so a block it cannot prove is one it refuses to
    // build. This is the same check as the replay's, reached from the other side.
    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn the_ledger_refuses_to_build_a_block_it_could_not_prove() {
        let key = TestKey::new(Scheme::Ed25519, b"a signing key");
        let receiver = TestKey::new(Scheme::Ed25519, b"a receiver").address();
        let mut ledger = Ledger::with_domain(TEST_DOMAIN);

        let payment = Payment::new(key.address(), receiver, 400_000);

        ledger.get_block(vec![
            SignedTransaction::deposit(Deposit::new(key.address(), 1_000_000)),
            SignedTransaction::payment(payment, key.sign(b"not this payment")),
        ]);
    }
}
