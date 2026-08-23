//! Deterministic Falcon-1024 -- "det1024" -- as Algorand implements it.
//!
//! A safe wrapper over the C library in `falcon/`, a submodule of
//! <https://github.com/algorand/falcon>. Wrapping the same code the settlement chain runs rather
//! than reimplementing the scheme is the whole point: a signature this crate accepts is one the
//! AVM's `falcon_verify` accepts, so a key that can spend inside the rollup can also present itself
//! to the settlement contract, and neither side has to be taught what the other considers valid.
//!
//! The pin is upstream `master`, which is ahead of the `v0.1.0` that go-algorand depends on. The
//! difference is hardening rather than behaviour: bounds checks around the untrusted signature
//! length, including one in the very function called here where `v0.1.0` computes a length before
//! checking it. No signature either version accepts is a signature the other rejects, which is what
//! agreement with L1 rests on -- and the stricter of the two is the one to be holding when the input
//! comes from whoever built the block.
//!
//! # What det1024 is
//!
//! Falcon-1024 with the salt removed. An ordinary Falcon signature carries a 40-byte random nonce,
//! so signing the same message twice gives two different signatures; det1024 replaces the nonce with
//! a fixed salt selected by a one-byte version, which makes signing a function of the key and the
//! message alone. It also changes the header byte, so the two are not mistakable for each other --
//! a salted signature simply fails to verify here.
//!
//! # Format
//!
//! The compressed format, variable-length and at most [`MAX_SIGNATURE_SIZE`] bytes, because it is
//! the one `falcon_verify` on L1 takes. The library also implements a fixed-size "CT" format, which
//! is larger and which the AVM will not accept, so nothing here produces or checks it.
//!
//! # Determinism
//!
//! Signing and key generation use floating point, and the C library is compiled with
//! `FALCON_FPEMU=1` so that arithmetic is emulated in integers rather than handed to whatever
//! floating-point unit the machine has. That is the library's own recommendation for deterministic
//! signing, and it is what lets `SigningKey::from_seed` produce the same key on a laptop as in a
//! zkVM guest. Verification is integer-only and unaffected.
//!
//! # Building
//!
//! `falcon/` is a git submodule, so a fresh clone needs `git submodule update --init` before this
//! crate will build; `build.rs` says so rather than failing obscurely.
//!
//! Being C, it also has to be compiled for whatever target the crate is built for, and that is
//! worth knowing before a guest build fails: the zkVM target needs a RISC-V C compiler, which the
//! `cc` crate finds through `CC_riscv32im_succinct_zkvm_elf` (or the toolchain's own
//! `riscv32-unknown-elf-gcc`) rather than inventing. What it asks of that toolchain is small: the
//! compiled objects reference `memcpy`, `memmove` and `memset` and nothing else outside themselves.
//! With `FALCON_FPEMU` there is no libm to find, and with `FALCON_RAND_*` compiled out there is no
//! entropy source, no file I/O and no allocation -- every buffer, including Falcon's
//! several-kilobyte scratch space, is on the stack.

use std::ffi::{c_int, c_void};

/// A det1024 public key, which is a fixed-size encoding of one ring element.
pub const PUBLIC_KEY_SIZE: usize = 1793;

/// A det1024 private key.
pub const PRIVATE_KEY_SIZE: usize = 2305;

/// The longest a compressed det1024 signature can be.
///
/// Compressed signatures are variable-length -- the encoding is entropy-coded, so how long one
/// comes out depends on the key and the message -- and this is the bound the format allows rather
/// than a size anything actually reaches. Real signatures land a little over a hundred bytes short
/// of it.
pub const MAX_SIGNATURE_SIZE: usize = 1423;

/// The shortest byte string [`verify_compressed`] will look past the header of.
///
/// A header byte and a salt version, with no signature after them. Nothing this short can verify;
/// it is the point below which there is not even a well-formed thing to reject.
pub const MIN_SIGNATURE_SIZE: usize = 2;

/// First byte of every compressed det1024 signature.
///
/// The ordinary Falcon compressed header with its top bit set, which is what makes a deterministic
/// signature and a salted one distinguishable at a glance -- and unmistakable to a verifier, since
/// each rejects the other's header outright.
pub const SIGNATURE_HEADER: u8 = 0xba;

/// The salt version this crate signs with, and the only one it has ever seen.
///
/// The second byte of a signature. It exists so that a change to the signing algorithm can be
/// deployed without the result being confusable with what came before; the C library bumps it, and a
/// verifier built against an older version rejects the newer signatures rather than misreading
/// them.
pub const CURRENT_SALT_VERSION: u8 = 0;

/// The C library's SHAKE-256 context, whose contents are opaque by design.
///
/// Declared here only so it can be allocated with the right size and alignment; every field is the
/// C side's business. Its size is checked against `sizeof(shake256_context)` by a test.
#[cfg(feature = "sign")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Shake256Context {
    opaque_contents: [u64; 26],
}

#[cfg(feature = "sign")]
impl Shake256Context {
    const fn zeroed() -> Self {
        Self {
            opaque_contents: [0u64; 26],
        }
    }
}

// SAFETY: this is the declaration from `falcon/deterministic.h`. Each pointer is a buffer of the
// length the neighbouring argument states, which is what the one call site below is responsible for
// getting right.
unsafe extern "C" {
    fn falcon_det1024_verify_compressed(
        sig: *const c_void,
        sig_len: usize,
        pubkey: *const c_void,
        data: *const c_void,
        data_len: usize,
    ) -> c_int;
}

// The signing half of the library, declared only where it can be reached. The C archive holds it
// regardless -- see the `sign` feature in `Cargo.toml` -- but a build that cannot name these
// functions cannot call them by accident either.
//
// SAFETY: as above, these are the declarations from `falcon/deterministic.h` and `falcon/falcon.h`,
// with every buffer's length either the neighbouring argument or the size of the type.
#[cfg(feature = "sign")]
unsafe extern "C" {
    fn falcon_det1024_keygen(
        rng: *mut Shake256Context,
        privkey: *mut c_void,
        pubkey: *mut c_void,
    ) -> c_int;

    fn falcon_det1024_sign_compressed(
        sig: *mut c_void,
        sig_len: *mut usize,
        privkey: *const c_void,
        data: *const c_void,
        data_len: usize,
    ) -> c_int;

    fn shake256_init_prng_from_seed(
        ctx: *mut Shake256Context,
        seed: *const c_void,
        seed_len: usize,
    );

    fn shake256_extract(ctx: *mut Shake256Context, out: *mut c_void, len: usize);
}

/// Whether `signature` is a valid compressed det1024 signature over `message` under `public_key`.
///
/// Everything about `signature` is untrusted, including its length: a signature arrives from
/// whoever built the block, and this is the function that decides whether it authorizes anything.
/// The C library checks the header byte and bounds the length before it decodes anything, so an
/// arbitrary byte string is answered with `false` rather than read past.
#[must_use]
pub fn verify_compressed(
    signature: &[u8],
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
) -> bool {
    // SAFETY: `signature` and `message` are passed with their own lengths, and `public_key` is
    // exactly the `FALCON_DET1024_PUBKEY_SIZE` bytes the C side reads -- guaranteed by its type,
    // and by the test that pins that constant against the header. Nothing is written through any of
    // the three, all of which outlive the call.
    let result = unsafe {
        falcon_det1024_verify_compressed(
            signature.as_ptr().cast(),
            signature.len(),
            public_key.as_ptr().cast(),
            message.as_ptr().cast(),
            message.len(),
        )
    };

    result == 0
}

/// A SHAKE-256 stream, the source of randomness the C library's key generator takes.
///
/// Seeded rather than drawn from the system: the library is compiled with every system entropy
/// source disabled, so a seed is the only way to get one. A test or a fixture builder wants exactly
/// that -- the same seed gives the same key every time, which is what makes a Falcon key writable
/// down as one line rather than as 2305 bytes.
#[cfg(feature = "sign")]
pub struct Prng(Shake256Context);

#[cfg(feature = "sign")]
impl Prng {
    /// A stream seeded with `seed`, ready to produce bytes.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut context = Shake256Context::zeroed();

        // SAFETY: `context` is a live, correctly sized C context, and `seed` is passed with its own
        // length.
        unsafe { shake256_init_prng_from_seed(&mut context, seed.as_ptr().cast(), seed.len()) };

        Self(context)
    }

    /// Fill `out` with the stream's next bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        // SAFETY: `out` is a live buffer passed with its own length, and `self.0` was initialized
        // and flipped to output mode by `from_seed`, which is the only way to build one.
        unsafe { shake256_extract(&mut self.0, out.as_mut_ptr().cast(), out.len()) };
    }
}

/// A det1024 private key, with the public key it goes with.
///
/// Only ever built here, from a seed or a [`Prng`], because that is all the C library will do
/// without a system entropy source -- see [`Prng`]. Signing is deterministic, so a key plus a
/// message is a signature, with nothing else to record.
#[cfg(feature = "sign")]
pub struct SigningKey {
    private: [u8; PRIVATE_KEY_SIZE],
    public: [u8; PUBLIC_KEY_SIZE],
}

#[cfg(feature = "sign")]
impl SigningKey {
    /// The key `seed` generates, which is the same key every time.
    pub fn from_seed(seed: &[u8]) -> Self {
        Self::generate(&mut Prng::from_seed(seed))
    }

    /// The key `rng`'s next output generates.
    ///
    /// Takes the stream rather than a seed for the one case that needs it: reproducing the C
    /// library's own test vectors, which draw a key and a message from two separate streams.
    pub fn generate(rng: &mut Prng) -> Self {
        let mut key = Self {
            private: [0u8; PRIVATE_KEY_SIZE],
            public: [0u8; PUBLIC_KEY_SIZE],
        };

        // SAFETY: both buffers are exactly the sizes the C side writes, and `rng` is an initialized
        // context. Key generation cannot fail for a valid `logn`, which det1024 fixes at 10.
        let result = unsafe {
            falcon_det1024_keygen(
                &mut rng.0,
                key.private.as_mut_ptr().cast(),
                key.public.as_mut_ptr().cast(),
            )
        };
        assert_eq!(result, 0, "falcon_det1024_keygen failed with {result}");

        key
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.public
    }

    /// The compressed det1024 signature over `message`.
    ///
    /// Deterministic: the same key and message give the same bytes, on any machine -- see the note
    /// on determinism in the crate documentation.
    pub fn sign_compressed(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = [0u8; MAX_SIGNATURE_SIZE];
        let mut length = signature.len();

        // SAFETY: `signature` is `FALCON_DET1024_SIG_COMPRESSED_MAXSIZE` bytes, which is the buffer
        // the C side requires; `length` receives how much of it was written; the private key is
        // exactly the size read; and `message` is passed with its own length.
        let result = unsafe {
            falcon_det1024_sign_compressed(
                signature.as_mut_ptr().cast(),
                &mut length,
                self.private.as_ptr().cast(),
                message.as_ptr().cast(),
                message.len(),
            )
        };
        assert_eq!(
            result, 0,
            "falcon_det1024_sign_compressed failed with {result}"
        );

        signature[..length].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::c_uint;

    use super::*;

    // The sizes `src/sizes.c` reads out of the submodule's headers. Declared here rather than
    // beside the library's own entry points because nothing outside this module has any business
    // asking: a size that disagrees with the constants above is a build to abandon, not a case to
    // handle.
    unsafe extern "C" {
        fn falcon_det1024_rs_pubkey_size() -> usize;
        fn falcon_det1024_rs_privkey_size() -> usize;
        fn falcon_det1024_rs_sig_compressed_maxsize() -> usize;
        #[cfg(feature = "sign")]
        fn falcon_det1024_rs_shake256_context_size() -> usize;
        fn falcon_det1024_rs_sig_compressed_header() -> c_uint;
        fn falcon_det1024_rs_current_salt_version() -> c_uint;
    }

    /// How many of the library's 512 test vectors are reproduced below.
    ///
    /// Enough to cover the interesting variable, which is the message: vector `n` signs a message
    /// of `n` bytes, so this reaches from the empty message to a short one. Every vector costs a key
    /// generation, which is the expensive half of Falcon, and the failure they would catch -- a
    /// build whose arithmetic does not agree with the reference implementation's -- is not one that
    /// waits until vector 300 to show itself.
    #[cfg(feature = "sign")]
    const KATS: usize = 8;

    /// The first [`KATS`] signatures the C library records in
    /// `falcon/tests/test_deterministic_kat.h`.
    ///
    /// Read out of the submodule at run time rather than copied here. A vector pasted into this file
    /// would be a claim about what Falcon does; read from the library's own file, it is the
    /// library's claim, and it moves when the submodule moves.
    #[cfg(feature = "sign")]
    fn kat_signatures() -> Vec<Vec<u8>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/falcon/tests/test_deterministic_kat.h"
        );
        let vectors =
            std::fs::read_to_string(path).expect("the submodule carries its test vectors");

        let table = vectors
            .split_once("FALCON_DET1024_KAT[] = {")
            .expect("the vector table is where it has always been")
            .1;

        let signatures: Vec<Vec<u8>> = table
            .split('"')
            // Every second piece of a quoted list is a quoted entry; the ones between are the
            // commas and newlines that separate them.
            .skip(1)
            .step_by(2)
            .take(KATS)
            .map(|hex| {
                assert!(hex.len().is_multiple_of(2), "a vector is whole bytes");

                (0..hex.len() / 2)
                    .map(|index| {
                        u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                            .expect("a vector is hex")
                    })
                    .collect()
            })
            .collect();

        assert_eq!(signatures.len(), KATS, "the table is shorter than expected");

        signatures
    }

    /// The message and key of vector `index`, built the way `tests/test_deterministic.c` builds
    /// them: `index` bytes from the stream seeded `msg-NNNN`, under the key from `key-NNNN`.
    #[cfg(feature = "sign")]
    fn kat_inputs(index: usize) -> (Vec<u8>, SigningKey) {
        let mut message = vec![0u8; index];
        Prng::from_seed(format!("msg-{index:04}").as_bytes()).fill(&mut message);

        (
            message,
            SigningKey::generate(&mut Prng::from_seed(format!("key-{index:04}").as_bytes())),
        )
    }

    // The constants on the Rust side are what every buffer here is sized by, and the C side
    // computes its own from the submodule's headers. They have to be the same numbers, and this is
    // what says so if the submodule is ever moved to a version that changed one.
    #[test]
    fn the_declared_sizes_are_the_ones_the_c_library_computes() {
        // SAFETY: these take no arguments and return a size the header computed.
        unsafe {
            assert_eq!(falcon_det1024_rs_pubkey_size(), PUBLIC_KEY_SIZE);
            assert_eq!(falcon_det1024_rs_privkey_size(), PRIVATE_KEY_SIZE);
            assert_eq!(
                falcon_det1024_rs_sig_compressed_maxsize(),
                MAX_SIGNATURE_SIZE
            );
            #[cfg(feature = "sign")]
            assert_eq!(
                falcon_det1024_rs_shake256_context_size(),
                size_of::<Shake256Context>()
            );
            assert_eq!(
                falcon_det1024_rs_sig_compressed_header(),
                c_uint::from(SIGNATURE_HEADER)
            );
            assert_eq!(
                falcon_det1024_rs_current_salt_version(),
                c_uint::from(CURRENT_SALT_VERSION)
            );
        }
    }

    // The test that says this crate implements Falcon rather than something that resembles it: keys
    // and signatures reproduced byte for byte from the library's own vectors, which is a claim only
    // a deterministic scheme can make and only a faithful build can keep.
    #[test]
    #[cfg(feature = "sign")]
    fn the_c_library_test_vectors_are_reproduced_exactly() {
        for (index, expected) in kat_signatures().into_iter().enumerate() {
            let (message, key) = kat_inputs(index);
            let signature = key.sign_compressed(&message);

            assert_eq!(signature, expected, "vector {index}");
            assert_eq!(signature[0], SIGNATURE_HEADER);
            assert_eq!(signature[1], CURRENT_SALT_VERSION);
            assert!(verify_compressed(&signature, key.public_key(), &message));
        }
    }

    #[test]
    #[cfg(feature = "sign")]
    fn a_signature_verifies_under_its_own_key_and_message() {
        let key = SigningKey::from_seed(b"a signing key");
        let message = b"the bytes a sender signs".as_slice();
        let signature = key.sign_compressed(message);

        assert!(signature.len() <= MAX_SIGNATURE_SIZE);
        assert!(verify_compressed(&signature, key.public_key(), message));
    }

    #[test]
    #[cfg(feature = "sign")]
    fn a_seed_fixes_the_key_it_generates() {
        let key = SigningKey::from_seed(b"a signing key");
        let same = SigningKey::from_seed(b"a signing key");
        let other = SigningKey::from_seed(b"another signing key");

        assert_eq!(key.public_key(), same.public_key());
        assert_ne!(key.public_key(), other.public_key());

        // Signing is a function of the key and the message, so two keys from one seed sign
        // identically -- which is what lets a fixture record a key as a seed.
        assert_eq!(key.sign_compressed(b"msg"), same.sign_compressed(b"msg"));
    }

    #[test]
    #[cfg(feature = "sign")]
    fn a_signature_is_rejected_under_anything_it_was_not_made_for() {
        let key = SigningKey::from_seed(b"a signing key");
        let other = SigningKey::from_seed(b"another signing key");
        let message = b"the bytes a sender signs".as_slice();
        let signature = key.sign_compressed(message);

        assert!(!verify_compressed(&signature, other.public_key(), message));
        assert!(!verify_compressed(&signature, key.public_key(), b"other"));

        // Every byte of the signature is covered, including the header and the salt version.
        for index in [0, 1, 2, signature.len() - 1] {
            let mut tampered = signature.clone();
            tampered[index] ^= 1;
            assert!(
                !verify_compressed(&tampered, key.public_key(), message),
                "a signature with byte {index} flipped verified"
            );
        }

        // And so is its length, in both directions.
        assert!(!verify_compressed(
            &signature[..signature.len() - 1],
            key.public_key(),
            message
        ));
        let mut extended = signature.clone();
        extended.push(0);
        assert!(!verify_compressed(&extended, key.public_key(), message));
    }

    // Whatever arrives on the wire reaches this function, so "not a signature at all" has to be an
    // answer rather than a crash: too short to hold a header, longer than the format allows, or the
    // right shape with nothing in it.
    #[test]
    fn arbitrary_bytes_are_rejected_without_reading_past_them() {
        let public_key = [0u8; PUBLIC_KEY_SIZE];

        for signature in [
            [].as_slice(),
            &[SIGNATURE_HEADER],
            &[SIGNATURE_HEADER, CURRENT_SALT_VERSION],
            &[0u8; MAX_SIGNATURE_SIZE],
            &[SIGNATURE_HEADER; MAX_SIGNATURE_SIZE],
            &[SIGNATURE_HEADER; MAX_SIGNATURE_SIZE + 1],
            &[0xff; MAX_SIGNATURE_SIZE * 2],
        ] {
            assert!(!verify_compressed(signature, &public_key, b"message"));
        }
    }
}
