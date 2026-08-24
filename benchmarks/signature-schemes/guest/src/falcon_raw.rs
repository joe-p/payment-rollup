//! Falcon at an arbitrary degree, through the generic C API rather than the det1024 wrapper.
//!
//! `falcon-det1024` fixes `logn = 10`, so comparing Falcon-512 against Falcon-1024 has to go
//! around it. Both degrees are verified through *this* path in the same run, so the ratio is
//! between two identical code paths differing only in `logn` -- which is the number wanted, and is
//! not the same as comparing against the det1024 figure (det1024 drops the 40-byte nonce for a
//! salt, so it is a slightly different function).

/// `FALCON_SIG_COMPRESSED`, the format the rollup uses.
pub const SIG_COMPRESSED: i32 = 1;

/// Generous, so no `FALCON_TMPSIZE_VERIFY(logn)` macro has to be reproduced in Rust. The C side
/// checks the length it was given and fails if it is short, so over-allocating is safe and being
/// exact buys nothing here.
pub const TMP_VERIFY: usize = 64 * 1024;

unsafe extern "C" {
    pub fn falcon_verify(
        sig: *const u8,
        sig_len: usize,
        sig_type: i32,
        pubkey: *const u8,
        pubkey_len: usize,
        data: *const u8,
        data_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> i32;
}

/// Verify one signature at whatever degree its public key encodes.
pub fn verify(sig: &[u8], pubkey: &[u8], message: &[u8], tmp: &mut [u8]) -> bool {
    // SAFETY: every pointer is a live slice, and every length is that slice's own length.
    let result = unsafe {
        falcon_verify(
            sig.as_ptr(),
            sig.len(),
            SIG_COMPRESSED,
            pubkey.as_ptr(),
            pubkey.len(),
            message.as_ptr(),
            message.len(),
            tmp.as_mut_ptr(),
            tmp.len(),
        )
    };

    result == 0
}

// The two halves of the public-key-derived work, reached individually so it can be timed apart
// from the rest of a verification.
unsafe extern "C" {
    fn falcon_inner_modq_decode(
        x: *mut u16,
        logn: u32,
        input: *const u8,
        max_in_len: usize,
    ) -> usize;
    fn falcon_inner_to_ntt_monty(h: *mut u16, logn: u32);
}

/// The part of a Falcon verification that depends only on the public key.
///
/// `falcon_verify_finish` starts by decoding the public key's 14-bit coefficients into `h`, then
/// converting `h` to the NTT/Montgomery domain -- and only then touches the signature. Both steps
/// are a pure function of the key, so a batch in which one account signs many times recomputes
/// them once per signature for no reason. This measures what that repetition costs.
///
/// The cacheable artifact is `h` itself: `n` 16-bit coefficients, so 2 KiB at n = 1024.
pub fn expand_pubkey(pubkey: &[u8], logn: u32, h: &mut [u16]) -> bool {
    // SAFETY: `h` is at least `1 << logn` entries (asserted), and the key slice is passed with its
    // own length minus the one-byte header the C side expects to have been stripped.
    assert!(h.len() >= 1usize << logn, "h is too small for this degree");

    unsafe {
        let decoded = falcon_inner_modq_decode(
            h.as_mut_ptr(),
            logn,
            pubkey[1..].as_ptr(),
            pubkey.len() - 1,
        );
        if decoded != pubkey.len() - 1 {
            return false;
        }

        falcon_inner_to_ntt_monty(h.as_mut_ptr(), logn);
    }

    true
}

/// Falcon's field modulus. `modq_decode` refuses any coefficient at or above it.
pub const Q: u16 = 12289;

/// The check an expanded-key format has to carry in place of `modq_decode`'s.
///
/// `modq_decode` does three things: unpack 14-bit words, reject any coefficient `>= 12289`, and
/// reject non-zero trailing padding bits. A format that ships `h` already expanded skips the
/// unpacking -- but the range check has to survive, both because the arithmetic downstream assumes
/// coefficients below `q` and because it is what makes the encoding canonical, and an address that
/// is the hash of the key bytes needs one byte string per key.
pub fn coefficients_in_range(h: &[u16]) -> bool {
    h.iter().all(|&coefficient| coefficient < Q)
}
