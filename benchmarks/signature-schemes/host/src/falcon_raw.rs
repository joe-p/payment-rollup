//! Keygen and signing at an arbitrary Falcon degree, through the generic C API.
//!
//! Only here to produce fixtures for the guest. `falcon-det1024` fixes `logn = 10`, so Falcon-512
//! has to be reached around it.

/// `FALCON_SIG_COMPRESSED`.
const SIG_COMPRESSED: i32 = 1;

/// Over-allocated rather than reproducing the `FALCON_TMPSIZE_*` macros in Rust. The C side checks
/// the length it is handed, so too much is safe and too little fails loudly.
const TMP: usize = 4 * 1024 * 1024;

/// `FALCON_PUBKEY_SIZE(logn)`, which is exact.
pub fn pubkey_size(logn: u32) -> usize {
    (if logn <= 1 { 4 } else { 7usize << (logn - 2) }) + 1
}

/// `FALCON_PRIVKEY_SIZE(logn)`, which is exact.
pub fn privkey_size(logn: u32) -> usize {
    (if logn <= 3 {
        3usize << logn
    } else {
        ((10 - (logn as usize >> 1)) << (logn - 2)) + (1 << logn)
    }) + 1
}

/// `FALCON_SIG_COMPRESSED_MAXSIZE(logn)` -- an upper bound, not the length a signature turns out.
pub fn sig_maxsize(logn: u32) -> usize {
    ((((11usize << logn) + (101 >> (10 - logn))) + 7) >> 3) + 41
}

#[repr(C)]
struct Shake256Context {
    opaque_contents: [u64; 26],
}

unsafe extern "C" {
    fn shake256_init_prng_from_seed(sc: *mut Shake256Context, seed: *const u8, seed_len: usize);
    fn falcon_keygen_make(
        rng: *mut Shake256Context,
        logn: u32,
        privkey: *mut u8,
        privkey_len: usize,
        pubkey: *mut u8,
        pubkey_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> i32;
    fn falcon_sign_dyn(
        rng: *mut Shake256Context,
        sig: *mut u8,
        sig_len: *mut usize,
        sig_type: i32,
        privkey: *const u8,
        privkey_len: usize,
        data: *const u8,
        data_len: usize,
        tmp: *mut u8,
        tmp_len: usize,
    ) -> i32;
}

/// A keypair and one signature over `message`, at degree `1 << logn`.
pub fn keypair_and_signature(logn: u32, seed: &[u8], message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rng = Shake256Context {
        opaque_contents: [0u64; 26],
    };
    let mut tmp = vec![0u8; TMP];
    let mut privkey = vec![0u8; privkey_size(logn)];
    let mut pubkey = vec![0u8; pubkey_size(logn)];

    // SAFETY: every buffer below is a live allocation, passed with its own length.
    unsafe {
        shake256_init_prng_from_seed(&mut rng, seed.as_ptr(), seed.len());

        let result = falcon_keygen_make(
            &mut rng,
            logn,
            privkey.as_mut_ptr(),
            privkey.len(),
            pubkey.as_mut_ptr(),
            pubkey.len(),
            tmp.as_mut_ptr(),
            tmp.len(),
        );
        assert_eq!(result, 0, "falcon_keygen_make(logn={logn}) failed: {result}");

        let mut sig = vec![0u8; sig_maxsize(logn)];
        let mut sig_len = sig.len();
        let result = falcon_sign_dyn(
            &mut rng,
            sig.as_mut_ptr(),
            &mut sig_len,
            SIG_COMPRESSED,
            privkey.as_ptr(),
            privkey.len(),
            message.as_ptr(),
            message.len(),
            tmp.as_mut_ptr(),
            tmp.len(),
        );
        assert_eq!(result, 0, "falcon_sign_dyn(logn={logn}) failed: {result}");
        sig.truncate(sig_len);

        (pubkey, sig)
    }
}
