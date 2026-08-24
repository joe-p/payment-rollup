//! One verification of each post-quantum scheme, each inside a cycle-tracker region.
//!
//! Three schemes at NIST level 5, so the comparison is between equals:
//!
//! - Falcon-1024, which is what the rollup uses today
//! - ML-DSA-87 (Dilithium5)
//! - SLH-DSA-SHAKE-256s (SPHINCS+)
//!
//! The host writes each scheme's key, signature and message; nothing is generated here, because
//! signing is not what a guest would ever do. `cycle-tracker-report-start/end` is what the SP1
//! executor turns into the report's `cycle_tracker` map, so the three regions come back separately
//! from one run.
#![no_main]
sp1_zkvm::entrypoint!(main);

mod falcon_raw;

extern crate alloc;

use ml_dsa::{EncodedVerifyingKey, MlDsa87, Signature as MlDsaSignature, VerifyingKey};
use signature::Verifier;
use slh_dsa::{
    Shake128s, Shake192s, Shake256s, Signature as SlhSignature,
    VerifyingKey as SlhVerifyingKey,
};

pub fn main() {
    // Read everything first: io is not what is being measured, and interleaving reads with the
    // regions would charge each scheme for the host's serialization.
    let falcon_key = sp1_zkvm::io::read_vec();
    let falcon_sig = sp1_zkvm::io::read_vec();
    let falcon_msg = sp1_zkvm::io::read_vec();

    let mldsa_key = sp1_zkvm::io::read_vec();
    let mldsa_sig = sp1_zkvm::io::read_vec();
    let mldsa_msg = sp1_zkvm::io::read_vec();

    let slh_key = sp1_zkvm::io::read_vec();
    let slh_sig = sp1_zkvm::io::read_vec();
    let slh_msg = sp1_zkvm::io::read_vec();

    let ed_key = sp1_zkvm::io::read_vec();
    let ed_sig = sp1_zkvm::io::read_vec();

    let slh128_key = sp1_zkvm::io::read_vec();
    let slh128_sig = sp1_zkvm::io::read_vec();
    let slh192_key = sp1_zkvm::io::read_vec();
    let slh192_sig = sp1_zkvm::io::read_vec();

    let f512_key = sp1_zkvm::io::read_vec();
    let f512_sig = sp1_zkvm::io::read_vec();
    let f1024_key = sp1_zkvm::io::read_vec();
    let f1024_sig = sp1_zkvm::io::read_vec();
    let raw_msg = sp1_zkvm::io::read_vec();

    // -- Falcon-1024 -------------------------------------------------------------------------
    let falcon_key: &[u8; falcon_det1024::PUBLIC_KEY_SIZE] =
        falcon_key.as_slice().try_into().expect("falcon key size");

    println!("cycle-tracker-report-start: falcon-1024");
    let falcon_ok = falcon_det1024::verify_compressed(&falcon_sig, falcon_key, &falcon_msg);
    println!("cycle-tracker-report-end: falcon-1024");
    assert!(falcon_ok, "falcon signature did not verify");

    // -- ML-DSA-87 ---------------------------------------------------------------------------
    let mldsa_encoded = EncodedVerifyingKey::<MlDsa87>::try_from(mldsa_key.as_slice())
        .expect("ml-dsa key size");
    let mldsa_signature =
        MlDsaSignature::<MlDsa87>::decode(&mldsa_sig.as_slice().try_into().expect("ml-dsa sig size"))
            .expect("ml-dsa signature decode");

    // `decode` is where `ml-dsa` expands the matrix A from rho, and that is a real part of a cold
    // verify -- keeping it outside this region measured an ML-DSA whose A was already expanded,
    // which is the amortized cost and not what a first verification pays.
    println!("cycle-tracker-report-start: ml-dsa-87-cold");
    let mldsa_vk = VerifyingKey::<MlDsa87>::decode(&mldsa_encoded);
    let mldsa_ok = mldsa_vk.verify(&mldsa_msg, &mldsa_signature).is_ok();
    println!("cycle-tracker-report-end: ml-dsa-87-cold");

    // The same verification again, with A already expanded: what a repeat signer would cost.
    println!("cycle-tracker-report-start: ml-dsa-87-warm");
    let mldsa_ok_warm = mldsa_vk.verify(&mldsa_msg, &mldsa_signature).is_ok();
    println!("cycle-tracker-report-end: ml-dsa-87-warm");
    assert!(mldsa_ok_warm, "ml-dsa warm verify disagreed");
    assert!(mldsa_ok, "ml-dsa signature did not verify");

    // -- SLH-DSA-SHAKE-256s ------------------------------------------------------------------
    let slh_vk = SlhVerifyingKey::<Shake256s>::try_from(slh_key.as_slice()).expect("slh key size");
    let slh_signature = SlhSignature::<Shake256s>::try_from(slh_sig.as_slice()).expect("slh sig");

    println!("cycle-tracker-report-start: slh-dsa-shake-256s");
    let slh_ok = slh_vk.verify(&slh_msg, &slh_signature).is_ok();
    println!("cycle-tracker-report-end: slh-dsa-shake-256s");
    assert!(slh_ok, "slh-dsa signature did not verify");

    // -- Ed25519, the classical half of the hybrid ---------------------------------------------
    // `verify_strict` specifically, because that is what the rollup calls.
    let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(
        ed_key.as_slice().try_into().expect("ed25519 key size"),
    )
    .expect("ed25519 key");
    let ed_signature = ed25519_dalek::Signature::from_bytes(
        ed_sig.as_slice().try_into().expect("ed25519 sig size"),
    );

    println!("cycle-tracker-report-start: ed25519-verify-strict");
    let ed_ok = ed_vk.verify_strict(&falcon_msg, &ed_signature).is_ok();
    println!("cycle-tracker-report-end: ed25519-verify-strict");
    assert!(ed_ok, "ed25519 signature did not verify");

    // -- SLH-DSA at the lower categories -------------------------------------------------------
    // Hash-based security is a more conservative assumption than lattice security, so a level-1
    // hash scheme is arguably comparable to a level-5 lattice one. These are what that costs.
    let slh128_vk =
        SlhVerifyingKey::<Shake128s>::try_from(slh128_key.as_slice()).expect("slh128 key");
    let slh128_signature =
        SlhSignature::<Shake128s>::try_from(slh128_sig.as_slice()).expect("slh128 sig");

    println!("cycle-tracker-report-start: slh-dsa-shake-128s");
    let slh128_ok = slh128_vk.verify(&slh_msg, &slh128_signature).is_ok();
    println!("cycle-tracker-report-end: slh-dsa-shake-128s");
    assert!(slh128_ok, "slh-dsa-128s signature did not verify");

    let slh192_vk =
        SlhVerifyingKey::<Shake192s>::try_from(slh192_key.as_slice()).expect("slh192 key");
    let slh192_signature =
        SlhSignature::<Shake192s>::try_from(slh192_sig.as_slice()).expect("slh192 sig");

    println!("cycle-tracker-report-start: slh-dsa-shake-192s");
    let slh192_ok = slh192_vk.verify(&slh_msg, &slh192_signature).is_ok();
    println!("cycle-tracker-report-end: slh-dsa-shake-192s");
    assert!(slh192_ok, "slh-dsa-192s signature did not verify");

    // -- Falcon-512 against Falcon-1024, same code path, only `logn` differs ------------------
    let mut tmp = alloc::vec![0u8; falcon_raw::TMP_VERIFY];

    println!("cycle-tracker-report-start: falcon-512-generic");
    let f512_ok = falcon_raw::verify(&f512_sig, &f512_key, &raw_msg, &mut tmp);
    println!("cycle-tracker-report-end: falcon-512-generic");
    assert!(f512_ok, "falcon-512 signature did not verify");

    println!("cycle-tracker-report-start: falcon-1024-generic");
    let f1024_ok = falcon_raw::verify(&f1024_sig, &f1024_key, &raw_msg, &mut tmp);
    println!("cycle-tracker-report-end: falcon-1024-generic");
    assert!(f1024_ok, "falcon-1024 signature did not verify");

    // -- The cacheable half of a Falcon-1024 verify -------------------------------------------
    // Decode + NTT of the public key, which is everything `falcon_verify_finish` does before it
    // looks at the signature at all.
    let mut h = alloc::vec![0u16; 1024];

    println!("cycle-tracker-report-start: falcon-1024-pubkey-expand");
    let expand_ok = falcon_raw::expand_pubkey(&f1024_key, 10, &mut h);
    println!("cycle-tracker-report-end: falcon-1024-pubkey-expand");
    assert!(expand_ok, "falcon-1024 public key did not decode");

    let mut h512 = alloc::vec![0u16; 512];
    println!("cycle-tracker-report-start: falcon-512-pubkey-expand");
    let expand512_ok = falcon_raw::expand_pubkey(&f512_key, 9, &mut h512);
    println!("cycle-tracker-report-end: falcon-512-pubkey-expand");
    assert!(expand512_ok, "falcon-512 public key did not decode");

    // What an expanded-key format pays instead of the decode-and-NTT above.
    println!("cycle-tracker-report-start: falcon-1024-range-check");
    let in_range = falcon_raw::coefficients_in_range(&h);
    println!("cycle-tracker-report-end: falcon-1024-range-check");
    assert!(in_range, "expanded key out of range");

    // Committed so the run cannot be optimized into nothing.
    sp1_zkvm::io::commit(&(falcon_ok && mldsa_ok && slh_ok && f512_ok && f1024_ok && expand_ok && expand512_ok && in_range && slh128_ok && slh192_ok && ed_ok));
}
