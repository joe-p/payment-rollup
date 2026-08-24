//! Signs one message under each scheme, then executes the guest and reports what each verify cost.
//!
//! Signing happens here because it is not the thing being measured; the guest only verifies.

mod falcon_raw;

use ml_dsa::{MlDsa87, SigningKey as MlDsaSigningKey};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use signature::{Keypair, Signer};
use slh_dsa::{Shake128s, Shake192s, Shake256s, SigningKey as SlhSigningKey};
use sp1_sdk::{
    Elf, SP1Stdin,
    blocking::{Prover, ProverClient},
    include_elf,
};

const GUEST_ELF: Elf = include_elf!("scheme-bench-guest");

/// Roughly the length of the rollup's `bytes_to_sign`, so the message-dependent part of each
/// scheme's hashing is charged the same way it would be in a real block.
const MESSAGE: &[u8; 116] = &[0x11; 116];

/// A fixed, seeded generator, so the same keys and signatures come back on every run.
///
/// Not a CSPRNG and not pretending to be one -- this benchmark's keys protect nothing. It exists
/// because SLH-DSA has no seed-based constructor that produces a *valid* key (the private key
/// commits to the hypertree root), so keygen needs a generator even when determinism is what is
/// wanted.
struct FixedRng(u64);

impl FixedRng {
    // xorshift64*, which is all a fixture generator needs to be.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;

        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

// `Rng` is blanket-implemented for any infallible `TryRng`, so these two impls are the whole
// contract; writing `impl Rng` as well collides with that blanket.
impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }

        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

fn main() {
    let mut rng = FixedRng(0xF00D_D00D_1234_5678);

    // -- Falcon-1024 --
    let falcon = falcon_det1024::SigningKey::from_seed(b"pqbench falcon seed");
    let falcon_sig = falcon.sign_compressed(MESSAGE);
    let falcon_key = falcon.public_key();

    // -- ML-DSA-87 -- keygen is deterministic in the seed, per FIPS 204.
    let mldsa = MlDsaSigningKey::<MlDsa87>::from_seed(&[0x42u8; 32].into());
    let mldsa_sig = mldsa.sign(MESSAGE);
    let mldsa_key = mldsa.verifying_key().encode();

    // -- SLH-DSA-SHAKE-256s --
    let slh = SlhSigningKey::<Shake256s>::new(&mut rng);
    let slh_sig = slh.sign(MESSAGE);
    let slh_key = slh.as_ref().to_bytes();

    // -- Ed25519 --
    let ed_signing = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
    let ed_sig = ed25519_dalek::Signer::sign(&ed_signing, MESSAGE);
    let ed_key = ed_signing.verifying_key().to_bytes();

    // -- SLH-DSA at levels 1 and 3 --
    let slh128 = SlhSigningKey::<Shake128s>::new(&mut rng);
    let slh128_sig = slh128.sign(MESSAGE).to_bytes();
    let slh128_key = slh128.as_ref().to_bytes();

    let slh192 = SlhSigningKey::<Shake192s>::new(&mut rng);
    let slh192_sig = slh192.sign(MESSAGE).to_bytes();
    let slh192_key = slh192.as_ref().to_bytes();

    // -- Falcon-512 and Falcon-1024 through the generic API, for a same-path comparison --
    let (f512_key, f512_sig) = falcon_raw::keypair_and_signature(9, b"pqbench 512", MESSAGE);
    let (f1024_key, f1024_sig) = falcon_raw::keypair_and_signature(10, b"pqbench 1024", MESSAGE);

    let mldsa_sig_bytes = mldsa_sig.encode();
    let slh_sig_bytes = slh_sig.to_bytes();

    println!(
        "sizes (bytes)\n  falcon-1024        sig {:>6}  pk {:>6}\n  ml-dsa-87          sig {:>6}  pk \
         {:>6}\n  slh-dsa-shake-256s sig {:>6}  pk {:>6}",
        falcon_sig.len(),
        falcon_key.len(),
        mldsa_sig_bytes.len(),
        mldsa_key.len(),
        slh_sig_bytes.len(),
        slh_key.len(),
    );
    println!(
        "  slh-dsa-shake-128s sig {:>6}  pk {:>6}\n  slh-dsa-shake-192s sig {:>6}  pk {:>6}",
        slh128_sig.len(),
        slh128_key.len(),
        slh192_sig.len(),
        slh192_key.len(),
    );
    println!(
        "  falcon-512  (raw)  sig {:>6}  pk {:>6}\n  falcon-1024 (raw)  sig {:>6}  pk {:>6}",
        f512_sig.len(),
        f512_key.len(),
        f1024_sig.len(),
        f1024_key.len(),
    );

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(falcon_key);
    stdin.write_slice(&falcon_sig);
    stdin.write_slice(MESSAGE);
    stdin.write_slice(&mldsa_key);
    stdin.write_slice(&mldsa_sig_bytes);
    stdin.write_slice(MESSAGE);
    stdin.write_slice(&slh_key);
    stdin.write_slice(&slh_sig_bytes);
    stdin.write_slice(MESSAGE);
    stdin.write_slice(&ed_key);
    stdin.write_slice(&ed_sig.to_bytes());
    stdin.write_slice(&slh128_key);
    stdin.write_slice(&slh128_sig);
    stdin.write_slice(&slh192_key);
    stdin.write_slice(&slh192_sig);
    stdin.write_slice(&f512_key);
    stdin.write_slice(&f512_sig);
    stdin.write_slice(&f1024_key);
    stdin.write_slice(&f1024_sig);
    stdin.write_slice(MESSAGE);

    let client = ProverClient::builder().cpu().build();
    let (_public_values, report) = client
        .execute(GUEST_ELF, stdin)
        .calculate_gas(true)
        .run()
        .expect("guest execution");

    println!(
        "\ntotal {} instructions, gas {:?}",
        report.total_instruction_count(),
        report.gas(),
    );

    println!("\nper-scheme instructions:");
    let mut regions: Vec<_> = report.cycle_tracker.iter().collect();
    regions.sort_by_key(|(_, &count)| std::cmp::Reverse(count));
    for (label, count) in regions {
        println!("  {label:<24} {count:>12}");
    }

    println!("\nprecompiles:");
    let mut used: Vec<_> = report
        .syscall_counts
        .iter()
        .filter(|&(_, &count)| count > 0)
        .collect();
    used.sort_by_key(|(_, &count)| std::cmp::Reverse(count));
    for (code, count) in used {
        println!("  {:<24} {count:>12}", format!("{code:?}"));
    }
}
