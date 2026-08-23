//! Builds the deterministic Falcon C library the crate wraps.
//!
//! The sources are the submodule's, untouched, plus one shim of our own that reports the sizes its
//! headers compute so a test can compare them against the constants declared on the Rust side.

use std::path::{Path, PathBuf};

/// Exactly the object list the library's own `Makefile` builds.
///
/// All of it, including the signing and key-generation halves, because `falcon.c` holds
/// `falcon_verify` next to the signing entry points and references the key generator -- so an
/// archive that could link at all would have to carry them regardless of what this crate exposes.
const SOURCES: [&str; 11] = [
    "codec.c",
    "common.c",
    "deterministic.c",
    "falcon.c",
    "fft.c",
    "fpr.c",
    "keygen.c",
    "rng.c",
    "shake.c",
    "sign.c",
    "vrfy.c",
];

const HEADERS: [&str; 5] = [
    "config.h",
    "deterministic.h",
    "falcon.h",
    "fpr.h",
    "inner.h",
];

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let falcon = manifest.join("falcon");

    if !falcon.join("deterministic.h").exists() {
        panic!(
            "the Falcon submodule is missing from {}; run `git submodule update --init` and build \
             again",
            falcon.display()
        );
    }

    let mut build = cc::Build::new();
    build
        .include(&falcon)
        .files(SOURCES.iter().map(|source| falcon.join(source)))
        .file(manifest.join("src/sizes.c"))
        // Floating point is used by key generation and signing, never by verification, and the
        // library's own security warning is emphatic about this setting: emulated floating point is
        // what makes a deterministic signature deterministic across machines. It is also what keeps
        // the guest honest, where the RISC-V target has no floating-point unit at all and native
        // `double` arithmetic would become whatever the soft-float runtime decided to do.
        .define("FALCON_FPEMU", "1")
        .define("FALCON_FMA", "0")
        .define("FALCON_AVX2", "0")
        .define("FALCON_ASM_CORTEXM4", "0")
        // No system entropy, on any target. Every key this crate makes comes from a seed the caller
        // supplies, so `Zf(get_seed)` is never called -- and with all three sources off it compiles
        // to a stub that reports failure, which is the honest answer for a zkVM guest where there is
        // no operating system to ask.
        .define("FALCON_RAND_GETENTROPY", "0")
        .define("FALCON_RAND_URANDOM", "0")
        .define("FALCON_RAND_WIN32", "0")
        // Somebody else's C, held at a pinned commit, so its warnings are not ours to fix and a
        // build that printed them every time would train everybody to ignore the output. The shim
        // is compiled in the same pass and loses its warnings too, which is a fair trade for six
        // lines that return a constant.
        .warnings(false)
        // Optimized even in a debug profile. Nothing here is being stepped through, and an
        // unoptimized Falcon is slow enough to change how a test suite feels.
        .opt_level(2)
        .compile("falcon_det1024");

    rerun_if_changed(&manifest.join("src/sizes.c"));
    for source in SOURCES.iter().chain(HEADERS.iter()) {
        rerun_if_changed(&falcon.join(source));
    }
}

fn rerun_if_changed(path: &Path) {
    println!("cargo::rerun-if-changed={}", path.display());
}
