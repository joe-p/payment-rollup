//! Builds the guest to a zkVM ELF, but only when this crate is going to prove with it.
//!
//! `sp1_build` shells out to `cargo +succinct build --target riscv64im-succinct-zkvm-elf`, so a
//! build without the `prove` feature must not reach it -- emitting fixtures replays blocks
//! natively and has no use for an ELF or for the toolchain that produces one.

fn main() {
    #[cfg(feature = "prove")]
    {
        // Named explicitly rather than left to default. `sp1-guest` is a member of this workspace,
        // so the default -- every default member -- would sweep up this crate's own binary target
        // and try to build it for RISC-V.
        sp1_build::build_program_with_args(
            "../sp1-guest",
            sp1_build::BuildArgs {
                packages: vec!["sp1-guest".to_string()],
                binaries: vec!["sp1-guest".to_string()],
                ..Default::default()
            },
        );
    }
}
