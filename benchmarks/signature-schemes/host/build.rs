fn main() {
    sp1_build::build_program_with_args(
        "../guest",
        sp1_build::BuildArgs {
            packages: vec!["scheme-bench-guest".to_string()],
            binaries: vec!["scheme-bench-guest".to_string()],
            ..Default::default()
        },
    );
}
