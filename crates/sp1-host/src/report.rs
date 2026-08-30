//! What a block costs in the zkVM, measured by running the guest rather than by estimating it.
//!
//! This is the executor, not the prover: it runs the same ELF [`crate::prove`] would prove, on this
//! machine, for free, and reports what the run cost. No network, no credential, no GPU. What it
//! cannot tell you is wall-clock proving time -- for that there is `--prove`.
//!
//! Two numbers and one table come out of it, and they answer different questions:
//!
//! - **Instructions** is the RISC-V count. It is what "cycles" usually means, and on its own it
//!   understates anything that reaches a precompile: a syscall is one instruction here and a table
//!   of constrained rows in the prover.
//! - **Gas** is SP1's own normalization of proving cost, which does account for that trace area. It
//!   is the number to compare two schemes on.
//! - **Syscalls** is the per-precompile invocation count. This is what settles whether a patch is
//!   actually wired in: an `ed_add` of zero means `curve25519-dalek` compiled without its patch, and
//!   the block paid for Edwards arithmetic in software while looking fine from the outside.
//!
//! Compiled only under the `prove` feature, which is what puts a guest ELF and the SDK in reach.
//! Nothing here needs the network half of it.

use sp1_sdk::{
    Elf, ExecutionReport, SP1Stdin,
    blocking::{CpuProver, Prover, ProverClient},
};
use std::time::Instant;

use crate::{
    Settlement,
    prove::{GUEST_ELF, stdin_for},
};

/// A local executor, held so a run of several scenarios builds it once.
pub struct Reporter {
    client: CpuProver,
}

/// What one scenario cost, as the executor counted it.
pub struct Report {
    /// RISC-V instructions retired.
    pub instructions: u64,
    /// SP1's proving-cost metric, or `None` if the executor was asked not to compute it.
    pub gas: Option<u64>,
    /// Every precompile that was reached at least once, and how often, most-used first.
    pub syscalls: Vec<(String, u64)>,
    /// Transactions in the block, for turning the totals into per-transaction figures.
    pub txns: usize,
    /// How long the executor itself took. Not a proving time and not a proxy for one.
    pub elapsed: std::time::Duration,
}

impl Reporter {
    /// Build the local executor.
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            client: ProverClient::builder().cpu().build(),
        })
    }

    /// Execute one settlement and count what it cost.
    pub fn report(&self, settlement: &Settlement) -> Result<Report, String> {
        let stdin: SP1Stdin = stdin_for(settlement);
        let elf: Elf = GUEST_ELF;

        let started = Instant::now();
        let (public_values, report) = self
            .client
            .execute(elf, stdin)
            // Off by default in nothing -- it is on by default -- but named here because it is the
            // number worth having and the executor only computes it when asked.
            .calculate_gas(true)
            .run()
            .map_err(|error| format!("the guest failed to execute: {error}"))?;
        let elapsed = started.elapsed();

        // The same check `prove` makes, for the same reason: the guest and the host run the same
        // `execute`, so a disagreement here is the zkVM and native builds having drifted apart, and
        // a cost report for a block the guest got wrong is worse than no report.
        if public_values.as_slice() != settlement.public_values().as_slice() {
            return Err(
                "the guest committed public values the native replay did not produce".to_string(),
            );
        }

        Ok(Report {
            instructions: report.total_instruction_count(),
            gas: report.gas(),
            syscalls: syscalls(&report),
            txns: settlement.txn_count(),
            elapsed,
        })
    }
}

/// The precompiles a run reached, most-used first.
///
/// Every syscall the executor knows about is a key in the report's map, so the filter is what makes
/// this a list of what was used rather than a list of what exists. `Debug` is the only name a
/// `SyscallCode` has.
fn syscalls(report: &ExecutionReport) -> Vec<(String, u64)> {
    let mut used: Vec<_> = report
        .syscall_counts
        .iter()
        .filter(|&(_, &count)| count > 0)
        .map(|(code, &count)| (format!("{code:?}"), count))
        .collect();

    // Descending by count, then by name, so two runs of the same block print identically rather
    // than in whatever order ties happened to fall.
    used.sort_by(|(left_name, left), (right_name, right)| {
        right.cmp(left).then_with(|| left_name.cmp(right_name))
    });

    used
}

impl Report {
    /// Print the report, as a block of lines under the scenario it belongs to.
    ///
    /// To stderr, beside the other progress this binary reports, because stdout carries the fixture
    /// JSON and a reader of that should not have to filter measurements out of it.
    pub fn print(&self) {
        let per_txn = |total: u64| match self.txns {
            0 => "-".to_string(),
            txns => format!("{}", total / txns as u64),
        };

        eprintln!(
            "  executed in {:?}: {} instructions ({}/txn)",
            self.elapsed,
            self.instructions,
            per_txn(self.instructions),
        );
        match self.gas {
            Some(gas) => eprintln!("  gas {gas} ({}/txn)", per_txn(gas)),
            None => eprintln!("  gas not calculated"),
        }

        if self.syscalls.is_empty() {
            eprintln!("  no precompiles reached -- see this module's note on what that means");

            return;
        }

        eprintln!("  precompiles:");
        for (name, count) in &self.syscalls {
            eprintln!("    {name:<28} {count:>12} ({}/txn)", per_txn(*count));
        }
    }
}
