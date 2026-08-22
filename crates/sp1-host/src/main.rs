//! Emits settlement fixtures as JSON, for driving the contract end to end before there is a proof.
//!
//! Everything the contract's three methods take comes out of here: `batchLength` to open with,
//! `chunks` to post, and `publicValues` to settle against. See [`sp1_host`] for how they are
//! computed, which is by running the guest program natively.

use std::process::ExitCode;

use serde_json::{Value, json};
use payment_rollup::{MIN_WITHDRAWAL, REQUEST_CHAIN_GENESIS, WITHDRAWAL_CHAIN_GENESIS};
use sp1_host::{
    DEPOSIT_CHAIN_GENESIS, GENESIS_ROOT, PUBLIC_VALUES_SIZE, Settlement, hex, scenarios,
};

const USAGE: &str = "\
Emit settlement fixtures for the rollup verifier contract.

Usage:
  sp1-host [options] [SCENARIO...]

With no SCENARIO, every scenario is emitted.

Options:
  --out <PATH>       write the JSON here instead of to stdout
  --include-sidecar  include the prover-only sidecar bytes, which the contract does not need
  --list             list the scenarios and exit
  -h, --help         show this message
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sp1-host: {message}");

            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct Args {
    out: Option<String>,
    include_sidecar: bool,
    names: Vec<String>,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args::default();
    let mut remaining = std::env::args().skip(1);

    while let Some(arg) = remaining.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");

                return Ok(None);
            }
            "--list" => {
                for scenario in scenarios::all() {
                    println!("{}\n    {}\n", scenario.name, scenario.description);
                }

                return Ok(None);
            }
            "--include-sidecar" => args.include_sidecar = true,
            "--out" => {
                args.out = Some(
                    remaining
                        .next()
                        .ok_or_else(|| "--out needs a path".to_string())?,
                );
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other}\n\n{USAGE}"));
            }
            name => args.names.push(name.to_string()),
        }
    }

    Ok(Some(args))
}

fn run() -> Result<(), String> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };

    // Named scenarios keep the order they were asked for; an unnamed run keeps declaration order.
    let selected: Vec<_> = if args.names.is_empty() {
        scenarios::all().iter().collect()
    } else {
        args.names
            .iter()
            .map(|name| {
                scenarios::find(name)
                    .ok_or_else(|| format!("no scenario named {name} (try --list)"))
            })
            .collect::<Result<_, _>>()?
    };

    let mut emitted = Vec::with_capacity(selected.len());
    for scenario in &selected {
        let block = (scenario.build)();
        let settlement = Settlement::for_block(&block)
            .map_err(|error| format!("scenario {}: {error}", scenario.name))?;

        // Every scenario settles against a fresh contract now that deposits carry value in, so this
        // is an invariant rather than a per-scenario caveat -- and a loud failure if it ever breaks,
        // since there is no longer any way to put a contract at a root by hand.
        if !settlement.settles_from_genesis() {
            return Err(format!(
                "scenario {}: starts from {} rather than genesis, and there is no way to seed a \
                 contract to meet it",
                scenario.name,
                hex(&settlement.old_root()),
            ));
        }

        eprintln!(
            "{}: {} txns ({} deposits), {} B in {} chunk(s)",
            scenario.name,
            settlement.txn_count(),
            settlement.deposits().len(),
            settlement.batch_length(),
            settlement.chunk_count(),
        );

        emitted.push(fixture(scenario, &settlement, args.include_sidecar));
    }

    let document = json!({
        // Mirrors of the constants the contract hard-codes, so a test can assert the two sides
        // agree rather than hard-coding them a third time.
        "chunkSize": sp1_host::CHUNK_SIZE,
        "publicValuesSize": PUBLIC_VALUES_SIZE,
        "minWithdrawal": MIN_WITHDRAWAL,
        "genesisRoot": hex(&GENESIS_ROOT),
        "depositChainGenesis": hex(&DEPOSIT_CHAIN_GENESIS),
        "withdrawalChainGenesis": hex(&WITHDRAWAL_CHAIN_GENESIS),
        "requestChainGenesis": hex(&REQUEST_CHAIN_GENESIS),
        "scenarios": emitted,
    });

    let mut json = serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?;
    json.push('\n');

    match &args.out {
        Some(path) => {
            let path = std::path::Path::new(path);
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("creating {}: {error}", parent.display()))?;
            }

            std::fs::write(path, &json)
                .map_err(|error| format!("writing {}: {error}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => print!("{json}"),
    }

    Ok(())
}

/// One scenario as the TypeScript tests read it.
///
/// Field names are camelCase and the byte strings are hex, both to be pasted straight into a test
/// without a translation step in between.
fn fixture(
    scenario: &scenarios::Scenario,
    settlement: &Settlement,
    include_sidecar: bool,
) -> Value {
    let mut fixture = json!({
        "name": scenario.name,
        "description": scenario.description,
        "txnCount": settlement.txn_count(),

        // `verifyBatch` takes only this; the roots, the commitment and the chain ends below are the
        // same bytes sliced out, emitted separately so a failing assertion can name which fifth
        // disagreed.
        "publicValues": hex(settlement.public_values()),
        "oldRoot": hex(&settlement.old_root()),
        "newRoot": hex(&settlement.new_root()),
        "batchCommitment": hex(&settlement.batch_commitment()),
        "depositChainFrom": hex(&settlement.deposit_chain_from()),
        "depositChainTo": hex(&settlement.deposit_chain_to()),
        "withdrawalChain": hex(&settlement.withdrawal_chain()),
        "requestChainFrom": hex(&settlement.request_chain_from()),
        "requestChainTo": hex(&settlement.request_chain_to()),

        // One `requestWithdrawal(address, recipient, ...)` call each, in this order, before the
        // batch is opened. Like the deposits, the chain only reaches `requestChainTo` if L1 sees
        // exactly these, exactly here -- which is what stops the sequencer settling around them.
        "requests": settlement
            .requests()
            .iter()
            .map(|(address, recipient)| json!({
                "address": hex(address),
                "recipient": hex(recipient),
            }))
            .collect::<Vec<_>>(),

        // One `deposit(payment, recipient)` call each, in this order, before the batch is opened.
        // The chain only reaches `depositChainTo` if L1 sees exactly these, exactly here.
        "deposits": settlement
            .deposits()
            .iter()
            .map(|(recipient, amount)| json!({ "recipient": hex(recipient), "amount": amount }))
            .collect::<Vec<_>>(),

        // One `claimWithdrawal(recipient, amount, chainBefore)` call each, after the batch has
        // settled -- in the *reverse* of this order, because the queue unwinds newest-first. The
        // first entry's `chainBefore` is the genesis value, which is where the queue drains.
        "withdrawals": settlement
            .withdrawal_claims()
            .iter()
            .map(|(recipient, amount, chain_before)| json!({
                "recipient": hex(recipient),
                "amount": amount,
                "chainBefore": hex(chain_before),
            }))
            .collect::<Vec<_>>(),

        // One `forceExit(...)` call each, in any order, once the rollup has escaped. Empty for
        // every scenario but the one built for it -- an exit proves against a frozen root, so it
        // has nothing to do with settling and is emitted alongside rather than as part of it.
        "exits": if scenario.name == "forced-exit" {
            scenarios::forced_exit_proofs()
                .iter()
                .map(|exit| json!({
                    "address": hex(&exit.address),
                    "pubKey": hex(&exit.pub_key),
                    "nonce": exit.nonce,
                    "amount": exit.amount,
                    "authAddress": hex(&exit.auth_address),
                    "siblings": exit.siblings.iter().map(|s| hex(s)).collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        },

        // `openBatch(batchLength)`, then one `accumulateChunk(chunk)` per entry, in this order.
        "batchLength": settlement.batch_length(),
        "chunkCount": settlement.chunk_count(),
        "chunks": settlement.chunks().map(hex).collect::<Vec<_>>(),
        // The same bytes unsplit, for a test that wants to re-cut them itself.
        "batch": hex(settlement.batch_bytes()),

        "settlesFromGenesis": settlement.settles_from_genesis(),
        "sidecarLength": settlement.sidecar_bytes().len(),
    });

    if include_sidecar {
        fixture["sidecar"] = json!(hex(settlement.sidecar_bytes()));
    }

    fixture
}
