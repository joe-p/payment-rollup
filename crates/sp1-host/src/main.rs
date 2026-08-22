//! Emits settlement fixtures as JSON, for driving the contract end to end before there is a proof.
//!
//! Everything the contract's three methods take comes out of here: `batchLength` to open with,
//! `chunks` to post, and `publicValues` to settle against. See [`sp1_host`] for how they are
//! computed, which is by running the guest program natively.

use std::process::ExitCode;

use serde_json::{Value, json};
use sp1_host::{GENESIS_ROOT, PUBLIC_VALUES_SIZE, Settlement, hex, scenarios};

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

        eprintln!(
            "{}: {} txns, {} B in {} chunk(s), {}",
            scenario.name,
            settlement.txn_count(),
            settlement.batch_length(),
            settlement.chunk_count(),
            if settlement.settles_from_genesis() {
                "settles against a fresh contract".to_string()
            } else {
                format!("needs seedStateRoot({})", hex(&settlement.old_root()))
            },
        );

        emitted.push(fixture(scenario, &settlement, args.include_sidecar));
    }

    let document = json!({
        // Mirrors of the constants the contract hard-codes, so a test can assert the two sides
        // agree rather than hard-coding them a third time.
        "chunkSize": sp1_host::CHUNK_SIZE,
        "publicValuesSize": PUBLIC_VALUES_SIZE,
        "genesisRoot": hex(&GENESIS_ROOT),
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

        // `verifyBatch` takes only this; the roots and the commitment below are the same bytes
        // sliced out, emitted separately so a failing assertion can name which third disagreed.
        "publicValues": hex(settlement.public_values()),
        "oldRoot": hex(&settlement.old_root()),
        "newRoot": hex(&settlement.new_root()),
        "batchCommitment": hex(&settlement.batch_commitment()),

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
