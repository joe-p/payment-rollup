# Algorand ZK Rollup

This repository contains a proof-of-concept for a ZK rollup on Algorand using SP1 zkVM. It has not
been audited and is not intended for production use.

[The zkVM program](./crates/sp1-guest/src/main.rs) proves one block of a payment rollup: payments
between L2 accounts, deposits credited from the L1, and withdrawals paid out on the L1. Payments
carry one sender, one receiver, and a fee. Accounts sign with ed25519 or with a hybrid of
FALCON-1024 (deterministic, as Algorand implements it) and ed25519, where both halves must verify.

[The contract](./contracts/contracts/rollup-verifier.algo.ts) is the L1 settlement contract. It
takes batch bytes as posted calldata, verifies the SP1 Groth16 proof against them, and advances its
state roots. Alongside that it handles deposits, forced withdrawals, withdrawal payouts, and the
escape hatch. There is a security council that can permanently escape the L1 contract or schedule a
delayed verifier rotation or contract update. The L1 design is more or less the same regardless of
what is happening on the L2. The exception is if the L2 has more complex state that should be
forced/proven on the L1 (e.g. EVM account state).

## Repository Layout

| Path | What it is |
| --- | --- |
| [`crates/payment-rollup`](./crates/payment-rollup) | The state transition itself: batch codec, merkle tree, signature verification |
| [`crates/sp1-guest`](./crates/sp1-guest) | The zkVM entrypoint, which is just io around `payment_rollup::execute` |
| [`crates/sp1-host`](./crates/sp1-host) | Emits settlement fixtures, proves scenarios, and reports what they cost |
| [`crates/falcon-det1024`](./crates/falcon-det1024) | Safe wrapper over the same Falcon C library the AVM runs |
| [`contracts`](./contracts) | The L1 settlement contract and its test suite |
| [`benchmarks/signature-schemes`](./benchmarks/signature-schemes) | Cost of verifying each candidate PQ scheme in the guest |

Two docs sit beside the code:

- [`proofs.md`](./proofs.md) - proof times and cost per transaction, on the Succinct Prover Network
  and on single GPUs
- [`schemes.md`](./schemes.md) — measured cycles, gas, and bytes for each candidate signature
  scheme, and why Falcon-1024 won

## Tech Stack

- The SP1 zkVM is used for L2 block proving.
- The succinct proving network is used for generating proofs (runpod was used for single GPU proving measurements)
- The [snarkjs-algorand](https://github.com/joe-p/snarkjs-algorand) library was used for the Algorand groth16 BN254 contract and client-side code. This library was written by myself and not audited.
- Algorand's [FALCON library](https://github.com/algorand/falcon) for deterministic FALCON-1024 signature verification

## ZK Rollup Architecture

Below is the high level flow of how a ZK-rollup works. For a more detailed overview, refer to the
Ethereum developer docs on ZK rollups
[here](https://ethereum.org/developers/docs/scaling/zk-rollups/).

1. Assets locked in L1 contract

1. The off-chain sequencer verifies and processes signed transactions. Transactions can either be
   sourced directly from the L2 or forced from the L1

1. Sequencer generates a zkVM proof. This proves the state transition from old merkle root(s) to new
   merkle root(s)

1. Sequencer posts the batch bytes to the L1, in chunks, so anyone can replay the L2 from L1 data
   alone. The proof only carries a commitment to the batch; the contract hashes the posted bytes
   itself and compares

1. L1 verifies proof submitted by the sequencer. Updates global state values from old root(s) to new
   root(s)

In this implementation the sequencer is a single permissioned party: the app creator is the only
address that may settle a batch. The trust model below does not depend on that.

### Trust Model

#### Safety

The L2 inherits the safety of the L1. If the L1 is safe and the L2 proof system is sound, the L2
funds are safe. This means a rogue sequencer cannot steal funds.

#### Liveness

If the sequencer goes down the state roots in the L1 contract will not move forward. The L1 measures
that by what the sequencer has left sitting: once the oldest pending L1 inbox entry(a deposit
waiting to be credited or a withdrawal request waiting to be answered) has waited longer than the
contract's `inboxTimeout`, anyone may signal an escape. That starts a grace period, which the
sequencer can extend by settling inbox entries or making payouts. If it lets the grace period lapse,
the roots in the L1 are permanently frozen and users prove their account state on the L1 to get back
their funds.

Note the trigger is a pending inbox entry, not idleness on its own: a sequencer that stops while the
inbox is empty trips nothing until someone deposits or requests a withdrawal. The security council
can also escape immediately, without waiting for any of this. Once escaped, the contract never
unfreezes.

#### Censorship

If the sequencer is updating state on the L1 but censoring specific transactions, a user can force
their exit by posting a withdrawal request to the L1. What can be forced is leaving, not an
arbitrary L2 payment. This prevents race conditions happening between transactions from the L1 and the L2.

A forced request joins the same L1 inbox as deposits, so it is the same watchdog as above that
answers it: the sequencer has until `inboxTimeout` plus the grace period to include the request, and
the state freezes if it does not.

## Development

Requires Rust, `pnpm`, and [AlgoKit](https://github.com/algorandfoundation/algokit-cli) for
LocalNet. `sp1-host` enables its `prove` feature by default, which compiles the guest to RISC-V, so
a default build of the workspace also needs the SP1 toolchain and `protoc`:

```sh
curl -L https://sp1up.succinct.xyz | bash && sp1up
apt-get install protobuf-compiler
```

The Falcon C library is a submodule:

```sh
git submodule update --init --recursive
cargo test
```

The contract test suite runs against LocalNet, replaying committed settlement fixtures — including
two with real Groth16 proofs — through the contract:

```sh
algokit localnet start
cd contracts
pnpm install
pnpm build   # compiles the contract, generates clients, regenerates settlement fixtures
pnpm test
```

`sp1-host` drives everything proof-side. Emitting fixtures replays the guest natively, so
`--no-default-features` is enough for it and skips the SP1 toolchain entirely:

```sh
cargo run -p sp1-host --no-default-features -- --list               # the scenarios it can emit
cargo run -p sp1-host --no-default-features -- --out fixtures.json  # emit them all
```

Cost reporting executes a block in the zkVM locally, which is free but needs the guest ELF that the
default `prove` feature builds. `--prove` goes to the Succinct Prover Network and additionally needs
`NETWORK_PRIVATE_KEY` in the environment, because each request is paid. Both take named scenarios,
and the expensive ones — `falcon-1000` among them — are hidden from `--list` so they cannot be run
by accident:

```sh
cargo run -p sp1-host -- --report falcon-1000
cargo run -p sp1-host -- --prove falcon-1000
```

## Future Work

### TEE Integration

L2s may have multiple ways of verifying state transitions. One approach is to use a combination of
TEEs and zkVMs. The TEEs are a trust-minimized way to verify state transitions with low latency,
while zkVMs offer a fully trustless verification path with higher latency. This is similar to the
architecture of [Base](https://l2beat.com/layer2s/projects/base#state-validation)

## AI Disclosure

Various models were used during the development of the code in this repository. I used an agent to implement architeural decision that I made alone or after consultation of the agent. The code here has been reviewed at a high level to make sure it matches the desired architecture, but it has not gone under an in-depth audit. This is definitely not production-ready.
