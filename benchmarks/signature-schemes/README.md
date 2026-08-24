# Signature scheme benchmark

What one signature verification of each candidate scheme costs inside the SP1 guest. The numbers it
produces, and what they argue for, are in [`../../schemes.md`](../../schemes.md).

This measures schemes the protocol does **not** support and is not going to. It exists so the choice
of `Scheme::Falcon1024HybridEd25519` rests on measurements rather than on intuitions about which
primitive "should" be cheap in a zkVM — several of those intuitions turned out to be wrong by
multiples, in both directions.

## Running it

```
cargo run --release
```

Needs the SP1 toolchain, since it compiles a guest for RISC-V:

```
curl -L https://sp1up.succinct.xyz | bash && sp1up
```

No network, no credential, no GPU: this executes the guest locally and reads the cycle counts off
the executor. It never proves anything.

## Why it is a separate workspace

It is excluded from the root workspace on purpose, and needs to stay that way. Two reasons, either
one sufficient:

- It depends on `ml-dsa` and `slh-dsa`, which nothing in the protocol does. They have no business in
  the lockfile the guest is built from.
- It has `[patch.crates-io]` entries of its own, and `[patch]` is workspace-global. As a member they
  would silently apply to `sp1-guest`.

## How it measures

Each verification is wrapped in a `cycle-tracker-report-start/end` pair. The SP1 executor turns
those into `ExecutionReport::cycle_tracker`, so one run reports every scheme separately. This is why
the host enables `sp1-sdk`'s `profiling` feature — without it the markers are printed as ordinary
guest output and the map comes back empty.

Three things the measurement is careful about, each of which caught a real error while it was being
written:

- **Every scheme's hashing reaches the precompile it would reach in a real guest.** Otherwise the
  benchmark compares software hashing, which is 18x slower for the hash-based schemes and would
  misrepresent them badly. See the `[patch.crates-io]` section in `Cargo.toml`, and note that
  `ml-dsa` needs a patch that upstream does not publish (`vendor/keccak-sp1`).
- **Cold, not warm.** `ml-dsa`'s `VerifyingKey::decode` expands the matrix A, which is a real part of
  a first verification. Measuring with `decode` outside the region reported ML-DSA at 59% of its
  actual cost. Both figures are now reported, `-cold` and `-warm`.
- **Falcon at two degrees through one code path.** `falcon-det1024` fixes `logn = 10`, so comparing
  Falcon-512 against Falcon-1024 goes through the generic C API for both (`falcon_raw.rs`). The
  `falcon-1024` and `falcon-1024-generic` figures agreeing to 0.3% is what says that path is honest.

## Reading the output

`total`/`gas` cover the whole run and are not per-scheme. The `per-scheme instructions` block is the
interesting part. Regions that are not whole verifications:

| region | what it is |
| --- | --- |
| `falcon-1024-pubkey-expand` | decode + NTT of the public key: the cacheable part of a verify |
| `falcon-1024-range-check` | what an expanded-key format would pay in place of the above |
| `ml-dsa-87-warm` | a second verify, with A already expanded |

`gas` is reported for the run as a whole because the executor does not attribute it per region.
Per-scheme gas in `schemes.md` is derived by differencing runs, and is marked as such.
