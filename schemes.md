# Why Falcon-1024

What each candidate signature scheme costs to verify inside the SP1 guest, measured rather than
estimated. Reproduce with [`benchmarks/signature-schemes`](benchmarks/signature-schemes); the
per-block figures come from `sp1-host --report`.

Falcon-1024 is the cheapest post-quantum scheme measured, on cycles, on gas, and on bytes — and it
stays cheapest against alternatives one and two security categories *below* it. Nothing here is a
close call.

## One verification, cold

SP1 v6.4.0, `riscv64im-succinct-zkvm-elf`, using the then-current 116-byte `bytes_to_sign` message.
The fee header has since increased that message to 124 bytes; these historical measurements have
not been rerun. Every
scheme's hashing reaches its precompile; instruction counts are exact.

| Scheme | NIST level | Instructions | ≈ Gas | Signature | Public key |
| --- | --- | --- | --- | --- | --- |
| Ed25519 (`verify_strict`) | — (classical) | 94,134 | ~117,000 | 64 | 32 |
| **Falcon-512** | 1 | **428,795** | ~0.43M | 658 | 897 |
| **Falcon-1024** | 5 | **907,584** | ~0.91M | 1,233 | 1,793 |
| ML-DSA-87 | 5 | 2,569,078 | ~2.9M | 4,627 | 2,592 |
| SLH-DSA-SHAKE-128s | 1 | 3,961,385 | ~9.1M | 7,856 | 32 |
| SLH-DSA-SHAKE-192s | 3 | 5,543,395 | ~12.8M | 16,224 | 48 |
| SLH-DSA-SHAKE-256s | 5 | 8,529,530 | ~19.5M | 29,792 | 64 |

Gas is derived, not reported per region: the executor gives one figure per run, so per-scheme gas
comes from differencing runs. That yields ~21 gas per `ED_ADD` and ~1,199 per `KECCAK_PERMUTE`
against ~1 per instruction, which is why the hash-based schemes are further behind on gas than on
cycles. Instruction counts are direct and exact; treat the gas column as ±10%.

## What that means for a 10k-signature block

`falcon-10000` measured at **10.85B instructions / 11.06B gas**, and proved on the network in
6m 46s (see `proofs.md`). Per signature, from the 1000 → 10000 marginal:

| | Instructions | Share |
| --- | --- | --- |
| Falcon-1024 | 907,584 | 83.5% |
| Ed25519 `verify_strict` | 94,134 | 8.7% |
| state / Merkle / decode | ~84,724 | 7.8% |
| **total per signature** | **1,086,442** | |

Substituting the alternatives at the same block size:

| PQ half | Block instructions | vs today |
| --- | --- | --- |
| **Falcon-1024** | **10.85B** | — |
| Falcon-512 | ~6.1B | −44% |
| ML-DSA-87 | ~27B | 2.5x |
| SLH-DSA-SHAKE-128s | ~41B | 3.8x |

SLH-DSA also brings 78.6 MB of signature data per block instead of 12.3 MB, and that is at level 1
against Falcon-1024's level 5.

## Falcon-specific findings

Two levers on the current scheme, neither requiring a protocol change:

| Lever | Block saving | Cost |
| --- | --- | --- |
| Cache the public-key expansion per account | up to −20.5% | none but code |
| Route Falcon's SHAKE through `KECCAK_PERMUTE` | ~−7% | a `__riscv` path in `shake.c` |

The first is the larger one. A quarter of every Falcon verification — **222,440 instructions** — is
`modq_decode` plus `to_ntt_monty` on the public key, which depends on nothing else. The cacheable
artifact is `h`: n 16-bit coefficients, **2 KiB** at n = 1024, and `Zf(verify_raw)` takes it as
`const`, so a cached copy is not clobbered. Saving scales as `1 − (distinct signers / signatures)`;
`falcon-10000` runs ~400 signatures per account, so it captures nearly all of it.

Shipping *expanded* public keys in the protocol instead was considered and rejected. It saves the
same 222,440 less a 5,417-instruction range check — which cannot be dropped, since `modq_decode`
enforces `w < 12289` per coefficient and rejects non-canonical padding, and an address that is the
hash of key bytes needs one byte string per key. At ~400 signatures per account, caching beats it
outright (the crossover is ~41 signatures per account). More importantly, the expanded form is *this
Falcon implementation's* NTT ordering and Montgomery constants (`R = 4091`, `R2 = 10952`), so
committing addresses to it would hardwire an implementation internal: change the library and every
address changes.

Falcon-512 is the largest lever of all at −44%, and the one this document is least willing to
recommend: it drops the post-quantum half from category 5 to category 1, and no deterministic variant
of it exists — `falcon-det1024` fixes `FALCON_DET1024_LOGN 10`, and the det construction is specified
for n = 1024 only.

## Method notes

- Cycle counts come from `ExecutionReport::cycle_tracker`, which needs `sp1-sdk`'s `profiling`
  feature; without it the markers are ordinary guest output and the map is empty.
- That the precompiles are actually reached was confirmed differentially: with the patches removed,
  `KECCAK_PERMUTE` goes to zero and the SLH-DSA figures rise ~18x, while every Falcon figure is
  bit-for-bit identical — Falcon's SHAKE is its own C and was never accelerated in either build.
- `ml-dsa` reaches SHAKE through `shake` → `keccak`, which sp1-patches does not publish a patch for,
  so the benchmark carries one (`benchmarks/signature-schemes/vendor/keccak-sp1`). Without it
  ML-DSA's numbers would be unfairly bad.
- SP1 v6 targets **riscv64**, not riscv32. 64-bit hashing is not the handicap in a zkVM that it is on
  a 32-bit VM, which is why SHA-512 is a small part of Ed25519's cost rather than a large one.
