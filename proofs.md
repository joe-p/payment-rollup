## Prover Network

Right now gas is very cheap on the prover network, so every proof essentially pays just the base fee which is about $0.07. The downside of the prover network is that there can be a lot of variance in proof times.

| Scenario | Commit | Proof Time | Request Link | Cost/Tx |
| --- | --- | --- | --- | --- |
| 100 Ed25519 | [dcbe03e](https://github.com/joe-p/payment-rollup/commit/dcbe03e31ca4d4af4ad14b18aa0e47def0a8bb66) | 37s | [0xdfe9555e191944a9a81e9fca8c6b4e03348b0e535b1eab9784dca565ffe3ee52](https://explorer.succinct.xyz/request/0xdfe9555e191944a9a81e9fca8c6b4e03348b0e535b1eab9784dca565ffe3ee52) | $0.0007 |
| 1,000 Ed25519 | [dcbe03e](https://github.com/joe-p/payment-rollup/commit/dcbe03e31ca4d4af4ad14b18aa0e47def0a8bb66) | 1m 37s | [0x5defd310d7d2c82dbcac3fb6ebd3b7a8aec7c8567ecb97ad98b5b8a160ac92ce](https://explorer.succinct.xyz/request/0x5defd310d7d2c82dbcac3fb6ebd3b7a8aec7c8567ecb97ad98b5b8a160ac92ce) | $0.00007 |
| 10,000 Ed25519 | [dcbe03e](https://github.com/joe-p/payment-rollup/commit/dcbe03e31ca4d4af4ad14b18aa0e47def0a8bb66) | 9m 1s | [0x1b370806c4560a9cead5d11cf1bd888e46c4069bc5ed1e8885c032b1e12e8d69](https://explorer.succinct.xyz/request/0x1b370806c4560a9cead5d11cf1bd888e46c4069bc5ed1e8885c032b1e12e8d69) | $0.000007 |
| 100 FALCON+Ed25519 | [f061738](https://github.com/joe-p/payment-rollup/commit/f0617389cc7e7ed55dc3769efd64bc53cdf7d382) | 36s | [0x3647587f7a18f38e5058a8c7249f8ee9a3712ae8b8cd1f7019582d994d06898a](https://explorer.succinct.xyz/request/0x3647587f7a18f38e5058a8c7249f8ee9a3712ae8b8cd1f7019582d994d06898a) | $0.0007 |
| 1,000 FALCON+Ed25519 | [f061738](https://github.com/joe-p/payment-rollup/commit/f0617389cc7e7ed55dc3769efd64bc53cdf7d382) | 1m 41s | [0xf0e58c2cf07a18b6213ef85945760df3507e7994cc062315501fa0c03b896842](https://explorer.succinct.xyz/request/0xf0e58c2cf07a18b6213ef85945760df3507e7994cc062315501fa0c03b896842) | $0.00007 |
| 219.831150113 10,000 FALCON+Ed25519 | [f061738](https://github.com/joe-p/payment-rollup/commit/f0617389cc7e7ed55dc3769efd64bc53cdf7d382) | 8m 50s | [0xeb765d152c05b02962a933823f2e5e2c2a35894c99223719410a1992a67ec711](https://explorer.succinct.xyz/request/0xeb765d152c05b02962a933823f2e5e2c2a35894c99223719410a1992a67ec711) | $0.000007 |

## Single GPUs

| GPU | Scenario | Commit | Time | Proof Cost | Cost/Tx |
| --- | --- | --- | --- | --- | -- |
| L40S | 100 ed25519 | [5f52307](https://github.com/joe-p/payment-rollup/commit/5f5230796c20d111fef48e5d68560eb10b508a31) | 163s | $0.05 | $0.0005 |
| L40S | 1000 FALCON-1024 + ed25519 | [5f52307](https://github.com/joe-p/payment-rollup/commit/5f5230796c20d111fef48e5d68560eb10b508a31) | 576s | $0.15 | $0.0001585 |

L40S was used because it was the most available and the most comparable to an AWS offering: `g6e.4xlarge`

TODO: Testing with 5090 and 4090
