| Scenario | Commit | Gas | Proof Time | Request Link |
| --- | --- | --- | --- | --- |
| 100 Ed25519 | [dcbe03e](https://github.com/joe-p/payment-rollup/commit/dcbe03e31ca4d4af4ad14b18aa0e47def0a8bb66) | 20,495,245 PGUs | 37s | [0xdfe9555e191944a9a81e9fca8c6b4e03348b0e535b1eab9784dca565ffe3ee52](https://explorer.succinct.xyz/request/0xdfe9555e191944a9a81e9fca8c6b4e03348b0e535b1eab9784dca565ffe3ee52) |
| 1,000 Ed25519 | [dcbe03e](https://github.com/joe-p/payment-rollup/commit/dcbe03e31ca4d4af4ad14b18aa0e47def0a8bb66) | 203,254,359 PGUs | 1m 37s | [0x5defd310d7d2c82dbcac3fb6ebd3b7a8aec7c8567ecb97ad98b5b8a160ac92ce](https://explorer.succinct.xyz/request/0x5defd310d7d2c82dbcac3fb6ebd3b7a8aec7c8567ecb97ad98b5b8a160ac92ce) |
| 10,000 Ed25519 | [dcbe03e](https://github.com/joe-p/payment-rollup/commit/dcbe03e31ca4d4af4ad14b18aa0e47def0a8bb66) | 2,191,986,152 PGUs | 9m 1s | [0x1b370806c4560a9cead5d11cf1bd888e46c4069bc5ed1e8885c032b1e12e8d69](https://explorer.succinct.xyz/request/0x1b370806c4560a9cead5d11cf1bd888e46c4069bc5ed1e8885c032b1e12e8d69) |
| 100 FALCON+Ed25519 | [f061738](https://github.com/joe-p/payment-rollup/commit/f0617389cc7e7ed55dc3769efd64bc53cdf7d382) | 108,334,578 PGUs | 36s | [0x3647587f7a18f38e5058a8c7249f8ee9a3712ae8b8cd1f7019582d994d06898a](https://explorer.succinct.xyz/request/0x3647587f7a18f38e5058a8c7249f8ee9a3712ae8b8cd1f7019582d994d06898a) |
| 1,000 FALCON+Ed25519 | [f061738](https://github.com/joe-p/payment-rollup/commit/f0617389cc7e7ed55dc3769efd64bc53cdf7d382) | 1,083,957,598 PGUs | 1m 41s | [0xf0e58c2cf07a18b6213ef85945760df3507e7994cc062315501fa0c03b896842](https://explorer.succinct.xyz/request/0xf0e58c2cf07a18b6213ef85945760df3507e7994cc062315501fa0c03b896842) |
|219.831150113 10,000 FALCON+Ed25519 | [f061738](https://github.com/joe-p/payment-rollup/commit/f0617389cc7e7ed55dc3769efd64bc53cdf7d382) | 11,056,978,187 PGUs| 8m 50s | [0xeb765d152c05b02962a933823f2e5e2c2a35894c99223719410a1992a67ec711](https://explorer.succinct.xyz/request/0xeb765d152c05b02962a933823f2e5e2c2a35894c99223719410a1992a67ec711) |

NOTES:

- There is a significant amount of variance on the prover network. For example, the same ed25519 scenario that took 37s above took 1m19s here: https://explorer.succinct.xyz/request/0x1f62bc9f74fbb00ff5fc1be94b00137fc21b6c6df5f14572cbe7ac7cde08f8f4
- On a runpod H100 SXM (28 Intel(R) Xeon(R) Platinum 8480+ vCPUs with 251GB memory) the 100 ed25519 scenario took 253.424721643s to prove.
  - This suggests a cluster of multiple 5090s or 4090s is probably the best bang/buck for self proving. This is what we commonly see for ETH proofs.
