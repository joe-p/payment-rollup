import { beforeAll, describe, it } from "vitest";
import { RollupVerifier } from "../src";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import fixture from "../fixtures/settlements.json";

describe("rollup verifier", () => {
  let sender: algosdk.AddressWithTransactionSigner;
  let algorand: AlgorandClient;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    const acct = await algorand.account.localNetDispenser();
    sender = { address: acct.addr, txnSigner: acct.signer };
  });

  for (const scenario of fixture.scenarios) {
    it(`should verify with scenario ${scenario.name}`, async () => {
      const client = await RollupVerifier.create(algorand, sender);

      await client.appClient.send.seedStateRoot({
        sender: sender.address,
        signer: sender.txnSigner,
        args: { root: Buffer.from(scenario.oldRoot, "hex") },
      });

      await client.verifyBatch(
        sender,
        Buffer.from(scenario.batch, "hex"),
        Buffer.from(scenario.publicValues, "hex"),
      );
    });
  }
});
