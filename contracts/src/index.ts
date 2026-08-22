import algosdk from "algosdk";
import {
  RollupVerifierFactory,
  RollupVerifierClient,
} from "../contracts/clients/RollupVerifierClient";

import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";

export class RollupVerifier {
  appClient: RollupVerifierClient;

  constructor(algorand: AlgorandClient, appId: bigint) {
    this.appClient = algorand.client.getTypedAppClientById(
      RollupVerifierClient,
      {
        appId,
      },
    );
  }

  static async create(
    algorand: AlgorandClient,
    creator: algosdk.AddressWithTransactionSigner,
  ) {
    const factory = algorand.client.getTypedAppFactory(RollupVerifierFactory, {
      deployTimeParams: { ALLOW_ROOT_SEEDING: 1 },
    });

    const result = await factory.send.create.createApplication({
      sender: creator.address,
      signer: creator.txnSigner,
      note: `Created on ${Date.now()}`,
      args: {},
    });

    return new RollupVerifier(algorand, result.appClient.appId);
  }

  async verifyBatch(
    sender: algosdk.AddressWithTransactionSigner,
    batch: Uint8Array,
    publicValues: Uint8Array,
  ): Promise<void> {
    const batchLength = batch.byteLength;
    const senderSigner = { sender: sender.address, signer: sender.txnSigner };

    await this.appClient.send.openBatch({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { batchLength },
    });

    const chunks = [];
    for (let i = 0; i < batch.byteLength; i += 4094) {
      chunks.push(batch.subarray(i, i + 4094));
    }

    let composer = this.appClient.newGroup();
    let txns = 0;

    for (const chunk of chunks) {
      if (txns === 16) {
        await composer.send();
        composer = this.appClient.newGroup();
      }
      composer.accumulateChunk({
        ...senderSigner,
        args: { chunk },
        extraFee: microAlgo(531),
      });
      txns++;
    }

    await composer.send();

    await this.appClient.send.verifyBatch({
      ...senderSigner,
      args: { publicValues },
    });
  }
}
