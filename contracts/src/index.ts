import algosdk from "algosdk";
import {
  RollupVerifierFactory,
  RollupVerifierClient,
} from "../contracts/clients/RollupVerifierClient";

import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";

/**
 * Must equal `CHUNK_SIZE` in the contract and in the guest. The fixtures emit it as `chunkSize` so
 * a test can assert the three agree rather than trusting that they do.
 */
export const CHUNK_SIZE = 4094;

/**
 * Minimum balance one deposit box costs, which the depositor advances and `pruneDeposit` returns.
 * Mirrors `DEPOSIT_BOX_MBR` in the contract.
 */
export const DEPOSIT_BOX_MBR = 38_100n;

/** Largest group the network will accept, and so the most chunks one send can carry. */
const MAX_GROUP_SIZE = 16;

/**
 * The rollup address a key controls, mirroring `address_from_public_key`.
 *
 * Deposits name their recipient by this and not by an Algorand address, and the contract cannot
 * tell the two apart -- depositing to an algosdk address credits an account no key controls and the
 * funds are unrecoverable. Derive it here rather than by hand.
 */
export function l2Address(scheme: string, pubKey: Uint8Array): Uint8Array {
  const tag = new TextEncoder().encode(`ADDR${scheme}`);
  const preimage = new Uint8Array(tag.length + pubKey.length);
  preimage.set(tag);
  preimage.set(pubKey, tag.length);

  return new Uint8Array(algosdk.sha256(preimage));
}

/** The box a deposit is filed in: the map's `"d"` prefix and the nonce, big-endian. */
function depositBoxName(nonce: bigint): Uint8Array {
  const name = new Uint8Array(9);
  name.set(new TextEncoder().encode("d"));
  new DataView(name.buffer).setBigUint64(1, nonce);

  return name;
}

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
    const factory = algorand.client.getTypedAppFactory(RollupVerifierFactory);

    const result = await factory.send.create.createApplication({
      sender: creator.address,
      signer: creator.txnSigner,
      note: `Created on ${Date.now()}`,
      args: {},
    });

    const verifier = new RollupVerifier(algorand, result.appClient.appId);

    // The app holds real ALGO now, so it needs its own base minimum balance before anything can pay
    // it. Each deposit brings its own box's minimum balance with it; this is only the account.
    await algorand.send.payment({
      sender: creator.address,
      signer: creator.txnSigner,
      receiver: result.appClient.appAddress,
      amount: microAlgo(100_000),
    });

    return verifier;
  }

  /** Nonce the next deposit will take, which `openBatch` has to be told to expect. */
  async depositCursor(): Promise<bigint> {
    return (await this.appClient.state.global.depositCursor()) ?? 0n;
  }

  /**
   * Move `amount` microALGO into the rollup, credited to the L2 address `recipient`.
   *
   * The payment carries the box's minimum balance on top of `amount`, so the depositor advances it
   * and gets it back from {@link pruneDeposit} once the deposit has settled.
   *
   * @returns The nonce the deposit was filed under.
   */
  async deposit(
    sender: algosdk.AddressWithTransactionSigner,
    recipient: Uint8Array,
    amount: bigint,
  ): Promise<bigint> {
    const nonce = await this.depositCursor();

    const payment = await this.appClient.algorand.createTransaction.payment({
      sender: sender.address,
      receiver: this.appClient.appAddress,
      amount: microAlgo(amount + DEPOSIT_BOX_MBR),
    });

    const result = await this.appClient.send.deposit({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { payment, recipient },
      boxReferences: [depositBoxName(nonce)],
    });

    return result.return!;
  }

  /** Reclaim a settled deposit's box, refunding its minimum balance to the account that paid it. */
  async pruneDeposit(
    sender: algosdk.AddressWithTransactionSigner,
    nonce: bigint,
  ): Promise<void> {
    await this.appClient.send.pruneDeposit({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { nonce },
      boxReferences: [depositBoxName(nonce)],
      // Covers the refund's inner transaction, whose own fee the contract sets to zero.
      extraFee: microAlgo(1_000),
    });
  }

  /** Discard a batch that cannot settle, so the next one can be opened. Creator only. */
  async abandonBatch(
    sender: algosdk.AddressWithTransactionSigner,
  ): Promise<void> {
    await this.appClient.send.abandonBatch({
      sender: sender.address,
      signer: sender.txnSigner,
      args: {},
    });
  }

  /**
   * Post a batch and settle it: open, accumulate every chunk, then verify.
   *
   * The deposits the batch credits must already have been made -- `verifyBatch` compares the chain
   * they folded on L1 against the one the batch folds to, so a missing or out-of-order deposit
   * fails at the very end, after every chunk has been paid for.
   */
  async verifyBatch(
    sender: algosdk.AddressWithTransactionSigner,
    batch: Uint8Array,
    publicValues: Uint8Array,
  ): Promise<void> {
    const batchLength = batch.byteLength;
    const senderSigner = { sender: sender.address, signer: sender.txnSigner };

    await this.appClient.send.openBatch({
      ...senderSigner,
      args: {
        batchLength,
        expectedDepositCursor: await this.depositCursor(),
      },
    });

    const chunks = [];
    for (let i = 0; i < batch.byteLength; i += CHUNK_SIZE) {
      chunks.push(batch.subarray(i, i + CHUNK_SIZE));
    }

    let composer = this.appClient.newGroup();
    let txns = 0;

    for (const chunk of chunks) {
      if (txns === MAX_GROUP_SIZE) {
        await composer.send();
        composer = this.appClient.newGroup();
        txns = 0;
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
