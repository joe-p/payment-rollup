import { createHash } from "node:crypto";
import algosdk from "algosdk";
import nacl from "tweetnacl";
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

/**
 * Minimum balance one withdrawal queue box costs, advanced by whoever settles the batch and
 * returned when the queue drains. Mirrors `WITHDRAWAL_BOX_MBR` in the contract.
 */
export const WITHDRAWAL_BOX_MBR = 31_700n;

/**
 * Smallest withdrawal the guest will prove, in microALGO. Mirrors `MIN_WITHDRAWAL` in the core
 * crate.
 *
 * Equal to the network minimum balance, which is what lets `claimWithdrawal` pay out with an inner
 * transaction that cannot fail for want of a receiver account.
 */
export const MIN_WITHDRAWAL = 100_000n;

/**
 * Minimum balance for the permanent record that an account has been force-exited. Mirrors
 * `EXIT_BOX_MBR` in the contract.
 *
 * Withheld from the exit rather than paid separately, and never returned: the record has to outlive
 * the payout or a frozen state root would keep authorizing the same one.
 */
export const EXIT_BOX_MBR = 18_900n;

/**
 * Minimum balance one pending withdrawal request costs, advanced by the requester and returned by
 * {@link RollupVerifier.pruneRequest}. Mirrors `REQUEST_BOX_MBR` in the contract.
 */
export const REQUEST_BOX_MBR = 47_700n;

/** Largest group the network will accept, and so the most chunks one send can carry. */
const MAX_GROUP_SIZE = 16;

/**
 * Rounds a deposit may sit unsequenced before {@link RollupVerifier.signalEscape} will accept it as
 * evidence the sequencer has stopped, and rounds between that signal and
 * {@link RollupVerifier.executeEscape}.
 *
 * A week and a day, at roughly 2.8 seconds a round. Deployment-time arguments rather than contract
 * constants because there is no `UpdateApplication` handler to retune them later -- and because the
 * e2e has to be able to actually cross the threshold, which it cannot do with numbers this size.
 */
export const DEPOSIT_TIMEOUT_ROUNDS = 216_000n;
export const ESCAPE_GRACE_ROUNDS = 31_000n;

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

  // Node's own SHA-256 rather than algosdk's: algosdk v3 exposes `sha512_256`, which is what
  // Algorand addresses use, and no plain `sha256` at all. The rollup hashes with SHA-256
  // throughout, so reaching for the algosdk helper here would silently derive the wrong address.
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

/** A `BoxMap<uint64, _>` key: the map's one-character prefix and the key, big-endian. */
function boxName(prefix: string, key: bigint): Uint8Array {
  const name = new Uint8Array(9);
  name.set(new TextEncoder().encode(prefix));
  new DataView(name.buffer).setBigUint64(1, key);

  return name;
}

/** The box a deposit is filed in. */
const depositBoxName = (nonce: bigint) => boxName("d", nonce);

/** The box a settled batch's unclaimed withdrawals are queued in. */
const withdrawalBoxName = (batchNumber: bigint) => boxName("w", batchNumber);

/** The box a pending L1 withdrawal request is filed in. */
const requestBoxName = (nonce: bigint) => boxName("r", nonce);

/**
 * The bytes a holder signs to demand that their account be let out.
 *
 * Mirrors the preimage `requestWithdrawal` builds. The application id keeps the signature from being
 * carried to another deployment; the nonce makes it authorize one request rather than an unbounded
 * stream of replays of it.
 */
export function withdrawalRequestMessage(
  appId: bigint,
  nonce: bigint,
  address: Uint8Array,
  recipient: algosdk.Address,
): Uint8Array {
  const tag = new TextEncoder().encode("WREQ");
  const message = new Uint8Array(tag.length + 8 + 8 + 32 + 32);
  const view = new DataView(message.buffer);

  message.set(tag);
  view.setBigUint64(tag.length, appId);
  view.setBigUint64(tag.length + 8, nonce);
  message.set(address, tag.length + 16);
  message.set(recipient.publicKey, tag.length + 16 + 32);

  return message;
}

/** The box recording that a rollup address has been force-exited: the `"e"` prefix and the address. */
function exitBoxName(address: Uint8Array): Uint8Array {
  const name = new Uint8Array(33);
  name.set(new TextEncoder().encode("e"));
  name.set(address, 1);

  return name;
}

/**
 * The bytes a holder signs to authorize a forced exit of `address` to `recipient`.
 *
 * Mirrors the preimage `forceExit` builds. The application id is in there so a signature cannot be
 * carried to another deployment where the same key controls the same rollup address.
 */
export function exitMessage(
  appId: bigint,
  address: Uint8Array,
  recipient: algosdk.Address,
): Uint8Array {
  const tag = new TextEncoder().encode("EXIT");
  const message = new Uint8Array(tag.length + 8 + 32 + 32);

  message.set(tag);
  new DataView(message.buffer).setBigUint64(tag.length, appId);
  message.set(address, tag.length + 8);
  message.set(recipient.publicKey, tag.length + 8 + 32);

  return message;
}

/**
 * Opcode allowance one application call carries, and so what each `opUp` filler contributes to the
 * group's pool.
 */
const OPCODE_BUDGET_PER_CALL = 700;

/**
 * What `forceExit` spends, near enough to size the filler calls from.
 *
 * `ed25519verify_bare` is 1900 and dwarfs everything else; each `sha256` is 35, and the fold runs
 * one per level plus two for the leaf and the key derivation. The rest is slack for the box write,
 * the payment, and the byte-slicing around them.
 */
function forceExitOpcodeCost(depth: number): number {
  return 1900 + 35 * (depth + 2) + 400;
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

  /**
   * Deploy a rollup.
   *
   * The two escape parameters default to production values; a test that needs to reach the escape
   * hatch passes something it can actually wait out.
   */
  static async create(
    algorand: AlgorandClient,
    creator: algosdk.AddressWithTransactionSigner,
    depositTimeout: bigint = DEPOSIT_TIMEOUT_ROUNDS,
    escapeGrace: bigint = ESCAPE_GRACE_ROUNDS,
  ) {
    const factory = algorand.client.getTypedAppFactory(RollupVerifierFactory);

    const result = await factory.send.create.createApplication({
      sender: creator.address,
      signer: creator.txnSigner,
      note: `Created on ${Date.now()}`,
      args: { depositTimeout, escapeGrace },
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

  /** Nonce the next withdrawal request will take. */
  async requestCursor(): Promise<bigint> {
    return (await this.appClient.state.global.requestCursor()) ?? 0n;
  }

  /**
   * Demand from L1 that an account be emptied to `recipient`, whether the sequencer likes it or not.
   *
   * The whole balance leaves; no amount is named. Once filed, no batch can settle until it is
   * answered, so a sequencer that wants to keep censoring has to stop settling entirely -- which
   * starts the escape clock.
   *
   * `secretKey` is the 64-byte Ed25519 secret for the key `address` derives from; it never leaves
   * this process. Padded with `opUp` fillers because verifying the signature costs more opcodes than
   * one application call is given.
   *
   * @returns The nonce the request was filed under.
   */
  async requestWithdrawal(
    sender: algosdk.AddressWithTransactionSigner,
    address: Uint8Array,
    pubKey: Uint8Array,
    recipient: string,
    secretKey: Uint8Array,
  ): Promise<bigint> {
    const nonce = await this.requestCursor();
    const signature = nacl.sign.detached(
      withdrawalRequestMessage(
        this.appClient.appId,
        nonce,
        address,
        algosdk.decodeAddress(recipient),
      ),
      secretKey,
    );

    const payment = await this.appClient.algorand.createTransaction.payment({
      sender: sender.address,
      receiver: this.appClient.appAddress,
      amount: microAlgo(REQUEST_BOX_MBR),
    });

    const senderSigner = { sender: sender.address, signer: sender.txnSigner };
    let group = this.appClient.newGroup();
    // One signature check and a couple of hashes, so a pair of fillers is ample.
    for (let i = 0; i < 3; i++) {
      group = group.opUp({ ...senderSigner, args: { nonce: BigInt(i) } });
    }

    const result = await group
      .requestWithdrawal({
        ...senderSigner,
        args: {
          payment,
          expectedNonce: nonce,
          address,
          recipient,
          scheme: new TextEncoder().encode("edd"),
          pubKey,
          signature,
        },
        boxReferences: [requestBoxName(nonce)],
      })
      .send();

    return result.returns![0] as bigint;
  }

  /** Reclaim an answered request's box, refunding its minimum balance to whoever filed it. */
  async pruneRequest(
    sender: algosdk.AddressWithTransactionSigner,
    nonce: bigint,
  ): Promise<void> {
    await this.appClient.send.pruneRequest({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { nonce },
      boxReferences: [requestBoxName(nonce)],
      extraFee: microAlgo(1_000),
    });
  }

  /**
   * Refund a deposit the rollup will never credit, in full, to the account that paid it.
   *
   * Only after {@link executeEscape}. The counterpart to {@link pruneDeposit}: below
   * `settledDepositCursor` a batch consumed the deposit and only the box minimum balance is owed,
   * at or above it the whole payment is.
   */
  async reclaimDeposit(
    sender: algosdk.AddressWithTransactionSigner,
    nonce: bigint,
  ): Promise<void> {
    await this.appClient.send.reclaimDeposit({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { nonce },
      boxReferences: [depositBoxName(nonce)],
      // Covers the refund's inner transaction, whose own fee the contract sets to zero.
      extraFee: microAlgo(1_000),
    });
  }

  /**
   * Accuse the sequencer of having stopped, by pointing at the head of each pending queue.
   *
   * Permissionless. Both heads are referenced because either can be the stale one: a deposit left
   * uncredited, or a withdrawal request left unanswered. The contract reads their rounds and
   * nothing else, and only reads a queue it has already found to be non-empty.
   */
  async signalEscape(
    sender: algosdk.AddressWithTransactionSigner,
  ): Promise<void> {
    const deposits =
      (await this.appClient.state.global.settledDepositCursor()) ?? 0n;
    const requests =
      (await this.appClient.state.global.settledRequestCursor()) ?? 0n;

    await this.appClient.send.signalEscape({
      sender: sender.address,
      signer: sender.txnSigner,
      args: {},
      boxReferences: [depositBoxName(deposits), requestBoxName(requests)],
    });
  }

  /**
   * Pull the escape hatch, once the grace period has run out with no settlement.
   *
   * Permissionless and terminal: afterwards no deposit is accepted, no batch settles, the state
   * root is final, and every pending deposit is refundable through {@link reclaimDeposit}.
   */
  async executeEscape(
    sender: algosdk.AddressWithTransactionSigner,
  ): Promise<void> {
    await this.appClient.send.executeEscape({
      sender: sender.address,
      signer: sender.txnSigner,
      args: {},
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
   * Pay an L2 balance out against the frozen state root, on the holder's own authority.
   *
   * Only after {@link executeEscape}. `secretKey` is the 64-byte Ed25519 secret for the key the
   * account's `auth_address` names -- it never leaves this process; what goes on-chain is the
   * signature over {@link exitMessage}.
   *
   * The call is padded with `opUp` fillers because the AVM pools opcode allowance across a group and
   * verifying a signature costs more than one call is given on its own.
   *
   * @returns The amount actually paid out, which is the balance less the cost of the permanent
   *   record that this account has exited.
   */
  async forceExit(
    sender: algosdk.AddressWithTransactionSigner,
    exit: {
      address: Uint8Array;
      pubKey: Uint8Array;
      nonce: bigint;
      amount: bigint;
      authAddress: Uint8Array;
      siblings: Uint8Array[];
    },
    recipient: algosdk.Address,
    secretKey: Uint8Array,
  ): Promise<bigint> {
    const appId = this.appClient.appId;
    const signature = nacl.sign.detached(
      exitMessage(appId, exit.address, recipient),
      secretKey,
    );

    const siblings = new Uint8Array(exit.siblings.length * 32);
    exit.siblings.forEach((s, i) => siblings.set(s, i * 32));

    const senderSigner = { sender: sender.address, signer: sender.txnSigner };
    const fillers =
      Math.ceil(
        forceExitOpcodeCost(exit.siblings.length) / OPCODE_BUDGET_PER_CALL,
      ) - 1;

    let group = this.appClient.newGroup();
    for (let i = 0; i < fillers; i++) {
      // The nonce only exists to keep two fillers from being the same transaction.
      group = group.opUp({ ...senderSigner, args: { nonce: BigInt(i) } });
    }

    await group
      .forceExit({
        ...senderSigner,
        args: {
          address: exit.address,
          nonce: exit.nonce,
          amount: exit.amount,
          authAddress: exit.authAddress,
          scheme: new TextEncoder().encode("edd"),
          pubKey: exit.pubKey,
          signature,
          recipient: recipient.toString(),
          siblings,
        },
        boxReferences: [exitBoxName(exit.address)],
        // Covers the payout's inner transaction, whose own fee the contract sets to zero.
        extraFee: microAlgo(1_000),
      })
      .send();

    return exit.amount - EXIT_BOX_MBR;
  }

  /** Number the next batch to settle will take, and so the key its withdrawal queue lands under. */
  async batchNumber(): Promise<bigint> {
    return (await this.appClient.state.global.batchNumber()) ?? 0n;
  }

  /**
   * Pay out one withdrawal from a settled batch's queue.
   *
   * Claims unwind the queue newest-first: `previousChain` is the chain value standing immediately
   * before this withdrawal was folded in, and the last claim is the one whose `previousChain` is
   * 32 zero bytes. Permissionless -- the payout goes to `recipient` whoever calls this.
   */
  async claimWithdrawal(
    sender: algosdk.AddressWithTransactionSigner,
    batchNumber: bigint,
    recipient: string,
    amount: bigint,
    previousChain: Uint8Array,
  ): Promise<void> {
    // Draining the queue deletes the box and refunds its minimum balance, which is a second inner
    // transaction. Paying for both every time costs 1000 µALGO and avoids making the caller know
    // which claim is the last one.
    await this.appClient.send.claimWithdrawal({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { batchNumber, recipient, amount, previousChain },
      boxReferences: [withdrawalBoxName(batchNumber)],
      extraFee: microAlgo(2_000),
    });
  }

  /**
   * Post a batch and settle it: open, accumulate every chunk, then verify.
   *
   * The deposits the batch credits must already have been made -- `verifyBatch` compares the chain
   * they folded on L1 against the one the batch folds to, so a missing or out-of-order deposit
   * fails at the very end, after every chunk has been paid for.
   *
   * `withdraws` says whether the batch's public values carry a non-genesis withdrawal chain. When
   * they do, the settling call has to be preceded in its own group by a payment covering the queue
   * box's minimum balance, and a box reference for the queue.
   */
  async verifyBatch(
    sender: algosdk.AddressWithTransactionSigner,
    batch: Uint8Array,
    publicValues: Uint8Array,
    withdraws: boolean = false,
  ): Promise<void> {
    const batchLength = batch.byteLength;
    const senderSigner = { sender: sender.address, signer: sender.txnSigner };

    await this.appClient.send.openBatch({
      ...senderSigner,
      args: {
        batchLength,
        expectedDepositCursor: await this.depositCursor(),
        expectedRequestCursor: await this.requestCursor(),
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

    if (!withdraws) {
      await this.appClient.send.verifyBatch({
        ...senderSigner,
        args: { publicValues },
      });

      return;
    }

    // The contract reads the transaction immediately before this one, so the funding payment and
    // the settling call have to travel together.
    const batchNumber = await this.batchNumber();
    const funding = await this.appClient.algorand.createTransaction.payment({
      sender: sender.address,
      receiver: this.appClient.appAddress,
      amount: microAlgo(WITHDRAWAL_BOX_MBR),
    });

    await this.appClient
      .newGroup()
      .addTransaction(funding, sender.txnSigner)
      .verifyBatch({
        ...senderSigner,
        args: { publicValues },
        boxReferences: [withdrawalBoxName(batchNumber)],
      })
      .send();
  }
}
