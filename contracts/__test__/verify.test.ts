import { beforeAll, describe, expect, it } from "vitest";
import {
  CHUNK_SIZE,
  EXIT_BOX_MBR,
  INBOX_BOX_MBR,
  MIN_WITHDRAWAL,
  RollupVerifier,
  approvalProgramCommitment,
  decodeSp1VkeyHash,
  deploymentDomain,
  exitMessage,
  l2Address,
  paymentMessage,
  withdrawalMessage,
  withdrawalRequestMessage,
} from "../src";
import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import nacl from "tweetnacl";
import { createHash } from "node:crypto";
import fixture from "../fixtures/settlements.json";
import falcon100 from "../fixtures/proofs/falcon-100.json";
import falcon1000 from "../fixtures/proofs/falcon-1000.json";

const PROOFS = [falcon100, falcon1000];

type Scenario = (typeof fixture.scenarios)[number];

const hex = (value: string) => Buffer.from(value, "hex");

const bytes = (value: bigint) => {
  const result = Buffer.alloc(8);
  result.writeBigUInt64BE(value);
  return result;
};

const queueBox = (cursor: bigint) =>
  Buffer.concat([Buffer.from("i"), bytes(cursor)]);

const sha256 = (...parts: Uint8Array[]) => {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
};

const tag = (value: string) => new TextEncoder().encode(value);

/** Where a batch's payout chain ends. Mirrors `withdrawalTerminal` and `withdrawal_chain_terminal`. */
const withdrawalTerminal = (domain: Uint8Array) => sha256(tag("WEND"), domain);

/** Prepend one payout to a payout chain. Mirrors `accumulate_withdrawal`. */
const accumulateWithdrawal = (
  tail: Uint8Array,
  recipient: Uint8Array,
  amount: bigint,
) => sha256(tag("WPAY"), tail, recipient, bytes(amount));

/**
 * Escape parameters small enough for a test to wait out.
 *
 * The production values are hundreds of thousands of rounds, which is precisely why they are
 * deployment arguments rather than contract constants -- no test could ever reach one.
 */
const TEST_INBOX_TIMEOUT = 5n;
const TEST_ESCAPE_GRACE = 3n;

/**
 * The seeds every Ed25519-authorized fixture is built around.
 *
 * The fixtures carry the public keys; these are the secrets behind them. The Rust crate has no
 * Ed25519 implementation, so it writes the public keys out by hand -- if either side ever changed
 * one, nothing but the assertion in the forced-exit suite would notice.
 */
const EXIT_SEEDS = [
  "payment-rollup exit key one!!!!!",
  "payment-rollup exit key two!!!!!",
];

const keyPair = (index: number) =>
  nacl.sign.keyPair.fromSeed(new TextEncoder().encode(EXIT_SEEDS[index]));

/** The keypair behind a rollup address, or undefined if none of the fixture keys derive it. */
const keyPairFor = (addressHex: string) => {
  for (let index = 0; index < EXIT_SEEDS.length; index++) {
    const pair = keyPair(index);
    if (
      Buffer.from(l2Address("edd", pair.publicKey)).toString("hex") ===
      addressHex
    ) {
      return pair;
    }
  }

  return undefined;
};

describe("rollup verifier", () => {
  let algorand: AlgorandClient;
  let sender: algosdk.AddressWithTransactionSigner;

  beforeAll(async () => {
    algorand = AlgorandClient.defaultLocalNet();
    const acct = await algorand.account.localNetDispenser();
    sender = { address: acct.addr, txnSigner: acct.signer };
  });

  const scenario = (name: string): Scenario =>
    fixture.scenarios.find((s) => s.name === name)!;

  /** Notes have to differ or two identical self-payments collide on transaction id. */
  let filler = 0;

  /**
   * Seal `count` blocks.
   *
   * LocalNet runs in dev mode, where every transaction produces a block, so the cheapest way to
   * move the round forward is to send something and throw it away.
   */
  const advanceRounds = async (count: number) => {
    for (let i = 0; i < count; i++) {
      await algorand.send.payment({
        sender: sender.address,
        signer: sender.txnSigner,
        receiver: sender.address,
        amount: microAlgo(0),
        note: `advance ${filler++}`,
      });
    }
  };

  const balanceOf = async (address: algosdk.Address | string) =>
    (await algorand.account.getInformation(address)).balance.microAlgo;

  const fundedOutsider = async () => {
    const account = algorand.account.random();
    await algorand.send.payment({
      sender: sender.address,
      signer: sender.txnSigner,
      receiver: account.addr,
      amount: microAlgo(5_000_000),
    });
    return { address: account.addr, txnSigner: account.signer };
  };

  const bindScenarioToDomain = (s: Scenario, domain: Uint8Array): Scenario => {
    const batch = hex(s.batch);
    let batchCommitment = sha256(
      tag("BATCH"),
      domain,
      bytes(BigInt(batch.length)),
    );
    for (let offset = 0; offset < batch.length; offset += CHUNK_SIZE) {
      const chunk = batch.subarray(offset, offset + CHUNK_SIZE);
      batchCommitment = sha256(tag("CHUNK"), batchCommitment, sha256(chunk));
    }

    // The payout chain, built back to front from the terminal, which is how the contract can check
    // a payout before making it: each link carries the tail it folds onto. Mirrors
    // `withdrawal_links` and `withdrawal_chain`.
    let chain = withdrawalTerminal(domain);
    const withdrawals = [];
    for (const withdrawal of [...s.withdrawals].reverse()) {
      withdrawals.unshift({ ...withdrawal, tail: chain.toString("hex") });
      chain = accumulateWithdrawal(
        chain,
        hex(withdrawal.recipient),
        BigInt(withdrawal.amount),
      );
    }

    const publicValues = Buffer.from(hex(s.publicValues));
    batchCommitment.copy(publicValues, 64);
    chain.copy(publicValues, 160);

    return {
      ...s,
      deploymentDomain: Buffer.from(domain).toString("hex"),
      batchCommitment: batchCommitment.toString("hex"),
      withdrawalChain: chain.toString("hex"),
      withdrawals,
      publicValues: publicValues.toString("hex"),
    };
  };

  /** Rebind the fixture-generator deployment to the fresh application deployed by a test. */
  const bindScenario = async (
    client: RollupVerifier,
    s: Scenario,
  ): Promise<Scenario> =>
    bindScenarioToDomain(s, await client.deploymentDomain());

  /** Replay the fixture's authoritative cross-kind L1 order before settlement. */
  const replayL1 = async (client: RollupVerifier, s: Scenario) => {
    for (const [expectedIndex, item] of s.inbox.entries()) {
      let index: bigint;
      if (item.kind === "deposit") {
        index = await client.deposit(
          sender,
          hex(item.recipient),
          BigInt(item.amount),
        );
      } else {
        const pair = keyPairFor(item.address)!;
        const returnedIndex = await client.requestWithdrawal(
          sender,
          hex(item.address),
          pair.publicKey,
          algosdk.encodeAddress(hex(item.recipient)),
          pair.secretKey,
        );
        index = returnedIndex ?? (await client.inboxCursor()) - 1n;
      }
      expect(index).toBe(BigInt(expectedIndex));
    }
  };

  /** Settle a scenario. Needs no funding transaction, whatever the batch withdraws. */
  const settle = async (client: RollupVerifier, s: Scenario) => {
    const bound = await bindScenario(client, s);
    await client.verifyBatch(sender, hex(bound.batch), hex(bound.publicValues));
    return bound;
  };

  /**
   * Walk a settled batch's payout chain to its terminal.
   *
   * Order is not a convention here: the contract holds the head, so only the next payout is
   * acceptable at any point.
   */
  const drainAll = async (client: RollupVerifier, s: Scenario) => {
    for (const w of s.withdrawals) {
      await client.payWithdrawal(
        sender,
        algosdk.encodeAddress(hex(w.recipient)),
        BigInt(w.amount),
        hex(w.tail),
      );
    }
  };

  /** Replay only a scenario's deposits for tests that deliberately omit its requests. */
  const replayDeposits = async (client: RollupVerifier, s: Scenario) => {
    for (const deposit of s.deposits) {
      await client.deposit(
        sender,
        hex(deposit.recipient),
        BigInt(deposit.amount),
      );
    }
  };

  // The constants the contract, the guest and the driver each hold a copy of, with nothing but
  // these assertions linking the three.
  it("agrees with the guest about the chunk size", () => {
    expect(CHUNK_SIZE).toBe(fixture.chunkSize);
  });

  it("agrees with the guest about the withdrawal minimum", () => {
    expect(MIN_WITHDRAWAL).toBe(BigInt(fixture.minWithdrawal));
  });

  it("derives the same deployment domain as the Rust core", () => {
    expect(
      Buffer.from(deploymentDomain(new Uint8Array(32), 7n)).toString("hex"),
    ).toBe("459115f1be8e477f1e200d702ac5f9c5643ff430c310d3ff44b06273cb5daa15");

    const domain = new Uint8Array(32).fill(0x42);
    const senderAddress = new Uint8Array(32).fill(1);
    const destination = new Uint8Array(32).fill(2);
    const message = paymentMessage(domain, senderAddress, 3n, destination, 4n);
    expect(Buffer.from(message.subarray(0, 3)).toString()).toBe("PAY");
    expect(message.subarray(3, 35)).toEqual(domain);
    expect(message.subarray(35, 67)).toEqual(senderAddress);
    expect(Buffer.from(message.subarray(67, 75))).toEqual(bytes(3n));
    expect(message.subarray(75, 107)).toEqual(destination);
    expect(Buffer.from(message.subarray(107))).toEqual(bytes(4n));
    expect(message).not.toEqual(
      withdrawalMessage(
        domain,
        senderAddress,
        3n,
        algosdk.decodeAddress(algosdk.encodeAddress(destination)),
        4n,
      ),
    );
    expect(
      paymentMessage(domain, senderAddress, 3n, destination, 4n),
    ).not.toEqual(
      paymentMessage(
        new Uint8Array(32).fill(0x43),
        senderAddress,
        3n,
        destination,
        4n,
      ),
    );
  });

  it("commits approval-program pages for a scheduled application update", () => {
    expect(
      Buffer.from(
        approvalProgramCommitment([
          new Uint8Array([1, 2]),
          new Uint8Array([3]),
        ]),
      ).toString("hex"),
    ).toBe("c1119571f59c979ab344dcc7efab03b4267cd13f36619ef4a795e930650bf82a");
  });

  it("reproduces the Rust fixture commitments and withdrawal chains", () => {
    const domain = deploymentDomain(
      hex(fixture.genesisHash),
      BigInt(fixture.appId),
    );
    expect(Buffer.from(domain).toString("hex")).toBe(fixture.deploymentDomain);

    for (const s of fixture.scenarios) {
      expect(bindScenarioToDomain(s, domain)).toEqual(s);
    }
  });

  for (const proofScenario of PROOFS) {
    it(`settles the ${proofScenario.scenario.name} batch with its Groth16 proof`, async () => {
      const client = await RollupVerifier.create(algorand, sender, {
        groth16VerificationKey: hex(proofScenario.groth16VerificationKey),
        programVkeyHash: decodeSp1VkeyHash(proofScenario.vkey),
        securityCouncil: sender.address,
        recursionVkeyRoot: hex(proofScenario.recursionVkeyRoot),
        testDeployment: true,
      });
      const proof = {
        encodedProof: hex(proofScenario.scenario.groth16.encodedProof),
        publicInputs: proofScenario.scenario.groth16.publicInputs as [
          string,
          string,
          string,
          string,
          string,
        ],
      };

      for (const deposit of proofScenario.scenario.deposits) {
        await client.deposit(
          sender,
          hex(deposit.recipient),
          BigInt(deposit.amount),
        );
      }

      const preBalance = (
        await algorand.client.algod.accountInformation(sender.address).do()
      ).amount;
      await client.verifyBatch(
        sender,
        hex(proofScenario.scenario.batch),
        hex(proofScenario.scenario.publicValues),
        { proof },
      );

      const postBalance = (
        await algorand.client.algod.accountInformation(sender.address).do()
      ).amount;

      expect(preBalance - postBalance).toMatchSnapshot("verifyBatch cost");
      const txnCount = BigInt(proofScenario.scenario.name.split("-")[1]!);
      expect((preBalance - postBalance) / txnCount).toMatchSnapshot(
        "verifyBatch cost per txn",
      );

      const state = await client.appClient.state.global.getAll();
      expect(Buffer.from(state.stateRoot!.asByteArray()!).toString("hex")).toBe(
        proofScenario.scenario.newRoot,
      );
      expect(state.settledInboxCursor).toBe(
        BigInt(proofScenario.scenario.inbox.length),
      );
    }, 120_000);
  }

  for (const s of fixture.scenarios) {
    it(`should verify with scenario ${s.name}`, async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);

      await replayL1(client, s);

      await settle(client, s);

      const state = await client.appClient.state.global.getAll();
      expect(Buffer.from(state.stateRoot!.asByteArray()!).toString("hex")).toBe(
        s.newRoot,
      );
      expect(
        Buffer.from(state.settledInboxChain!.asByteArray()!).toString("hex"),
      ).toBe(s.inboxChainTo);
      expect(state.settledInboxCursor).toBe(BigInt(s.inbox.length));
    });
  }

  it("replays the Rust inbox-ordering scenario in cross-kind L1 order", () => {
    const s = scenario("inbox-ordering");
    expect(s.inbox.map((item) => item.kind)).toEqual([
      "deposit",
      "forcedWithdrawal",
      "deposit",
    ]);
  });

  describe("batch posting", () => {
    it("rejects a settlement committed for another application", async () => {
      const first = await RollupVerifier.createForTesting(algorand, sender);
      const second = await RollupVerifier.createForTesting(algorand, sender);
      const fixtureScenario = scenario("genesis-empty-batch");
      const firstBound = await bindScenario(first, fixtureScenario);
      const secondBound = await bindScenario(second, fixtureScenario);

      expect(firstBound.deploymentDomain).not.toBe(
        secondBound.deploymentDomain,
      );
      await expect(
        second.verifyBatch(
          sender,
          hex(firstBound.batch),
          hex(firstBound.publicValues),
        ),
      ).rejects.toThrow();
      expect(secondBound.batchCommitment).not.toBe(firstBound.batchCommitment);
    });

    // The test verifier deliberately trusts the creator and recomputes the public-values signal.
    // This exercises the payout-chain state machine without requiring a paid proof per test; the
    // production LogicSig would reject these altered values because its proof would no longer match.
    it("the mock verifier can install a withdrawal chain and is then stuck with it", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const empty = await bindScenario(client, scenario("genesis-empty-batch"));
      const publicValues = hex(empty.publicValues);
      publicValues.fill(1, 160, 192);

      await client.verifyBatch(sender, hex(empty.batch), publicValues);
      expect(await client.pendingWithdrawals()).toEqual(
        new Uint8Array(Buffer.alloc(32, 1)),
      );

      // No link folds to `0x01…01`, so the chain cannot be drained and no further batch can open.
      await expect(
        client.payWithdrawal(
          sender,
          sender.address.toString(),
          100_000n,
          Buffer.alloc(32),
        ),
      ).rejects.toThrow();
      await expect(settle(client, scenario("deposits-only"))).rejects.toThrow();
    });

    it("rejects public values that do not match the proof signal", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = await bindScenario(client, scenario("genesis-empty-batch"));

      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: { batchLength: s.batchLength, targetInboxCursor: 0n },
      });
      await client.appClient.send.accumulateChunk({
        sender: sender.address,
        signer: sender.txnSigner,
        args: { chunk: hex(s.chunks[0]) },
      });

      const verifier = await algorand.createTransaction.payment({
        sender: sender.address,
        signer: sender.txnSigner,
        receiver: client.appClient.appAddress,
        amount: microAlgo(0),
        staticFee: microAlgo(0),
      });
      await expect(
        client.appClient.send.verifyBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: {
            verifier,
            signals: [0n, 0n, 0n, 0n, 0n],
            proof: {
              piA: new Uint8Array(64),
              piB: new Uint8Array(128),
              piC: new Uint8Array(64),
            },
            publicValues: hex(s.publicValues),
          },
          extraFee: microAlgo(1_000),
        }),
      ).rejects.toThrow();
    });

    it("restricts open, chunk, verify, and abandon to the creator", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const outsider = await fundedOutsider();
      const s = await bindScenario(client, scenario("deposits-only"));
      await replayDeposits(client, s);
      const open = {
        args: {
          batchLength: s.batchLength,
          targetInboxCursor: await client.inboxCursor(),
        },
        boxReferences: [queueBox(2n)],
      };

      await expect(
        client.appClient.send.openBatch({
          sender: outsider.address,
          signer: outsider.txnSigner,
          ...open,
        }),
      ).rejects.toThrow();
      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        ...open,
      });
      await expect(
        client.appClient.send.accumulateChunk({
          sender: outsider.address,
          signer: outsider.txnSigner,
          args: { chunk: hex(s.chunks[0]) },
        }),
      ).rejects.toThrow();
      for (const chunk of s.chunks) {
        await client.appClient.send.accumulateChunk({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { chunk: hex(chunk) },
          extraFee: microAlgo(531),
        });
      }
      await expect(
        client.settlePostedBatch(outsider, hex(s.publicValues)),
      ).rejects.toThrow();
      await expect(client.abandonBatch(outsider)).rejects.toThrow();
      await client.abandonBatch(sender);
    });

    it("rejects an extra empty chunk after the declared batch is complete", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = await bindScenario(client, scenario("multi-chunk"));
      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: {
          batchLength: s.batchLength,
          targetInboxCursor: 0n,
        },
      });
      for (const chunk of s.chunks) {
        await client.appClient.send.accumulateChunk({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { chunk: hex(chunk) },
          extraFee: microAlgo(531),
        });
      }

      await expect(
        client.appClient.send.accumulateChunk({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { chunk: new Uint8Array() },
          extraFee: microAlgo(531),
        }),
      ).rejects.toThrow();
    });

    it("chains a second settlement from the first settled root and inbox", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const firstFixture = scenario("deposits-only");
      await replayDeposits(client, firstFixture);
      const first = await settle(client, firstFixture);

      const second = await bindScenario(
        client,
        scenario("genesis-empty-batch"),
      );
      const publicValues = hex(second.publicValues);
      hex(first.newRoot).copy(publicValues, 0);
      hex(first.newRoot).copy(publicValues, 32);
      hex(first.inboxChainTo).copy(publicValues, 96);
      hex(first.inboxChainTo).copy(publicValues, 128);

      await client.verifyBatch(sender, hex(second.batch), publicValues);

      const state = await client.appClient.state.global.getAll();
      expect(Buffer.from(state.stateRoot!.asByteArray()!).toString("hex")).toBe(
        first.newRoot,
      );
      // Neither batch withdrew anything, so neither left a payout chain to hold the other up.
      expect(await client.pendingWithdrawals()).toBeUndefined();
    });
  });

  describe("inbox deposit inclusion", () => {
    // Every case below settles a batch whose deposits do not match what L1 saw. The chain is what
    // catches each one, and it catches all of them the same way: the fold lands somewhere the
    // contract is not holding.
    const depositsOnly = () => scenario("deposits-only");

    const settleExpectingFailure = async (
      client: RollupVerifier,
      s: Scenario,
    ) => {
      const bound = await bindScenario(client, s);
      await expect(
        client.verifyBatch(sender, hex(bound.batch), hex(bound.publicValues)),
      ).rejects.toThrow();
    };

    it("rejects a batch that credits a deposit L1 never accepted", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = depositsOnly();

      // Only the first two of the three the batch claims.
      for (const deposit of s.deposits.slice(0, 2)) {
        await client.deposit(
          sender,
          hex(deposit.recipient),
          BigInt(deposit.amount),
        );
      }

      await settleExpectingFailure(client, s);
    });

    it("rejects a batch that omits a pending deposit", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = depositsOnly();

      await replayDeposits(client, s);
      // One more than the batch credits, so the sealed chain runs past where the batch lands.
      await client.deposit(sender, hex(s.deposits[0].recipient), 1_000n);

      await settleExpectingFailure(client, s);
    });

    it("rejects a batch whose deposits arrived in a different order", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = depositsOnly();

      // The same three deposits, the same amounts, the wrong order. A set commitment would not
      // notice; a chain does.
      for (const deposit of [...s.deposits].reverse()) {
        await client.deposit(
          sender,
          hex(deposit.recipient),
          BigInt(deposit.amount),
        );
      }

      await settleExpectingFailure(client, s);
    });

    it("rejects a batch that alters a deposit's amount", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = depositsOnly();

      for (const [index, deposit] of s.deposits.entries()) {
        await client.deposit(
          sender,
          hex(deposit.recipient),
          BigInt(deposit.amount) + (index === 1 ? 1n : 0n),
        );
      }

      await settleExpectingFailure(client, s);
    });

    // The empty-batch case needs no special handling: a batch with no deposits commits
    // `new == old`, which cannot equal a sealed chain that a pending deposit has moved.
    it("rejects an empty batch while a deposit is pending", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);

      await client.deposit(
        sender,
        hex(depositsOnly().deposits[0].recipient),
        1_000n,
      );

      await settleExpectingFailure(client, scenario("genesis-empty-batch"));
    });

    // Deposits are accepted throughout a batch's posting; they simply belong to the next one. This
    // is what the copy-don't-reset seal buys, and it has to keep working.
    it("accepts a deposit that lands while a batch is being posted", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = await bindScenario(client, depositsOnly());

      await replayDeposits(client, s);

      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: {
          batchLength: s.batchLength,
          targetInboxCursor: await client.inboxCursor(),
        },
        boxReferences: [queueBox(2n)],
      });

      // Mid-batch, after the seal.
      await client.deposit(sender, hex(s.deposits[0].recipient), 4_000n);

      for (const chunk of s.chunks) {
        await client.appClient.send.accumulateChunk({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { chunk: hex(chunk) },
        });
      }

      await client.settlePostedBatch(sender, hex(s.publicValues));

      // The batch settled against the sealed chain, and the late deposit is still pending.
      const state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(3n);
      expect(state.inboxCursor).toBe(4n);
    });

    it("allows a batch to stop before a later pending deposit", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = await bindScenario(client, depositsOnly());

      await replayDeposits(client, s);
      const stale = await client.inboxCursor();
      await client.deposit(sender, hex(s.deposits[0].recipient), 1_000n);

      await client.verifyBatch(sender, hex(s.batch), hex(s.publicValues), {
        inboxCursor: stale,
      });

      const state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(3n);
      expect(state.inboxCursor).toBe(4n);
    });
  });

  describe("box lifecycle", () => {
    it("charges the depositor the box minimum balance and refunds it on prune", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = scenario("deposits-only");
      const app = client.appClient.appAddress;

      const before = (await algorand.account.getInformation(app)).balance
        .microAlgo;

      await replayDeposits(client, s);

      const credited = s.deposits.reduce(
        (total, d) => total + BigInt(d.amount),
        0n,
      );
      const funded = (await algorand.account.getInformation(app)).balance
        .microAlgo;

      // Each deposit brought its own box's minimum balance on top of what it credits, so the app
      // is never out of pocket for holding the queue.
      expect(funded - before).toBe(
        credited + INBOX_BOX_MBR * BigInt(s.deposits.length),
      );

      await settle(client, s);

      await expect(client.pruneRequest(sender, 0n)).rejects.toThrow();
      await client.pruneDeposit(sender, 0n);

      const pruned = (await algorand.account.getInformation(app)).balance
        .microAlgo;
      expect(funded - pruned).toBe(INBOX_BOX_MBR);
    });

    it("refuses to prune a deposit that has not settled", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);

      await client.deposit(
        sender,
        hex(scenario("deposits-only").deposits[0].recipient),
        1_000n,
      );

      await expect(client.pruneDeposit(sender, 0n)).rejects.toThrow();
    });
  });

  describe("withdrawals", () => {
    const withdrawing = () => scenario("withdrawals");

    /** Deploy, replay the inbox, and settle, leaving the payout chain outstanding. */
    const settled = async (s: Scenario) => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      await replayL1(client, s);
      const bound = await settle(client, s);

      return { client, s: bound };
    };

    it("pays every withdrawal out to the account the batch named", async () => {
      const { client, s } = await settled(withdrawing());

      const before = await Promise.all(
        s.withdrawals.map((w) =>
          balanceOf(algosdk.encodeAddress(hex(w.recipient))),
        ),
      );

      await drainAll(client, s);

      for (const [index, w] of s.withdrawals.entries()) {
        const after = await balanceOf(algosdk.encodeAddress(hex(w.recipient)));
        expect(after - before[index]).toBe(BigInt(w.amount));
      }

      // Reaching the terminal clears the chain, so the rollup owes nothing.
      expect(await client.pendingWithdrawals()).toBeUndefined();
    });

    // The chain is the order. This is what replaces the claim bitmap: there is no bit to check
    // because there is only ever one payout the contract will accept.
    it("refuses a payout out of chain order", async () => {
      const { client, s } = await settled(withdrawing());
      const second = s.withdrawals[1];

      await expect(
        client.payWithdrawal(
          sender,
          algosdk.encodeAddress(hex(second.recipient)),
          BigInt(second.amount),
          hex(second.tail),
        ),
      ).rejects.toThrow();

      // The head has not moved, so the first payout still goes through.
      const first = s.withdrawals[0];
      await client.payWithdrawal(
        sender,
        algosdk.encodeAddress(hex(first.recipient)),
        BigInt(first.amount),
        hex(first.tail),
      );
    });

    it("refuses an altered recipient, amount, or tail", async () => {
      const { client, s } = await settled(withdrawing());
      const w = s.withdrawals[0];
      const pay = (
        recipient = algosdk.encodeAddress(hex(w.recipient)),
        amount = BigInt(w.amount),
        tail = hex(w.tail),
      ) => client.payWithdrawal(sender, recipient, amount, tail);

      await expect(pay(sender.address.toString())).rejects.toThrow();
      await expect(pay(undefined, BigInt(w.amount) + 1n)).rejects.toThrow();
      const tail = Buffer.from(hex(w.tail));
      tail[0] ^= 1;
      await expect(pay(undefined, undefined, tail)).rejects.toThrow();

      // None of them moved the head, so the genuine payout is still the next one.
      await pay();
    });

    // Position in the chain is the nullifier: once the head has stepped past a payout, the same
    // arguments can never reproduce a head again.
    it("refuses a replayed payout", async () => {
      const { client, s } = await settled(withdrawing());
      const w = s.withdrawals[0];
      const pay = () =>
        client.payWithdrawal(
          sender,
          algosdk.encodeAddress(hex(w.recipient)),
          BigInt(w.amount),
          hex(w.tail),
        );

      await pay();
      await expect(pay()).rejects.toThrow();
    });

    // Two identical payouts are two distinct positions in the chain, differing only in their tails,
    // and each is made exactly once.
    it("pays identical withdrawals at distinct chain positions", async () => {
      const { client, s } = await settled(scenario("duplicate-withdrawals"));
      const recipient = algosdk.encodeAddress(hex(s.withdrawals[0].recipient));
      const before = await balanceOf(recipient);

      expect(s.withdrawals[0].recipient).toBe(s.withdrawals[1].recipient);
      expect(s.withdrawals[0].amount).toBe(s.withdrawals[1].amount);
      expect(s.withdrawals[0].tail).not.toBe(s.withdrawals[1].tail);

      await drainAll(client, s);

      expect((await balanceOf(recipient)) - before).toBe(
        BigInt(s.withdrawals[0].amount) * 2n,
      );
    });

    // The rule the whole redesign exists for: the sequencer cannot move on while it still owes
    // withdrawals.
    it("refuses to open the next batch until the chain has drained", async () => {
      const { client, s } = await settled(withdrawing());

      expect(await client.pendingWithdrawals()).toBeDefined();
      await expect(settle(client, scenario("deposits-only"))).rejects.toThrow();

      // Halfway is still not drained.
      const [first, ...rest] = s.withdrawals;
      await client.payWithdrawal(
        sender,
        algosdk.encodeAddress(hex(first.recipient)),
        BigInt(first.amount),
        hex(first.tail),
      );
      expect(await client.pendingWithdrawals()).toBeDefined();
      await expect(settle(client, scenario("deposits-only"))).rejects.toThrow();

      await drainAll(client, { ...s, withdrawals: rest });
      expect(await client.pendingWithdrawals()).toBeUndefined();
    });

    // Draining costs the app exactly the payouts and nothing else -- no box minimum balance is
    // advanced at settlement and none is returned at the end, because there is no box.
    it("pays out exactly the withdrawals, with no box minimum balance either way", async () => {
      const s = withdrawing();
      const client = await RollupVerifier.createForTesting(algorand, sender);
      await replayDeposits(client, s);

      const app = client.appClient.appAddress;
      const beforeSettle = await balanceOf(app);
      const bound = await settle(client, s);
      expect(await balanceOf(app)).toBe(beforeSettle);

      await drainAll(client, bound);

      const paid = s.withdrawals.reduce((t, w) => t + BigInt(w.amount), 0n);
      expect(beforeSettle - (await balanceOf(app))).toBe(paid);

      // And no box was ever created for the chain.
      const names = await client.appClient.appClient.getBoxNames();
      expect(
        names.filter((n) => n.nameRaw[0] === "w".charCodeAt(0)),
      ).toHaveLength(0);
    });

    // A batch that withdraws nothing commits the terminal itself, so it writes no chain and the
    // rollup is free to continue immediately -- that is what keeps the common settlement free of the
    // whole mechanism.
    it("leaves no chain for a batch that withdraws nothing", async () => {
      const s = scenario("deposits-only");
      const client = await RollupVerifier.createForTesting(algorand, sender);

      await replayDeposits(client, s);
      await settle(client, s);

      expect(await client.pendingWithdrawals()).toBeUndefined();
      await expect(
        client.payWithdrawal(
          sender,
          sender.address.toString(),
          100_000n,
          Buffer.alloc(32),
        ),
      ).rejects.toThrow();

      // The inbox boxes are asserted alongside so this cannot pass by seeing no boxes at all.
      const names = await client.appClient.appClient.getBoxNames();
      expect(
        names.filter((n) => n.nameRaw[0] === "i".charCodeAt(0)),
      ).toHaveLength(s.inbox.length);
      expect(
        names.filter((n) => n.nameRaw[0] === "w".charCodeAt(0)),
      ).toHaveLength(0);
    });

    // Value that already left L2 in a settled batch is not the rollup's to withhold, whatever
    // happens to the rollup afterwards. Being permissionless, the drain needs nobody's cooperation
    // either -- which is what stops an outstanding chain from becoming a hostage.
    it("still pays out after the rollup has escaped", async () => {
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );

      const fixtureScenario = withdrawing();
      await replayDeposits(client, fixtureScenario);
      const s = await settle(client, fixtureScenario);

      // Strand a fresh deposit and pull the hatch, with the chain still outstanding.
      await client.deposit(sender, hex(s.deposits[0].recipient), 1_000n);
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      expect(await client.pendingWithdrawals()).toBeDefined();

      const outsider = await fundedOutsider();
      const before = await Promise.all(
        s.withdrawals.map((w) =>
          balanceOf(algosdk.encodeAddress(hex(w.recipient))),
        ),
      );

      for (const w of s.withdrawals) {
        await client.payWithdrawal(
          outsider,
          algosdk.encodeAddress(hex(w.recipient)),
          BigInt(w.amount),
          hex(w.tail),
        );
      }

      for (const [index, w] of s.withdrawals.entries()) {
        expect(
          (await balanceOf(algosdk.encodeAddress(hex(w.recipient)))) -
            before[index],
        ).toBe(BigInt(w.amount));
      }
      expect(await client.pendingWithdrawals()).toBeUndefined();
    });

    // The round-trip scenario withdraws from an account that held nothing when the block opened.
    it("settles a batch that deposits, pays and withdraws at once", async () => {
      const { client, s } = await settled(scenario("round-trip"));

      await drainAll(client, s);

      const state = await client.appClient.state.global.getAll();
      expect(Buffer.from(state.stateRoot!.asByteArray()!).toString("hex")).toBe(
        s.newRoot,
      );
    });
  });

  describe("escape hatch", () => {
    const recipient = () =>
      hex(scenario("deposits-only").deposits[0].recipient);

    /** A rollup whose escape parameters are small enough to actually cross. */
    const escapable = () =>
      RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );

    it("lets the configured security council trigger the terminal escape immediately", async () => {
      const council = await fundedOutsider();
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
        council.address,
      );

      await expect(client.securityCouncilEscape(sender)).rejects.toThrow();
      await client.securityCouncilEscape(council);

      expect((await client.appClient.state.global.getAll()).escaped).toBe(1n);
      await expect(
        client.deposit(sender, recipient(), 1_000n),
      ).rejects.toThrow();
    });

    it("delays a security-council verifier rotation", async () => {
      const council = await fundedOutsider();
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
        council.address,
        3n,
      );
      const programVkeyHash = new Uint8Array(32).fill(1);
      const recursionVkeyRoot = new Uint8Array(32).fill(2);

      await client.scheduleVerifierUpdate(
        council,
        sender.address,
        programVkeyHash,
        recursionVkeyRoot,
      );

      await expect(client.executeVerifierUpdate(council)).rejects.toThrow();
      await advanceRounds(3);
      await client.executeVerifierUpdate(council);

      const state = await client.appClient.state.global.getAll();
      expect(state.verifierAddress).toBe(sender.address.toString());
      expect(state.programVkeyHash?.asByteArray()).toEqual(programVkeyHash);
      expect(state.recursionVkeyRoot?.asByteArray()).toEqual(recursionVkeyRoot);
    });

    it("only updates to the approval program scheduled after the delay", async () => {
      const council = await fundedOutsider();
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
        council.address,
        3n,
      );
      const program = await algorand.app.getById(client.appClient.appId);
      const approvalPages = [program.approvalProgram];
      const updateSelector = createHash("sha512-256")
        .update("updateApplication()void")
        .digest()
        .subarray(0, 4);
      const update = () =>
        algorand.send.appUpdate({
          sender: council.address,
          signer: council.txnSigner,
          appId: client.appClient.appId,
          approvalProgram: program.approvalProgram,
          clearStateProgram: program.clearStateProgram,
          args: [updateSelector],
        });

      await expect(update()).rejects.toThrow();

      await client.scheduleApplicationUpdate(council, new Uint8Array(32));
      await advanceRounds(3);
      await expect(update()).rejects.toThrow();

      await client.scheduleApplicationUpdate(
        council,
        approvalProgramCommitment(approvalPages),
      );
      await advanceRounds(3);
      await update();
    });

    /** Deposit, let it go stale, and signal. Leaves the contract one grace period from escape. */
    const signalOverStaleDeposit = async (client: RollupVerifier) => {
      await client.deposit(sender, recipient(), 1_000n);
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
    };

    /** Everything above: deposit, stale, signal, wait out the grace, pull the hatch. */
    const escape = async (client: RollupVerifier) => {
      await signalOverStaleDeposit(client);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);
    };

    it("refuses to signal while the oldest deposit is still fresh", async () => {
      const client = await escapable();

      await client.deposit(sender, recipient(), 1_000n);

      await expect(client.signalEscape(sender)).rejects.toThrow();
    });

    it("refuses to signal with nothing pending", async () => {
      const client = await escapable();

      // The queue is empty, so there is no deposit to point at and no censorship to allege.
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);

      await expect(client.signalEscape(sender)).rejects.toThrow();
    });

    it("signals once the oldest deposit has aged out, and only once", async () => {
      const client = await escapable();

      await signalOverStaleDeposit(client);

      const state = await client.appClient.state.global.getAll();
      expect(state.escapeDeadline).toBeGreaterThan(0n);
      expect(state.escaped).toBe(0n);

      await expect(client.signalEscape(sender)).rejects.toThrow();
    });

    // The answer to the accusation is to settle a batch. Doing so has to withdraw it, or an
    // operator that recovered would still be dragged through the hatch.
    it("withdraws the accusation when a batch settles", async () => {
      const client = await escapable();
      const s = scenario("deposits-only");

      await replayDeposits(client, s);
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);

      await settle(client, s);

      const state = await client.appClient.state.global.getAll();
      expect(state.escapeDeadline).toBeUndefined();
      expect(state.escapeInboxTarget).toBeUndefined();
      await expect(client.executeEscape(sender)).rejects.toThrow();
    });

    it("does not clear an inbox target created after an old batch opened", async () => {
      const client = await escapable();
      const s = await bindScenario(client, scenario("deposits-only"));
      await replayDeposits(client, s);
      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: {
          batchLength: s.batchLength,
          targetInboxCursor: await client.inboxCursor(),
        },
        boxReferences: [queueBox(2n)],
      });
      await client.deposit(sender, recipient(), 1_000n);
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      const initialDeadline = (await client.appClient.state.global.getAll())
        .escapeDeadline;
      for (const chunk of s.chunks) {
        await client.appClient.send.accumulateChunk({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { chunk: hex(chunk) },
        });
      }
      await client.settlePostedBatch(sender, hex(s.publicValues));

      const state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(3n);
      expect(state.escapeInboxTarget).toBe(4n);
      expect(state.escapeDeadline).toBe(initialDeadline);
    });

    it("refuses to execute before the grace period has run out", async () => {
      const client = await escapable();

      await signalOverStaleDeposit(client);

      await expect(client.executeEscape(sender)).rejects.toThrow();
    });

    it("refuses settlement after the escape deadline has expired", async () => {
      const client = await escapable();
      const s = scenario("deposits-only");

      await replayDeposits(client, s);
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);

      await expect(settle(client, s)).rejects.toThrow();
      await client.executeEscape(sender);
      expect((await client.appClient.state.global.getAll()).escaped).toBe(1n);
    });

    it("refuses to execute with nothing signalled", async () => {
      const client = await escapable();

      await expect(client.executeEscape(sender)).rejects.toThrow();
    });

    it("executes once the grace period has run out", async () => {
      const client = await escapable();

      await escape(client);

      const state = await client.appClient.state.global.getAll();
      expect(state.escaped).toBe(1n);
      expect(state.escapeDeadline).toBeUndefined();

      // One-way: there is no second pull and nothing that clears the flag.
      await expect(client.executeEscape(sender)).rejects.toThrow();
    });

    // The premise is that the sequencer is gone, so the hatch cannot depend on the creator-only
    // `abandonBatch` to clear a batch left half-posted.
    it("discards a half-posted batch on the way out", async () => {
      const client = await escapable();
      const s = scenario("deposits-only");

      await signalOverStaleDeposit(client);

      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: {
          batchLength: s.batchLength,
          targetInboxCursor: await client.inboxCursor(),
        },
        boxReferences: [queueBox(0n)],
      });

      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      // A deleted byte-typed global comes back as an empty wrapper rather than as `undefined`,
      // hence the unwrap; the integer ones are absent outright.
      const state = await client.appClient.state.global.getAll();
      expect(state.batchLength).toBeUndefined();
      expect(state.postedLength).toBeUndefined();
      expect(state.sealedInboxCursor).toBeUndefined();
      expect(state.chunkAccumulator?.asByteArray()).toBeUndefined();
      expect(state.sealedInboxChain?.asByteArray()).toBeUndefined();
    });

    it("freezes the rollup once the hatch is pulled", async () => {
      const client = await escapable();
      const s = scenario("deposits-only");

      await escape(client);

      await expect(
        client.deposit(sender, recipient(), 1_000n),
      ).rejects.toThrow();
      await expect(
        client.appClient.send.openBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: {
            batchLength: s.batchLength,
            targetInboxCursor: 1n,
          },
        }),
      ).rejects.toThrow();
      await expect(
        client.settlePostedBatch(
          sender,
          hex((await bindScenario(client, s)).publicValues),
        ),
      ).rejects.toThrow();
    });

    it("refunds a stranded deposit in full, to the payer and not the caller", async () => {
      const client = await escapable();
      const app = client.appClient.appAddress;

      // A depositor who then goes quiet, and a bystander who pulls them out.
      const depositor = algorand.account.random();
      await algorand.send.payment({
        sender: sender.address,
        signer: sender.txnSigner,
        receiver: depositor.addr,
        amount: microAlgo(1_000_000),
      });
      const payer = { address: depositor.addr, txnSigner: depositor.signer };

      await client.deposit(payer, recipient(), 500_000n);
      const stranded = await balanceOf(depositor.addr);
      const held = await balanceOf(app);

      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      // The bystander pays the fees; the money goes where the box says.
      await client.reclaimDeposit(sender, 0n);

      expect((await balanceOf(depositor.addr)) - stranded).toBe(
        500_000n + INBOX_BOX_MBR,
      );
      expect(held - (await balanceOf(app))).toBe(500_000n + INBOX_BOX_MBR);

      // The box is gone, so there is no second refund to collect.
      await expect(client.reclaimDeposit(sender, 0n)).rejects.toThrow();
    });

    it("refuses to reclaim before an escape", async () => {
      const client = await escapable();

      await client.deposit(sender, recipient(), 1_000n);

      await expect(client.reclaimDeposit(sender, 0n)).rejects.toThrow();
    });

    // `pruneDeposit` and `reclaimDeposit` partition the queue at `settledInboxCursor`, and the
    // partition is what makes a bare cursor comparison enough to decide who is owed what.
    it("splits the queue at the settled cursor", async () => {
      const client = await escapable();
      const s = scenario("deposits-only");

      await replayDeposits(client, s);
      await settle(client, s);

      // A fourth deposit, arriving after the only batch that will ever settle.
      await escape(client);

      // Settled: box minimum balance only, and never the deposit itself.
      await expect(client.reclaimDeposit(sender, 0n)).rejects.toThrow();
      await client.pruneDeposit(sender, 0n);

      // Stranded: the whole payment, and not through the prune path.
      await expect(client.pruneDeposit(sender, 3n)).rejects.toThrow();
      await client.reclaimDeposit(sender, 3n);

      // Past the end of the queue.
      await expect(client.reclaimDeposit(sender, 4n)).rejects.toThrow();
    });

    it("leaves the app holding nothing once every stranded deposit is reclaimed", async () => {
      const client = await escapable();
      const app = client.appClient.appAddress;

      const base = await balanceOf(app);

      const amounts = [1_000n, 250_000n, 7n];
      for (const amount of amounts) {
        await client.deposit(sender, recipient(), amount);
      }

      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      for (let nonce = 0n; nonce < BigInt(amounts.length); nonce++) {
        await client.reclaimDeposit(sender, nonce);
      }

      // Every deposit and every box minimum balance returned; the app is back to the bare account
      // minimum it was funded with at creation.
      expect(await balanceOf(app)).toBe(base);
    });
  });

  describe("withdrawal requests", () => {
    const forcing = () => scenario("forced-inclusion");

    /** The account the forced-inclusion scenario empties, and the key that can demand it. */
    const subject = () => {
      const request = forcing().requests[0];

      return { request, pair: keyPairFor(request.address)! };
    };

    it("forces a batch to answer the request", async () => {
      const s = forcing();
      const client = await RollupVerifier.createForTesting(algorand, sender);

      await replayL1(client, s);
      await settle(client, s);

      const state = await client.appClient.state.global.getAll();
      expect(
        Buffer.from(state.settledInboxChain!.asByteArray()!).toString("hex"),
      ).toBe(s.inboxChainTo);
      expect(state.settledInboxCursor).toBe(3n);
    });

    // The hole this whole mechanism exists to close. Before it, a sequencer could settle batches
    // forever while quietly dropping every withdrawal, and L1 had no way to tell.
    it("refuses to settle a batch that ignores a pending request", async () => {
      const s = scenario("forced-exit");
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const { request, pair } = subject();

      // The same two deposits the forced-exit batch credits, so that batch is otherwise settleable.
      await replayDeposits(client, s);

      // Then somebody demands their money.
      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      // The batch is valid, its deposits line up, and it still cannot settle -- it does not answer
      // the request, so its fold lands short of the chain the contract is holding.
      await expect(settle(client, s)).rejects.toThrow();
    });

    it("pays the whole balance out to the account the request named", async () => {
      const s = forcing();
      const client = await RollupVerifier.createForTesting(algorand, sender);

      await replayL1(client, s);
      const bound = await settle(client, s);

      const payout = bound.withdrawals[0];
      const recipient = algosdk.encodeAddress(hex(payout.recipient));
      const before = await balanceOf(recipient);

      await drainAll(client, bound);

      // The whole deposited balance, and no amount was ever named on L1 or on the wire.
      expect((await balanceOf(recipient)) - before).toBe(BigInt(payout.amount));
      expect(BigInt(payout.amount)).toBe(BigInt(s.deposits[0].amount));
    });

    // A request that is answered is spent: the account is empty, so demanding it again is legal
    // and simply pays nothing. What must not happen is the queue refusing to drain.
    it("lets an answered request be pruned and its minimum balance returned", async () => {
      const s = forcing();
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const app = client.appClient.appAddress;

      await replayL1(client, s);
      await settle(client, s);

      const before = await balanceOf(sender.address);
      await expect(client.pruneDeposit(sender, 2n)).rejects.toThrow();
      await client.pruneRequest(sender, 2n);

      // The request and deposits share indexes and box funding; only the request at index 2 is
      // removed here.
      expect(await balanceOf(sender.address)).toBeGreaterThan(
        before + INBOX_BOX_MBR - 3_000n,
      );
      const names = await client.appClient.appClient.getBoxNames();
      expect(
        names.filter((n) => n.nameRaw[0] === "i".charCodeAt(0)),
      ).toHaveLength(2);
      expect(app).toBeDefined();
    });

    it("refuses to prune a request that has not been answered", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const { request, pair } = subject();

      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      await expect(client.pruneRequest(sender, 0n)).rejects.toThrow();
    });

    // The request names an account, not a person, so authorization has to come from the key that
    // account derives from. Otherwise anyone could drain anyone to an address of their choosing.
    it("refuses a request signed by the wrong key", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const { request } = subject();

      await expect(
        client.requestWithdrawal(
          sender,
          hex(request.address),
          keyPair(0).publicKey,
          algosdk.encodeAddress(hex(request.recipient)),
          // Right public key, wrong secret.
          keyPair(1).secretKey,
        ),
      ).rejects.toThrow();
    });

    it("refuses a key that does not derive the account", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const { request } = subject();

      await expect(
        client.requestWithdrawal(
          sender,
          hex(request.address),
          keyPair(1).publicKey,
          algosdk.encodeAddress(hex(request.recipient)),
          keyPair(1).secretKey,
        ),
      ).rejects.toThrow();
    });

    // The nonce is inside the signed message, so a signature authorizes one request rather than an
    // unbounded stream of replays of it lifted off the chain.
    it("refuses a replayed signature", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const { request, pair } = subject();
      const recipient = algosdk.encodeAddress(hex(request.recipient));

      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        recipient,
        pair.secretKey,
      );

      // Nonce 0's signature presented against nonce 1.
      const stale = nacl.sign.detached(
        withdrawalRequestMessage(
          await client.deploymentDomain(),
          0n,
          hex(request.address),
          algosdk.decodeAddress(recipient),
        ),
        pair.secretKey,
      );
      const payment = await client.appClient.algorand.createTransaction.payment(
        {
          sender: sender.address,
          receiver: client.appClient.appAddress,
          amount: microAlgo(INBOX_BOX_MBR),
        },
      );
      const signerArgs = { sender: sender.address, signer: sender.txnSigner };

      await expect(
        client.appClient
          .newGroup()
          .opUp({ ...signerArgs, args: { nonce: 0n } })
          .opUp({ ...signerArgs, args: { nonce: 1n } })
          .opUp({ ...signerArgs, args: { nonce: 2n } })
          .requestWithdrawal({
            ...signerArgs,
            args: {
              payment,
              expectedNonce: 1n,
              address: hex(request.address),
              recipient,
              scheme: new TextEncoder().encode("edd"),
              pubKey: pair.publicKey,
              signature: stale,
            },
            boxReferences: [queueBox(1n)],
          })
          .send(),
      ).rejects.toThrow();
    });

    it("allows an open batch to stop before a later pending request", async () => {
      const s = scenario("forced-exit");
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const { request, pair } = subject();

      await replayDeposits(client, s);
      const stale = await client.inboxCursor();
      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      const bound = await bindScenario(client, s);
      await client.verifyBatch(
        sender,
        hex(bound.batch),
        hex(bound.publicValues),
        { inboxCursor: stale },
      );

      const state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(2n);
      expect(state.inboxCursor).toBe(3n);
    });

    const settleSyntheticPrefix = async (
      client: RollupVerifier,
      oldChain: Uint8Array,
      newChain: Uint8Array,
      inboxCursor: bigint,
      scenarioName:
        | "genesis-empty-batch"
        | "forced-exit"
        | "withdrawals" = "genesis-empty-batch",
    ) => {
      // Proof verification is still TODO, so these values intentionally isolate L1 FIFO watchdog
      // behavior without pretending the empty Rust batch produced the synthetic inbox transition.
      const s = await bindScenario(client, scenario(scenarioName));
      const publicValues = hex(s.publicValues);
      Buffer.from(oldChain).copy(publicValues, 96);
      Buffer.from(newChain).copy(publicValues, 128);
      await client.verifyBatch(sender, hex(s.batch), publicValues, {
        inboxCursor,
      });
      return s;
    };

    it("does not extend for a sub-256 mixed FIFO prefix and clears at its fixed target", async () => {
      const grace = 20n;
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        1n,
        grace,
      );
      const { request, pair } = subject();
      const depositRecipient = hex(
        scenario("deposits-only").deposits[0].recipient,
      );
      const requestRecipient = hex(request.recipient);

      expect(await client.deposit(sender, depositRecipient, 1n)).toBe(0n);
      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(requestRecipient),
        pair.secretKey,
      );
      expect(await client.inboxCursor()).toBe(2n);

      const firstChain = sha256(
        tag("INBOXD"),
        Buffer.alloc(32),
        depositRecipient,
        bytes(1n),
      );
      const targetChain = sha256(
        tag("INBOXW"),
        firstChain,
        hex(request.address),
        requestRecipient,
      );

      await advanceRounds(2);
      await client.signalEscape(sender);
      const initialDeadline = (await client.appClient.state.global.getAll())
        .escapeDeadline!;

      const first = await settleSyntheticPrefix(
        client,
        Buffer.alloc(32),
        firstChain,
        1n,
      );
      let state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(1n);
      expect(state.escapeInboxTarget).toBe(2n);
      expect(state.escapeDeadline).toBe(initialDeadline);

      await expect(
        client.appClient.send.openBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { batchLength: first.batchLength, targetInboxCursor: 0n },
        }),
      ).rejects.toThrow();

      await settleSyntheticPrefix(
        client,
        firstChain,
        targetChain,
        2n,
        "forced-exit",
      );
      state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(2n);
      expect(state.escapeInboxTarget).toBeUndefined();
      expect(state.escapeDeadline).toBeUndefined();
      expect(state.escapeProgress).toBeUndefined();
    });

    it("extends exactly once for the first 256 of 257 FIFO entries, then clears", async () => {
      const grace = 20n;
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        1n,
        grace,
      );
      const recipient = hex(scenario("deposits-only").deposits[0].recipient);
      let chain = Buffer.alloc(32);
      let firstTrancheChain = Buffer.alloc(32);

      for (let index = 0; index < 257; index++) {
        expect(await client.deposit(sender, recipient, 1n)).toBe(BigInt(index));
        chain = sha256(tag("INBOXD"), chain, recipient, bytes(1n));
        if (index === 255) firstTrancheChain = chain;
      }

      await client.signalEscape(sender);
      const initialDeadline = (await client.appClient.state.global.getAll())
        .escapeDeadline!;
      const first = await settleSyntheticPrefix(
        client,
        Buffer.alloc(32),
        firstTrancheChain,
        256n,
      );

      let state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(256n);
      expect(state.escapeInboxTarget).toBe(257n);
      expect(state.escapeDeadline).toBe(initialDeadline + grace);

      await expect(
        client.appClient.send.openBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { batchLength: first.batchLength, targetInboxCursor: 255n },
        }),
      ).rejects.toThrow();

      await settleSyntheticPrefix(
        client,
        firstTrancheChain,
        chain,
        257n,
        "forced-exit",
      );
      state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(257n);
      expect(state.escapeInboxTarget).toBeUndefined();
      expect(state.escapeDeadline).toBeUndefined();
      expect(state.escapeProgress).toBeUndefined();
    }, 120_000);

    // The point of counting both directions on one tranche. An outstanding payout chain closes
    // `openBatch`, so a sequencer under accusation has to drain before it can settle again -- and
    // without payouts earning credit, the drain the gate demands could itself be why the deadline
    // was missed. Here 255 consumed inbox entries plus one payout make a tranche between them.
    it("lets a settlement and a payout share one obligation tranche", async () => {
      const grace = 20n;
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        1n,
        grace,
      );
      const recipient = hex(scenario("deposits-only").deposits[0].recipient);
      let chain = Buffer.alloc(32);
      let shortOfTranche = Buffer.alloc(32);

      for (let index = 0; index < 256; index++) {
        expect(await client.deposit(sender, recipient, 1n)).toBe(BigInt(index));
        chain = sha256(tag("INBOXD"), chain, recipient, bytes(1n));
        if (index === 254) shortOfTranche = chain;
      }

      await client.signalEscape(sender);
      const initialDeadline = (await client.appClient.state.global.getAll())
        .escapeDeadline!;

      // Consume 255 of the 256 pending entries: short of the fixed target, and one short of a
      // tranche, so nothing is bought yet. This batch withdraws, so it leaves a chain outstanding.
      const bound = await settleSyntheticPrefix(
        client,
        Buffer.alloc(32),
        shortOfTranche,
        255n,
        "withdrawals",
      );

      let state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(255n);
      expect(state.escapeInboxTarget).toBe(256n);
      expect(state.escapeProgress).toBe(255n);
      expect(state.escapeDeadline).toBe(initialDeadline);
      expect(await client.pendingWithdrawals()).toBeDefined();

      // The prefix above is synthetic, so the deposit that would have funded these payouts never
      // reached L1 and every microALGO the app holds is committed to an inbox box. Cover them
      // directly -- this test is isolating the watchdog, not the accounting.
      await algorand.send.payment({
        sender: sender.address,
        signer: sender.txnSigner,
        receiver: client.appClient.appAddress,
        amount: microAlgo(1_000_000),
      });

      // An outsider's payout is real work, but it is not the sequencer's, and the accusation is
      // against the sequencer -- so it moves the chain and buys nothing.
      const outsider = await fundedOutsider();
      await client.payWithdrawal(
        outsider,
        algosdk.encodeAddress(hex(bound.withdrawals[0].recipient)),
        BigInt(bound.withdrawals[0].amount),
        hex(bound.withdrawals[0].tail),
      );

      state = await client.appClient.state.global.getAll();
      expect(state.escapeProgress).toBe(255n);
      expect(state.escapeDeadline).toBe(initialDeadline);

      // The sequencer's own payout completes the tranche the settlement started.
      await client.payWithdrawal(
        sender,
        algosdk.encodeAddress(hex(bound.withdrawals[1].recipient)),
        BigInt(bound.withdrawals[1].amount),
        hex(bound.withdrawals[1].tail),
      );

      state = await client.appClient.state.global.getAll();
      expect(state.escapeDeadline).toBe(initialDeadline + grace);
      // Spent, not carried, so the next window costs a full tranche again.
      expect(state.escapeProgress).toBe(0n);
      expect(state.escapeInboxTarget).toBe(256n);
    }, 120_000);

    // A request arriving mid-batch lies beyond the selected checkpoint and belongs to a later
    // batch, so a batch in flight is not invalidated by somebody demanding an exit.
    it("accepts a request that lands while a batch is being posted", async () => {
      const client = await RollupVerifier.createForTesting(algorand, sender);
      const s = await bindScenario(client, scenario("forced-exit"));
      const { request, pair } = subject();

      await replayDeposits(client, s);
      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: {
          batchLength: s.batchLength,
          targetInboxCursor: await client.inboxCursor(),
        },
        boxReferences: [queueBox(1n)],
      });

      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      for (const chunk of s.chunks) {
        await client.appClient.send.accumulateChunk({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { chunk: hex(chunk) },
        });
      }
      await client.settlePostedBatch(sender, hex(s.publicValues));

      const state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(2n);
      expect(state.inboxCursor).toBe(3n);
    });

    // A sequencer that credited the earlier deposits but ignores the next request still leaves a
    // stale unified inbox head that can trigger escape.
    it("lets a censored withdrawal trigger the escape on its own", async () => {
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );
      const s = scenario("forced-exit");
      const { request, pair } = subject();

      // The rollup is live and its inbox is clean: every earlier deposit has been credited.
      await replayDeposits(client, s);
      await settle(client, s);

      const state = await client.appClient.state.global.getAll();
      expect(state.settledInboxCursor).toBe(state.inboxCursor);

      // Somebody demands an exit, and the sequencer simply stops rather than honour it.
      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      // The only pending unified inbox entry is the request.
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      expect((await client.appClient.state.global.escaped()) ?? 0n).toBe(1n);
    });

    it("does not fire the escape while the request is still fresh", async () => {
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );
      const { request, pair } = subject();

      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      await expect(client.signalEscape(sender)).rejects.toThrow();
    });

    // An escape means the request will never be answered, so its box has nothing left to wait for
    // and the account comes out through forceExit instead.
    it("lets an unanswered request be pruned after an escape", async () => {
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );
      const { request, pair } = subject();

      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      await client.pruneRequest(sender, 0n);
    });

    it("refuses a request once the rollup has escaped", async () => {
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );
      const { request, pair } = subject();

      await client.deposit(sender, hex(request.address), 1_000n);
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      await expect(
        client.requestWithdrawal(
          sender,
          hex(request.address),
          pair.publicKey,
          algosdk.encodeAddress(hex(request.recipient)),
          pair.secretKey,
        ),
      ).rejects.toThrow();
    });
  });

  describe("forced exit", () => {
    type Exit = Scenario["exits"][number];

    const exits = () => scenario("forced-exit").exits;

    /** Deploy an escapable rollup, settle the forced-exit batch, and pull the hatch. */
    const escaped = async () => {
      const s = scenario("forced-exit");
      const client = await RollupVerifier.createForTesting(
        algorand,
        sender,
        TEST_INBOX_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );

      await replayDeposits(client, s);
      await settle(client, s);

      // The rollup then stops. One stranded deposit is what lets anyone prove it.
      await client.deposit(sender, hex(s.deposits[0].recipient), 1_000n);
      await advanceRounds(Number(TEST_INBOX_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      return client;
    };

    const exitArgs = (exit: Exit) => ({
      address: hex(exit.address),
      pubKey: hex(exit.pubKey),
      nonce: BigInt(exit.nonce),
      amount: BigInt(exit.amount),
      authAddress: hex(exit.authAddress),
      siblings: exit.siblings.map(hex),
    });

    it("derives the fixture's public keys from the seeds", () => {
      for (const [index, exit] of exits().entries()) {
        expect(Buffer.from(keyPair(index).publicKey).toString("hex")).toBe(
          exit.pubKey,
        );
      }
    });

    // The fixture's proofs are not degenerate -- the two accounts share a prefix, so each one is
    // hashed up through several levels rather than being the root outright.
    it("proves through a real path rather than a bare leaf", () => {
      for (const exit of exits()) {
        expect(exit.siblings.length).toBeGreaterThan(0);
      }
    });

    it("pays a holder out against the frozen root", async () => {
      const client = await escaped();
      const app = client.appClient.appAddress;

      const recipient = algorand.account.random();
      const held = await balanceOf(app);

      const [first] = exits();
      const paid = await client.forceExit(
        sender,
        exitArgs(first),
        recipient.addr,
        keyPair(0).secretKey,
      );

      // The balance arrives less the cost of the record that it was paid, and the app is left
      // holding exactly that record's minimum balance.
      expect(paid).toBe(BigInt(first.amount) - EXIT_BOX_MBR);
      expect(await balanceOf(recipient.addr)).toBe(paid);
      expect(held - (await balanceOf(app))).toBe(paid);
    });

    // A frozen root proves the same leaf forever, so nothing but the record stops a second payout.
    it("cannot exit the same account twice", async () => {
      const client = await escaped();
      const recipient = algorand.account.random();
      const [first] = exits();

      await client.forceExit(
        sender,
        exitArgs(first),
        recipient.addr,
        keyPair(0).secretKey,
      );

      await expect(
        client.forceExit(
          sender,
          exitArgs(first),
          recipient.addr,
          keyPair(0).secretKey,
        ),
      ).rejects.toThrow();
    });

    it("exits each account independently", async () => {
      const client = await escaped();
      const all = exits();

      for (const [index, exit] of all.entries()) {
        const recipient = algorand.account.random();
        const paid = await client.forceExit(
          sender,
          exitArgs(exit),
          recipient.addr,
          keyPair(index).secretKey,
        );

        expect(await balanceOf(recipient.addr)).toBe(paid);
      }
    });

    it("refuses before the rollup has escaped", async () => {
      const s = scenario("forced-exit");
      const client = await RollupVerifier.createForTesting(algorand, sender);

      await replayDeposits(client, s);
      await settle(client, s);

      await expect(
        client.forceExit(
          sender,
          exitArgs(exits()[0]),
          algorand.account.random().addr,
          keyPair(0).secretKey,
        ),
      ).rejects.toThrow();
    });

    // Proving the leaf says what the balance is; the signature says who may move it. Neither
    // substitutes for the other, so a valid proof signed by the wrong key must fail.
    it("refuses a proof signed by the wrong key", async () => {
      const client = await escaped();

      await expect(
        client.forceExit(
          sender,
          exitArgs(exits()[0]),
          algorand.account.random().addr,
          keyPair(1).secretKey,
        ),
      ).rejects.toThrow();
    });

    // The recipient is inside the signed message, so a claim cannot be lifted out of the mempool
    // and redirected.
    it("refuses a signature made out to a different recipient", async () => {
      const client = await escaped();
      const exit = exits()[0];
      const signature = nacl.sign.detached(
        exitMessage(
          await client.deploymentDomain(),
          hex(exit.address),
          algorand.account.random().addr,
        ),
        keyPair(0).secretKey,
      );

      await expect(
        client.appClient
          .newGroup()
          .opUp({
            sender: sender.address,
            signer: sender.txnSigner,
            args: { nonce: 0n },
          })
          .opUp({
            sender: sender.address,
            signer: sender.txnSigner,
            args: { nonce: 1n },
          })
          .opUp({
            sender: sender.address,
            signer: sender.txnSigner,
            args: { nonce: 2n },
          })
          .forceExit({
            sender: sender.address,
            signer: sender.txnSigner,
            args: {
              ...exitArgs(exit),
              scheme: new TextEncoder().encode("edd"),
              signature,
              // Signed for someone else.
              recipient: algorand.account.random().addr.toString(),
              siblings: Buffer.concat(exit.siblings.map(hex)),
            },
            boxReferences: [
              Buffer.concat([Buffer.from("e"), hex(exit.address)]),
            ],
            extraFee: microAlgo(1_000),
          })
          .send(),
      ).rejects.toThrow();
    });

    it("refuses an inflated balance", async () => {
      const client = await escaped();
      const exit = exits()[0];

      // The leaf commits to the amount, so claiming more cannot reproduce the root.
      await expect(
        client.forceExit(
          sender,
          { ...exitArgs(exit), amount: BigInt(exit.amount) * 2n },
          algorand.account.random().addr,
          keyPair(0).secretKey,
        ),
      ).rejects.toThrow();
    });

    it("refuses a doctored sibling", async () => {
      const client = await escaped();
      const exit = exits()[0];

      const siblings = exit.siblings.map(hex);
      siblings[siblings.length - 1] = Buffer.from(
        siblings[siblings.length - 1],
      );
      siblings[siblings.length - 1][0] ^= 1;

      await expect(
        client.forceExit(
          sender,
          { ...exitArgs(exit), siblings },
          algorand.account.random().addr,
          keyPair(0).secretKey,
        ),
      ).rejects.toThrow();
    });

    // A path of the wrong length ends up somewhere else in the tree, and there is no separate depth
    // field for it to disagree with -- the length *is* the depth.
    it("refuses a proof of the wrong depth", async () => {
      const client = await escaped();
      const exit = exits()[0];

      await expect(
        client.forceExit(
          sender,
          { ...exitArgs(exit), siblings: exit.siblings.slice(1).map(hex) },
          algorand.account.random().addr,
          keyPair(0).secretKey,
        ),
      ).rejects.toThrow();
    });

    // A managed account is one the sequencer signs for, so there is no key behind its auth address
    // and nothing anyone could present. Rejecting the scheme outright says so.
    it("refuses a scheme it cannot check", async () => {
      const client = await escaped();
      const exit = exits()[0];

      await expect(
        client.appClient.send.forceExit({
          sender: sender.address,
          signer: sender.txnSigner,
          args: {
            ...exitArgs(exit),
            scheme: new TextEncoder().encode("man"),
            signature: new Uint8Array(64),
            recipient: sender.address.toString(),
            siblings: Buffer.concat(exit.siblings.map(hex)),
          },
          boxReferences: [Buffer.concat([Buffer.from("e"), hex(exit.address)])],
        }),
      ).rejects.toThrow();
    });
  });

  // Without this a batch that cannot settle wedges the contract permanently: `openBatch` refuses
  // while one is in flight, and only `verifyBatch` used to clear that.
  it("can abandon a stuck batch and settle a clean one after", async () => {
    const client = await RollupVerifier.createForTesting(algorand, sender);
    const s = scenario("deposits-only");

    await replayDeposits(client, s);

    // Open with a length nothing will ever fill.
    await client.appClient.send.openBatch({
      sender: sender.address,
      signer: sender.txnSigner,
      args: {
        batchLength: s.batchLength + 1,
        targetInboxCursor: await client.inboxCursor(),
      },
      boxReferences: [queueBox(2n)],
    });

    await client.abandonBatch(sender);

    await settle(client, s);

    const state = await client.appClient.state.global.getAll();
    expect(Buffer.from(state.stateRoot!.asByteArray()!).toString("hex")).toBe(
      s.newRoot,
    );
  });
});
