import { beforeAll, describe, expect, it } from "vitest";
import { CHUNK_SIZE, DEPOSIT_BOX_MBR, RollupVerifier } from "../src";
import { AlgorandClient } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import fixture from "../fixtures/settlements.json";

type Scenario = (typeof fixture.scenarios)[number];

const hex = (value: string) => Buffer.from(value, "hex");

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

  /** Replay a scenario's deposits onto L1, in the order the batch credits them. */
  const replayDeposits = async (client: RollupVerifier, s: Scenario) => {
    for (const deposit of s.deposits) {
      await client.deposit(
        sender,
        hex(deposit.recipient),
        BigInt(deposit.amount),
      );
    }
  };

  // The one constant the contract, the guest and the driver each hold a copy of.
  it("agrees with the guest about the chunk size", () => {
    expect(CHUNK_SIZE).toBe(fixture.chunkSize);
  });

  for (const s of fixture.scenarios) {
    it(`should verify with scenario ${s.name}`, async () => {
      const client = await RollupVerifier.create(algorand, sender);

      await replayDeposits(client, s);

      await client.verifyBatch(sender, hex(s.batch), hex(s.publicValues));

      const state = await client.appClient.state.global.getAll();
      expect(Buffer.from(state.stateRoot!.asByteArray()!).toString("hex")).toBe(
        s.newRoot,
      );
      expect(
        Buffer.from(state.settledDepositChain!.asByteArray()!).toString("hex"),
      ).toBe(s.depositChainTo);
    });
  }

  describe("deposit inclusion", () => {
    // Every case below settles a batch whose deposits do not match what L1 saw. The chain is what
    // catches each one, and it catches all of them the same way: the fold lands somewhere the
    // contract is not holding.
    const depositsOnly = () => scenario("deposits-only");

    const settleExpectingFailure = async (
      client: RollupVerifier,
      s: Scenario,
    ) => {
      await expect(
        client.verifyBatch(sender, hex(s.batch), hex(s.publicValues)),
      ).rejects.toThrow();
    };

    it("rejects a batch that credits a deposit L1 never accepted", async () => {
      const client = await RollupVerifier.create(algorand, sender);
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
      const client = await RollupVerifier.create(algorand, sender);
      const s = depositsOnly();

      await replayDeposits(client, s);
      // One more than the batch credits, so the sealed chain runs past where the batch lands.
      await client.deposit(sender, hex(s.deposits[0].recipient), 1_000n);

      await settleExpectingFailure(client, s);
    });

    it("rejects a batch whose deposits arrived in a different order", async () => {
      const client = await RollupVerifier.create(algorand, sender);
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
      const client = await RollupVerifier.create(algorand, sender);
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
      const client = await RollupVerifier.create(algorand, sender);

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
      const client = await RollupVerifier.create(algorand, sender);
      const s = depositsOnly();

      await replayDeposits(client, s);

      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: {
          batchLength: s.batchLength,
          expectedDepositCursor: await client.depositCursor(),
        },
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

      await client.appClient.send.verifyBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: { publicValues: hex(s.publicValues) },
      });

      // The batch settled against the sealed chain, and the late deposit is still pending.
      const state = await client.appClient.state.global.getAll();
      expect(state.settledDepositCursor).toBe(3n);
      expect(state.depositCursor).toBe(4n);
    });

    it("refuses to open a batch built before a deposit landed", async () => {
      const client = await RollupVerifier.create(algorand, sender);
      const s = depositsOnly();

      await replayDeposits(client, s);
      const stale = await client.depositCursor();
      await client.deposit(sender, hex(s.deposits[0].recipient), 1_000n);

      await expect(
        client.appClient.send.openBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { batchLength: s.batchLength, expectedDepositCursor: stale },
        }),
      ).rejects.toThrow();
    });
  });

  describe("box lifecycle", () => {
    it("charges the depositor the box minimum balance and refunds it on prune", async () => {
      const client = await RollupVerifier.create(algorand, sender);
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
        credited + DEPOSIT_BOX_MBR * BigInt(s.deposits.length),
      );

      await client.verifyBatch(sender, hex(s.batch), hex(s.publicValues));

      await client.pruneDeposit(sender, 0n);

      const pruned = (await algorand.account.getInformation(app)).balance
        .microAlgo;
      expect(funded - pruned).toBe(DEPOSIT_BOX_MBR);
    });

    it("refuses to prune a deposit that has not settled", async () => {
      const client = await RollupVerifier.create(algorand, sender);

      await client.deposit(
        sender,
        hex(scenario("deposits-only").deposits[0].recipient),
        1_000n,
      );

      await expect(client.pruneDeposit(sender, 0n)).rejects.toThrow();
    });
  });

  // Without this a batch that cannot settle wedges the contract permanently: `openBatch` refuses
  // while one is in flight, and only `verifyBatch` used to clear that.
  it("can abandon a stuck batch and settle a clean one after", async () => {
    const client = await RollupVerifier.create(algorand, sender);
    const s = scenario("deposits-only");

    await replayDeposits(client, s);

    // Open with a length nothing will ever fill.
    await client.appClient.send.openBatch({
      sender: sender.address,
      signer: sender.txnSigner,
      args: {
        batchLength: s.batchLength + 1,
        expectedDepositCursor: await client.depositCursor(),
      },
    });

    await client.abandonBatch(sender);

    await client.verifyBatch(sender, hex(s.batch), hex(s.publicValues));

    const state = await client.appClient.state.global.getAll();
    expect(Buffer.from(state.stateRoot!.asByteArray()!).toString("hex")).toBe(
      s.newRoot,
    );
  });
});
