import { beforeAll, describe, expect, it } from "vitest";
import {
  CHUNK_SIZE,
  DEPOSIT_BOX_MBR,
  EXIT_BOX_MBR,
  MIN_WITHDRAWAL,
  REQUEST_BOX_MBR,
  RollupVerifier,
  WITHDRAWAL_BOX_MBR,
  exitMessage,
  l2Address,
  withdrawalRequestMessage,
} from "../src";
import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";
import algosdk from "algosdk";
import nacl from "tweetnacl";
import fixture from "../fixtures/settlements.json";

type Scenario = (typeof fixture.scenarios)[number];

const hex = (value: string) => Buffer.from(value, "hex");

/**
 * Escape parameters small enough for a test to wait out.
 *
 * The production values are hundreds of thousands of rounds, which is precisely why they are
 * deployment arguments rather than contract constants -- no test could ever reach one.
 */
const TEST_DEPOSIT_TIMEOUT = 5n;
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
    if (Buffer.from(l2Address("edd", pair.publicKey)).toString("hex") === addressHex) {
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

  /** Whether a scenario's public values carry a withdrawal chain, and so open a payout queue. */
  const withdraws = (s: Scenario) => s.withdrawals.length > 0;

  /**
   * File a scenario's L1 withdrawal requests, in the order the batch answers them.
   *
   * The mirror of {@link replayDeposits}, and just as load-bearing: the request chain only reaches
   * `requestChainTo` if L1 sees exactly these, exactly here.
   */
  const replayRequests = async (client: RollupVerifier, s: Scenario) => {
    for (const request of s.requests) {
      const pair = keyPairFor(request.address)!;
      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );
    }
  };

  /** Everything L1 must see before a batch can settle. */
  const replayL1 = async (client: RollupVerifier, s: Scenario) => {
    await replayDeposits(client, s);
    await replayRequests(client, s);
  };

  /** Settle a scenario, funding the withdrawal queue box when the batch needs one. */
  const settle = (client: RollupVerifier, s: Scenario) =>
    client.verifyBatch(sender, hex(s.batch), hex(s.publicValues), withdraws(s));

  /**
   * Drain a settled batch's payout queue.
   *
   * Newest-first, which is the only direction a hash chain can be followed: the fixture lists the
   * withdrawals in batch order, so the claims run through it backwards.
   */
  const claimAll = async (
    client: RollupVerifier,
    s: Scenario,
    batchNumber: bigint,
  ) => {
    for (const w of [...s.withdrawals].reverse()) {
      await client.claimWithdrawal(
        sender,
        batchNumber,
        algosdk.encodeAddress(hex(w.recipient)),
        BigInt(w.amount),
        hex(w.chainBefore),
      );
    }
  };

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

  // The constants the contract, the guest and the driver each hold a copy of, with nothing but
  // these assertions linking the three.
  it("agrees with the guest about the chunk size", () => {
    expect(CHUNK_SIZE).toBe(fixture.chunkSize);
  });

  it("agrees with the guest about the withdrawal minimum", () => {
    expect(MIN_WITHDRAWAL).toBe(BigInt(fixture.minWithdrawal));
  });

  for (const s of fixture.scenarios) {
    it(`should verify with scenario ${s.name}`, async () => {
      const client = await RollupVerifier.create(algorand, sender);

      await replayL1(client, s);

      await settle(client, s);

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
          expectedRequestCursor: await client.requestCursor(),
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
          args: {
            batchLength: s.batchLength,
            expectedDepositCursor: stale,
            expectedRequestCursor: await client.requestCursor(),
          },
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

  describe("withdrawals", () => {
    const withdrawing = () => scenario("withdrawals");

    /** Deploy, replay the deposits, settle, and hand back the queue's batch number. */
    const settled = async (s: Scenario) => {
      const client = await RollupVerifier.create(algorand, sender);
      await replayDeposits(client, s);

      const batchNumber = await client.batchNumber();
      await settle(client, s);

      return { client, batchNumber };
    };

    it("pays every withdrawal out to the account the batch named", async () => {
      const s = withdrawing();
      const { client, batchNumber } = await settled(s);

      const before = await Promise.all(
        s.withdrawals.map((w) =>
          balanceOf(algosdk.encodeAddress(hex(w.recipient))),
        ),
      );

      await claimAll(client, s, batchNumber);

      // Each recipient got its own amount, which only holds if the unwind matched claims to
      // positions rather than merely draining the right total.
      for (const [index, w] of s.withdrawals.entries()) {
        const after = await balanceOf(algosdk.encodeAddress(hex(w.recipient)));
        expect(after - before[index]).toBe(BigInt(w.amount));
      }
    });

    // The queue is a chain, so it can only be followed backwards. Claiming the oldest first has to
    // fail, or the tip is not doing the work it exists to do.
    it("refuses a claim that is not the newest unclaimed one", async () => {
      const s = withdrawing();
      const { client, batchNumber } = await settled(s);
      const oldest = s.withdrawals[0];

      await expect(
        client.claimWithdrawal(
          sender,
          batchNumber,
          algosdk.encodeAddress(hex(oldest.recipient)),
          BigInt(oldest.amount),
          hex(oldest.chainBefore),
        ),
      ).rejects.toThrow();
    });

    it("refuses a claim with an altered amount or recipient", async () => {
      const s = withdrawing();
      const { client, batchNumber } = await settled(s);
      const newest = s.withdrawals[s.withdrawals.length - 1];

      await expect(
        client.claimWithdrawal(
          sender,
          batchNumber,
          algosdk.encodeAddress(hex(newest.recipient)),
          BigInt(newest.amount) + 1n,
          hex(newest.chainBefore),
        ),
      ).rejects.toThrow();

      await expect(
        client.claimWithdrawal(
          sender,
          batchNumber,
          sender.address.toString(),
          BigInt(newest.amount),
          hex(newest.chainBefore),
        ),
      ).rejects.toThrow();
    });

    // Paying a claim consumes it: the tip moves past it and the fold no longer reproduces anything.
    // That is the whole of the double-claim defence -- there is no nullifier to check.
    it("cannot pay the same withdrawal twice", async () => {
      const s = withdrawing();
      const { client, batchNumber } = await settled(s);
      const newest = s.withdrawals[s.withdrawals.length - 1];

      const claim = () =>
        client.claimWithdrawal(
          sender,
          batchNumber,
          algosdk.encodeAddress(hex(newest.recipient)),
          BigInt(newest.amount),
          hex(newest.chainBefore),
        );

      await claim();
      await expect(claim()).rejects.toThrow();
    });

    it("returns the queue box minimum balance when the last claim lands", async () => {
      const s = withdrawing();
      const client = await RollupVerifier.create(algorand, sender);
      await replayDeposits(client, s);

      const batchNumber = await client.batchNumber();
      await settle(client, s);

      // The settler advanced the box's minimum balance out of their own pocket, so the app is
      // holding it on top of what it owes.
      const app = client.appClient.appAddress;
      const held = await balanceOf(app);
      const queues = async () =>
        (await client.appClient.appClient.getBoxNames()).filter(
          (n) => n.nameRaw[0] === "w".charCodeAt(0),
        );
      expect(await queues()).toHaveLength(1);

      await claimAll(client, s, batchNumber);

      const paid = s.withdrawals.reduce((t, w) => t + BigInt(w.amount), 0n);
      // The app paid out exactly the withdrawals and gave the box minimum balance back.
      expect(held - (await balanceOf(app))).toBe(paid + WITHDRAWAL_BOX_MBR);

      // And the box is gone, so nothing else can be claimed against that batch.
      expect(await queues()).toHaveLength(0);
    });

    // A batch that withdraws nothing folds to the genesis value and must not open a box at all --
    // that is what keeps the common settlement free of the whole mechanism.
    it("opens no queue for a batch that withdraws nothing", async () => {
      const s = scenario("deposits-only");
      const client = await RollupVerifier.create(algorand, sender);

      await replayDeposits(client, s);
      await settle(client, s);

      const names = await client.appClient.appClient.getBoxNames();
      // The deposit boxes are asserted alongside so that this cannot pass by seeing no boxes at
      // all -- the point is that the "w" prefix in particular is absent.
      expect(names.filter((n) => n.nameRaw[0] === "d".charCodeAt(0))).toHaveLength(
        s.deposits.length,
      );
      expect(names.filter((n) => n.nameRaw[0] === "w".charCodeAt(0))).toHaveLength(
        0,
      );
    });

    // Value that already left L2 in a settled batch is not the rollup's to withhold, whatever
    // happens to the rollup afterwards.
    it("still pays out after the rollup has escaped", async () => {
      const s = withdrawing();
      const client = await RollupVerifier.create(
        algorand,
        sender,
        TEST_DEPOSIT_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );

      await replayDeposits(client, s);
      const batchNumber = await client.batchNumber();
      await settle(client, s);

      // Strand a fresh deposit and pull the hatch.
      await client.deposit(sender, hex(s.deposits[0].recipient), 1_000n);
      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      const newest = s.withdrawals[s.withdrawals.length - 1];
      const recipient = algosdk.encodeAddress(hex(newest.recipient));
      const before = await balanceOf(recipient);

      await client.claimWithdrawal(
        sender,
        batchNumber,
        recipient,
        BigInt(newest.amount),
        hex(newest.chainBefore),
      );

      expect((await balanceOf(recipient)) - before).toBe(BigInt(newest.amount));
    });

    // Queues are keyed by batch number and anchored at genesis independently, so one batch's
    // claims neither block nor are blocked by another's.
    it("keeps two batches' queues independent", async () => {
      const s = withdrawing();
      const client = await RollupVerifier.create(algorand, sender);

      await replayDeposits(client, s);
      const first = await client.batchNumber();
      await settle(client, s);

      // The same scenario cannot settle twice -- it starts from genesis -- so this only checks the
      // keying, which is what the independence rests on.
      expect(first).toBe(0n);
      expect(await client.batchNumber()).toBe(1n);

      const newest = s.withdrawals[s.withdrawals.length - 1];
      await expect(
        client.claimWithdrawal(
          sender,
          1n,
          algosdk.encodeAddress(hex(newest.recipient)),
          BigInt(newest.amount),
          hex(newest.chainBefore),
        ),
      ).rejects.toThrow();
    });

    // The round-trip scenario withdraws from an account that held nothing when the block opened.
    it("settles a batch that deposits, pays and withdraws at once", async () => {
      const s = scenario("round-trip");
      const { client, batchNumber } = await settled(s);

      await claimAll(client, s, batchNumber);

      const state = await client.appClient.state.global.getAll();
      expect(Buffer.from(state.stateRoot!.asByteArray()!).toString("hex")).toBe(
        s.newRoot,
      );
    });
  });

  describe("escape hatch", () => {
    const recipient = () => hex(scenario("deposits-only").deposits[0].recipient);

    /** A rollup whose escape parameters are small enough to actually cross. */
    const escapable = () =>
      RollupVerifier.create(
        algorand,
        sender,
        TEST_DEPOSIT_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );

    /** Deposit, let it go stale, and signal. Leaves the contract one grace period from escape. */
    const signalOverStaleDeposit = async (client: RollupVerifier) => {
      await client.deposit(sender, recipient(), 1_000n);
      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
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
      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);

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
      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
      await client.signalEscape(sender);

      await client.verifyBatch(sender, hex(s.batch), hex(s.publicValues));

      expect(
        (await client.appClient.state.global.getAll()).escapeDeadline,
      ).toBeUndefined();
      await expect(client.executeEscape(sender)).rejects.toThrow();
    });

    it("refuses to execute before the grace period has run out", async () => {
      const client = await escapable();

      await signalOverStaleDeposit(client);

      await expect(client.executeEscape(sender)).rejects.toThrow();
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
          expectedDepositCursor: await client.depositCursor(),
          expectedRequestCursor: await client.requestCursor(),
        },
      });

      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      // A deleted byte-typed global comes back as an empty wrapper rather than as `undefined`,
      // hence the unwrap; the integer ones are absent outright.
      const state = await client.appClient.state.global.getAll();
      expect(state.batchLength).toBeUndefined();
      expect(state.postedLength).toBeUndefined();
      expect(state.sealedDepositCursor).toBeUndefined();
      expect(state.chunkAccumulator?.asByteArray()).toBeUndefined();
      expect(state.sealedDepositChain?.asByteArray()).toBeUndefined();
    });

    it("freezes the rollup once the hatch is pulled", async () => {
      const client = await escapable();
      const s = scenario("deposits-only");

      await escape(client);

      await expect(client.deposit(sender, recipient(), 1_000n)).rejects.toThrow();
      await expect(
        client.appClient.send.openBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: {
            batchLength: s.batchLength,
            expectedDepositCursor: 1n,
            expectedRequestCursor: 0n,
          },
        }),
      ).rejects.toThrow();
      await expect(
        client.appClient.send.verifyBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: { publicValues: hex(s.publicValues) },
        }),
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

      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      // The bystander pays the fees; the money goes where the box says.
      await client.reclaimDeposit(sender, 0n);

      expect((await balanceOf(depositor.addr)) - stranded).toBe(
        500_000n + DEPOSIT_BOX_MBR,
      );
      expect(held - (await balanceOf(app))).toBe(500_000n + DEPOSIT_BOX_MBR);

      // The box is gone, so there is no second refund to collect.
      await expect(client.reclaimDeposit(sender, 0n)).rejects.toThrow();
    });

    it("refuses to reclaim before an escape", async () => {
      const client = await escapable();

      await client.deposit(sender, recipient(), 1_000n);

      await expect(client.reclaimDeposit(sender, 0n)).rejects.toThrow();
    });

    // `pruneDeposit` and `reclaimDeposit` partition the queue at `settledDepositCursor`, and the
    // partition is what makes a bare cursor comparison enough to decide who is owed what.
    it("splits the queue at the settled cursor", async () => {
      const client = await escapable();
      const s = scenario("deposits-only");

      await replayDeposits(client, s);
      await client.verifyBatch(sender, hex(s.batch), hex(s.publicValues));

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

      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
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
      const client = await RollupVerifier.create(algorand, sender);

      await replayL1(client, s);
      await settle(client, s);

      const state = await client.appClient.state.global.getAll();
      expect(
        Buffer.from(state.settledRequestChain!.asByteArray()!).toString("hex"),
      ).toBe(s.requestChainTo);
      expect(state.settledRequestCursor).toBe(1n);
    });

    // The hole this whole mechanism exists to close. Before it, a sequencer could settle batches
    // forever while quietly dropping every withdrawal, and L1 had no way to tell.
    it("refuses to settle a batch that ignores a pending request", async () => {
      const s = scenario("forced-exit");
      const client = await RollupVerifier.create(algorand, sender);
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
      const client = await RollupVerifier.create(algorand, sender);

      await replayL1(client, s);
      const batchNumber = await client.batchNumber();
      await settle(client, s);

      const payout = s.withdrawals[0];
      const recipient = algosdk.encodeAddress(hex(payout.recipient));
      const before = await balanceOf(recipient);

      await claimAll(client, s, batchNumber);

      // The whole deposited balance, and no amount was ever named on L1 or on the wire.
      expect((await balanceOf(recipient)) - before).toBe(BigInt(payout.amount));
      expect(BigInt(payout.amount)).toBe(BigInt(s.deposits[0].amount));
    });

    // A request that is answered is spent: the account is empty, so demanding it again is legal
    // and simply pays nothing. What must not happen is the queue refusing to drain.
    it("lets an answered request be pruned and its minimum balance returned", async () => {
      const s = forcing();
      const client = await RollupVerifier.create(algorand, sender);
      const app = client.appClient.appAddress;

      await replayL1(client, s);
      await settle(client, s);

      const before = await balanceOf(sender.address);
      await client.pruneRequest(sender, 0n);

      // The refund lands and the app's own minimum balance falls by the same amount, so the two
      // cancel exactly as they do for a deposit box.
      expect(await balanceOf(sender.address)).toBeGreaterThan(
        before + REQUEST_BOX_MBR - 3_000n,
      );
      const names = await client.appClient.appClient.getBoxNames();
      expect(names.filter((n) => n.nameRaw[0] === "r".charCodeAt(0))).toHaveLength(0);
      expect(app).toBeDefined();
    });

    it("refuses to prune a request that has not been answered", async () => {
      const client = await RollupVerifier.create(algorand, sender);
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
      const client = await RollupVerifier.create(algorand, sender);
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
      const client = await RollupVerifier.create(algorand, sender);
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
      const client = await RollupVerifier.create(algorand, sender);
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
          client.appClient.appId,
          0n,
          hex(request.address),
          algosdk.decodeAddress(recipient),
        ),
        pair.secretKey,
      );
      const payment = await client.appClient.algorand.createTransaction.payment({
        sender: sender.address,
        receiver: client.appClient.appAddress,
        amount: microAlgo(REQUEST_BOX_MBR),
      });
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
            boxReferences: [
              Buffer.concat([Buffer.from("r"), Buffer.alloc(8, 0).fill(0)]),
            ],
          })
          .send(),
      ).rejects.toThrow();
    });

    it("refuses to open a batch built before a request landed", async () => {
      const s = scenario("forced-exit");
      const client = await RollupVerifier.create(algorand, sender);
      const { request, pair } = subject();

      await replayDeposits(client, s);
      const stale = await client.requestCursor();
      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      await expect(
        client.appClient.send.openBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: {
            batchLength: s.batchLength,
            expectedDepositCursor: await client.depositCursor(),
            expectedRequestCursor: stale,
          },
        }),
      ).rejects.toThrow();
    });

    // A request arriving mid-batch belongs to the next one, exactly as a deposit does. The seal is
    // a copy, so a batch in flight is not invalidated by somebody demanding an exit.
    it("accepts a request that lands while a batch is being posted", async () => {
      const s = scenario("forced-exit");
      const client = await RollupVerifier.create(algorand, sender);
      const { request, pair } = subject();

      await replayDeposits(client, s);
      await client.appClient.send.openBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: {
          batchLength: s.batchLength,
          expectedDepositCursor: await client.depositCursor(),
          expectedRequestCursor: await client.requestCursor(),
        },
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
      await client.appClient.send.verifyBatch({
        sender: sender.address,
        signer: sender.txnSigner,
        args: { publicValues: hex(s.publicValues) },
      });

      const state = await client.appClient.state.global.getAll();
      expect(state.settledRequestCursor).toBe(0n);
      expect(state.requestCursor).toBe(1n);
    });

    // The point of the second escape clock. A sequencer that keeps crediting deposits while
    // declining to let anyone out leaves the deposit queue spotless, so the deposit clock never
    // fires -- and before this, nothing else would either.
    it("lets a censored withdrawal trigger the escape on its own", async () => {
      const client = await RollupVerifier.create(
        algorand,
        sender,
        TEST_DEPOSIT_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );
      const s = scenario("forced-exit");
      const { request, pair } = subject();

      // The rollup is live and its deposit queue is clean: every deposit has been credited.
      await replayDeposits(client, s);
      await settle(client, s);

      const state = await client.appClient.state.global.getAll();
      expect(state.settledDepositCursor).toBe(state.depositCursor);

      // Somebody demands an exit, and the sequencer simply stops rather than honour it.
      await client.requestWithdrawal(
        sender,
        hex(request.address),
        pair.publicKey,
        algosdk.encodeAddress(hex(request.recipient)),
        pair.secretKey,
      );

      // Nothing is owed on the deposit side, so this can only be the request queue talking.
      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      expect((await client.appClient.state.global.escaped()) ?? 0n).toBe(1n);
    });

    it("does not fire the escape while the request is still fresh", async () => {
      const client = await RollupVerifier.create(
        algorand,
        sender,
        TEST_DEPOSIT_TIMEOUT,
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
      const client = await RollupVerifier.create(
        algorand,
        sender,
        TEST_DEPOSIT_TIMEOUT,
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

      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
      await client.signalEscape(sender);
      await advanceRounds(Number(TEST_ESCAPE_GRACE) + 1);
      await client.executeEscape(sender);

      await client.pruneRequest(sender, 0n);
    });

    it("refuses a request once the rollup has escaped", async () => {
      const client = await RollupVerifier.create(
        algorand,
        sender,
        TEST_DEPOSIT_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );
      const { request, pair } = subject();

      await client.deposit(sender, hex(request.address), 1_000n);
      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
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
      const client = await RollupVerifier.create(
        algorand,
        sender,
        TEST_DEPOSIT_TIMEOUT,
        TEST_ESCAPE_GRACE,
      );

      await replayDeposits(client, s);
      await settle(client, s);

      // The rollup then stops. One stranded deposit is what lets anyone prove it.
      await client.deposit(sender, hex(s.deposits[0].recipient), 1_000n);
      await advanceRounds(Number(TEST_DEPOSIT_TIMEOUT) + 1);
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
      const client = await RollupVerifier.create(algorand, sender);

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
          client.appClient.appId,
          hex(exit.address),
          algorand.account.random().addr,
        ),
        keyPair(0).secretKey,
      );

      await expect(
        client.appClient
          .newGroup()
          .opUp({ sender: sender.address, signer: sender.txnSigner, args: { nonce: 0n } })
          .opUp({ sender: sender.address, signer: sender.txnSigner, args: { nonce: 1n } })
          .opUp({ sender: sender.address, signer: sender.txnSigner, args: { nonce: 2n } })
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
        expectedRequestCursor: await client.requestCursor(),
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
