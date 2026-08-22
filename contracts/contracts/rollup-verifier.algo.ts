import {
  arc4,
  assert,
  assertMatch,
  BoxMap,
  bytes,
  Bytes,
  Contract,
  Global,
  gtxn,
  GlobalState,
  itxn,
  Txn,
  uint64,
  Account,
} from "@algorandfoundation/algorand-typescript";
import {
  bzero,
  itob,
  sha256,
} from "@algorandfoundation/algorand-typescript/op";

/**
 * Largest fragment of a batch: as much as fits in one application argument -- 4096 bytes as of
 * go-algorand 5.0 (AVM v42) -- once the ABI length prefix on a `byte[]` has taken its two.
 *
 * A chunk therefore lands two bytes inside the other limit that matters, the 4096 bytes the AVM
 * holds in a single value. That is why the fold below is two hashes per chunk rather than one:
 * `tag || accumulator || chunk` would be 4131 bytes and unhashable here, so the chunk is digested
 * down to 32 bytes first.
 *
 * Must equal `CHUNK_SIZE` in the guest. If the two disagree they cut the same bytes into different
 * chunks and never reach the same commitment.
 */
const CHUNK_SIZE = 4094;

/**
 * One posted fragment of a batch.
 *
 * Deliberately not `bytes<4094>`: every chunk but the last is full, and the last one is whatever
 * the declared length leaves over. The size a chunk is *allowed* to be at its position is checked
 * in `accumulateChunk` instead, where the running total is known.
 */
export type Chunk = bytes;

/**
 * The 160 bytes the guest commits:
 *
 * ```text
 * [  0.. 32)  old_root
 * [ 32.. 64)  new_root
 * [ 64.. 96)  batch_commitment
 * [ 96..128)  old_deposit_chain
 * [128..160)  new_deposit_chain
 * ```
 *
 * Mirrors `public_values`. Nothing else escapes the proof, which is why the batch itself has to
 * arrive as chunks and be folded into a commitment the contract can compare against the third
 * word.
 */
export type PublicValues = bytes<160>;

/**
 * Minimum balance the network charges for one deposit box: `2500 + 400 * (key + value)`, over a
 * 9-byte key (`"d"` and an 8-byte nonce) and an 80-byte value.
 *
 * The depositor funds it as part of their payment and gets it back from `pruneDeposit` once the
 * deposit has settled, so a deposit costs nothing but fees in the end and the app never subsidises
 * one. Spam is paid for by the spammer for as long as it sits in the queue.
 */
const DEPOSIT_BOX_MBR = 38_100;

/**
 * One pending deposit, exactly as much of it as anyone needs later.
 *
 * `recipient` and `amount` are the two fields the deposit chain commits to, and are what the
 * sequencer reads back to build a batch that folds to the same value. The other two are recorded
 * against a day that has not arrived; see the note on the missing forced exit in `deposit`.
 *
 * Fixed-width throughout, so the box is exactly 80 bytes and `DEPOSIT_BOX_MBR` is a constant rather
 * than something to compute per deposit.
 */
type DepositRecord = {
  /** The L2 address to credit. Not an Algorand address -- see the warning on `deposit`. */
  recipient: bytes<32>;
  /** microALGO to credit on L2, which is the payment less the box's own minimum balance. */
  amount: uint64;
  /**
   * The L1 account that sent the funds.
   *
   * Load-bearing and not obvious: `recipient` is an L2 address and can never receive an L1
   * payment, so a refund of any kind -- the minimum balance on prune today, the deposit itself if a
   * forced exit is ever built -- has nowhere else to go.
   */
  payer: Account;
  /** Round the deposit was accepted in. Nothing reads it yet; see `deposit`. */
  round: uint64;
};

export class RollupVerifier extends Contract {
  /**
   * The root the chain has settled on: the state every future batch must start from.
   *
   * This is the whole point of the contract. A proof carries the root it began at, and the only
   * proof this contract will accept is one that began at the root recorded here -- which is what
   * makes the sequence of batches a chain rather than a set of unrelated transitions.
   */
  stateRoot = GlobalState<bytes<32>>();

  /**
   * The fold over every chunk posted so far.
   *
   * This one word is the whole of the contract's data-availability bookkeeping -- no tree, no
   * per-chunk proofs, nothing retained per chunk. It starts at a seed over the declared length and
   * ends, once the last chunk lands, equal to the batch commitment the proof carries in its public
   * values.
   */
  chunkAccumulator = GlobalState<bytes<32>>();

  /**
   * Length the sequencer declared for the batch being posted.
   *
   * Committing to it up front is what tells the contract when a batch is complete rather than
   * having to be told, and what makes the chunk boundaries canonical: the length fixes where every
   * cut falls, so the same bytes cannot be re-cut into different chunks.
   */
  batchLength = GlobalState<uint64>();

  /** How many of those bytes have been posted. The batch is complete when it reaches the length. */
  postedLength = GlobalState<uint64>();

  /**
   * The fold over every deposit this contract has ever accepted, in the order it accepted them.
   *
   * Mirrors `accumulate_deposit`. This is what makes a batch's deposits provably L1's: a batch
   * settles only if the guest, folding the same hash over the deposits it decoded, walks from the
   * value settled last time to the value standing here. With both ends pinned the folds between
   * them are determined, so a batch cannot invent, drop, reorder or alter a deposit.
   *
   * Never reset. A batch consumes a segment of the chain, not the whole of it, which is what lets
   * deposits keep arriving while a batch is being posted and what makes `abandonBatch` possible.
   */
  depositChain = GlobalState<bytes<32>>();

  /** Nonce the next deposit will be filed under. Never reset; deposits are strictly append-only. */
  depositCursor = GlobalState<uint64>();

  /** `depositChain` as of the last settled batch: the value the next batch has to anchor to. */
  settledDepositChain = GlobalState<bytes<32>>();

  /** First nonce not yet settled. Everything below it is safe to prune. */
  settledDepositCursor = GlobalState<uint64>();

  /**
   * `depositChain` at the moment the open batch was opened, and the value it has to fold to.
   *
   * Copied rather than moved, so deposits that arrive while the batch is in flight extend the live
   * chain past this point without disturbing it. They belong to the next batch.
   */
  sealedDepositChain = GlobalState<bytes<32>>();

  /** `depositCursor` at the same moment, and what `settledDepositCursor` becomes on settlement. */
  sealedDepositCursor = GlobalState<uint64>();

  /**
   * The pending queue, one box per deposit, keyed by nonce.
   *
   * Deliberately not part of the inclusion mechanism -- `openBatch`, `accumulateChunk` and
   * `verifyBatch` read **no** boxes, and that has to stay true. It is what keeps the cost of
   * settling independent of how many deposits are queued, and what keeps the settlement path inside
   * the eight box references a transaction is allowed.
   *
   * What they are for is discovery. A hash chain cannot be run backwards, so a sequencer coming up
   * cold, or anyone auditing one, needs the ordered pending list from somewhere; without these it
   * would have to be reconstructed from transaction history, and an ordering mistake shows up only
   * as a `verifyBatch` that fails after the whole batch has been paid for.
   */
  deposits = BoxMap<uint64, DepositRecord>({ keyPrefix: "d" });

  /**
   * Genesis: the empty ledger.
   *
   * `EMPTY_SUBTREE` in the tree is 32 zero bytes and an empty sparse tree hashes to it, so a
   * ledger with no accounts in it is the root below. Starting anywhere else would be claiming a
   * state no batch had ever proved its way to.
   */
  createApplication(): void {
    this.stateRoot.value = bzero(32);
    this.depositChain.value = bzero(32);
    this.settledDepositChain.value = bzero(32);
    this.depositCursor.value = 0;
    this.settledDepositCursor.value = 0;
  }

  /**
   * Move ALGO into the rollup, crediting `recipient` on L2.
   *
   * The payment and this call go in one group: the app takes custody of real ALGO, and the chain
   * fold below is the receipt. Nothing is credited on L2 here -- a deposit becomes a balance only
   * when a batch containing the matching rollup transaction settles, and `verifyBatch` will not
   * accept a batch whose deposits are not exactly these, in exactly this order.
   *
   * Two guarantees that compose and should not be confused. The `assertMatch` is what makes the
   * ALGO real: without it the chain would attest to a deposit nobody funded. The chain is what
   * makes the credit honest: without it a sequencer could mint a balance L1 never saw.
   *
   * Note what is *not* asserted: that no batch is open. Deposits stay accepted throughout, because
   * the chain is copied at `openBatch` rather than reset -- so one arriving mid-batch simply
   * belongs to the next one. Refusing them would mean a stuck batch could block deposits forever.
   *
   * The payment must exceed `DEPOSIT_BOX_MBR`, and the excess is what gets credited. `rekeyTo` and
   * `closeRemainderTo` are pinned to zero because either would hand the app away or drain it.
   *
   * **`recipient` is an L2 address, not an Algorand address.** It is `sha256("ADDR" || scheme ||
   * pub_key)`, the same derivation `address_from_public_key` performs; use the `l2Address` helper
   * exported alongside the client. Passing an Algorand address here credits an account no key
   * controls, and the funds are gone. The contract cannot tell the difference, and deliberately
   * knows nothing about how L2 addresses are derived.
   *
   * **There is no forced exit.** A sequencer that stops posting strands every pending deposit, and
   * nothing here can get it back. That is a smaller hole than the one `verifyBatch` still has --
   * the proof is not checked, so a sequencer that lies is unconstrained, never mind one that stops
   * -- and a correct forced exit is a withdrawal, which does not exist yet. `payer` and `round` are
   * recorded against the day it does.
   *
   * @returns The nonce the deposit was filed under, which is also its position in the chain.
   */
  deposit(payment: gtxn.PaymentTxn, recipient: bytes<32>): uint64 {
    assertMatch(
      payment,
      {
        receiver: Global.currentApplicationAddress,
        closeRemainderTo: Global.zeroAddress,
        rekeyTo: Global.zeroAddress,
        amount: { greaterThan: DEPOSIT_BOX_MBR },
      },
      "the deposit must pay this app more than the box minimum balance",
    );

    const amount: uint64 = payment.amount - DEPOSIT_BOX_MBR;
    const nonce = this.depositCursor.value;

    this.deposits(nonce).value = {
      recipient: recipient,
      amount: amount,
      payer: payment.sender,
      round: Global.round,
    };

    // Mirrors `accumulate_deposit`. Only the two fields the guest can reconstruct from the batch
    // bytes are hashed: an L1 nonce or `payer` would have to be carried on the wire forever to buy
    // something the chaining already provides.
    this.depositChain.value = sha256(
      Bytes("DEPOSIT")
        .concat(this.depositChain.value)
        .concat(recipient)
        .concat(itob(amount)),
    );
    this.depositCursor.value = nonce + 1;

    return nonce;
  }

  /**
   * Delete a settled deposit's box and return its minimum balance to whoever paid it.
   *
   * Permissionless, because there is nothing to abuse: the nonce must be below
   * `settledDepositCursor`, so only a deposit the chain has already accounted for can be pruned,
   * and the refund goes to the recorded `payer` rather than the caller. Deleting the box drops the
   * app's own minimum balance by exactly the amount being sent, so the two cancel and the app
   * neither gains nor loses. The caller covers the inner transaction's fee.
   */
  pruneDeposit(nonce: uint64): void {
    assert(
      nonce < this.settledDepositCursor.value,
      "a deposit cannot be pruned before the batch that consumed it has settled",
    );

    const payer = this.deposits(nonce).value.payer;
    this.deposits(nonce).delete();

    itxn
      .payment({
        receiver: payer,
        amount: DEPOSIT_BOX_MBR,
        fee: 0,
      })
      .submit();
  }

  /**
   * Throw away a batch that cannot settle, so the next one can be opened.
   *
   * `openBatch` refuses while a batch is in flight and only `verifyBatch` clears that, so without
   * this a batch that can never settle -- a mis-cut chunk, public values that do not line up --
   * wedges the contract permanently. Deposits make that materially likelier, since there is now a
   * second thing for a batch to disagree with.
   *
   * Three lines, and only possible because nothing was destroyed on the way in: `openBatch` copies
   * the deposit chain rather than resetting it, so abandoning is just forgetting the copy. A design
   * that reset the live chain per batch would have to splice deposits that arrived mid-batch back
   * onto a sealed chain, which cannot be done to a hash chain at all.
   *
   * Creator-gated: abandoning is harmless to the settled state but would let anyone cancel a batch
   * mid-post, which is pure griefing.
   */
  abandonBatch(): void {
    assert(
      Txn.sender === Global.creatorAddress,
      "only the creator may abandon",
    );
    assert(this.batchLength.hasValue, "no batch is being posted");

    this.chunkAccumulator.delete();
    this.batchLength.delete();
    this.postedLength.delete();
    this.sealedDepositChain.delete();
    this.sealedDepositCursor.delete();
  }

  /**
   * Start a batch, seeding the accumulator from the length its bytes are declared to have and
   * sealing the deposit chain the batch will have to fold to.
   *
   * Mirrors `chunk_accumulator_seed`.
   *
   * `expectedDepositCursor` is what the sequencer believed the queue length to be when it built the
   * batch. It is not needed for correctness -- `verifyBatch` compares the chain itself, and would
   * catch any disagreement -- but a deposit landing between the sequencer's snapshot and this call
   * would otherwise not be discovered until after every chunk had been posted and paid for. Eight
   * bytes and one assert turn that into a cheap failure here. An equal cursor implies an equal
   * chain because the queue is strictly append-only.
   *
   * The seal is a copy, not a move. Deposits arriving while this batch is in flight keep extending
   * `depositChain` past the sealed point and belong to the next batch.
   */
  openBatch(batchLength: uint64, expectedDepositCursor: uint64): void {
    // A second open would abandon a half-posted batch and start folding over its accumulator, so
    // a batch has to be finished before the next one begins. See `abandonBatch` for the way out.
    assert(!this.batchLength.hasValue, "a batch is already being posted");
    assert(
      this.depositCursor.value === expectedDepositCursor,
      "a deposit arrived after this batch was built",
    );

    this.chunkAccumulator.value = sha256(
      Bytes("BATCH").concat(itob(batchLength)),
    );
    this.batchLength.value = batchLength;
    this.postedLength.value = 0;

    // Written unconditionally, even with nothing pending -- `verifyBatch` compares it every time,
    // so `hasValue` must never become load-bearing here. Same discipline as `chunkAccumulator`.
    this.sealedDepositChain.value = this.depositChain.value;
    this.sealedDepositCursor.value = this.depositCursor.value;
  }

  /**
   * Fold one chunk into the accumulator.
   *
   * Mirrors `chunk_digest` composed with `accumulate_chunk`: the chunk is digested on its own,
   * untagged -- a chunk digest is only ever consumed inside the tagged preimage below, so it can
   * never be read as a seed or as an accumulator -- and the 69-byte fold step carries the tag.
   */
  accumulateChunk(chunk: Chunk): void {
    assert(this.batchLength.hasValue, "no batch is being posted");

    // Chunks are full until the last one, whose size the declared length pins. Checking it here
    // rejects a mis-cut chunk at the transaction that posted it, rather than as an accumulator
    // that silently fails to match a commitment several transactions later.
    const remaining: uint64 = this.batchLength.value - this.postedLength.value;
    let expected: uint64 = CHUNK_SIZE;
    if (remaining < CHUNK_SIZE) {
      expected = remaining;
    }
    assert(
      chunk.length === expected,
      "chunk is not the size its position allows",
    );

    this.chunkAccumulator.value = sha256(
      Bytes("CHUNK").concat(this.chunkAccumulator.value).concat(sha256(chunk)),
    );
    this.postedLength.value = this.postedLength.value + chunk.length;
  }

  /**
   * Settle a fully posted batch: check the proof against what the contract is holding, then advance
   * to what the proof landed on.
   *
   * Five things have to line up, and each one is load-bearing:
   *
   * - `publicValues[0..32]` against `stateRoot` -- the proof has to start where the chain is, so a
   *   valid proof of some other transition cannot be replayed here.
   * - `publicValues[64..96]` against the accumulator -- the proof only names the batch by its
   *   commitment, so this is what ties the transition to bytes the chain has actually recorded.
   *   Refusing to settle until the declared length has been posted in full is what makes the data
   *   available: stopping a chunk short leaves an accumulator that is not the commitment.
   * - `publicValues[96..128]` against `settledDepositChain` -- where the batch's deposits begin.
   * - `publicValues[128..160]` against `sealedDepositChain` -- where they end. Pinning both ends
   *   rather than just the last is what stops a prover choosing an anchor that makes a fabricated
   *   fold land correctly; with both fixed, the deposits between them are determined.
   * - the proof itself, over exactly those 160 bytes.
   *
   * The two deposit checks are together what make the batch's deposits exactly L1's: inventing,
   * dropping, reordering or altering one diverges the fold and never recovers. Note this needs no
   * special case for a batch with no deposits -- such a batch commits `new == old`, which settles
   * only if nothing is pending, because a pending deposit is precisely what makes the sealed chain
   * differ from the settled one.
   *
   * **None of that binds yet.** The proof is not verified -- see the TODO below -- and
   * `publicValues` is an ordinary argument, so a dishonest sequencer can read `sealedDepositChain`
   * straight out of global state and hand it back while the batch bytes say something else. The
   * chain is the right mechanism and becomes airtight the moment the verifier lands, with no
   * redesign; until then the sequencer is trusted here exactly as it is already trusted with
   * `stateRoot`. What does hold today is data availability: the accumulator forces the real bytes
   * on-chain, so the fraud is detectable by replay, just not preventable.
   *
   * No box is read here, and none should ever be. That is what keeps the cost of settling
   * independent of how many deposits are queued.
   */
  verifyBatch(publicValues: PublicValues): void {
    assert(this.batchLength.hasValue, "no batch is being posted");
    assert(
      this.postedLength.value === this.batchLength.value,
      "the batch is not fully posted",
    );

    const oldRoot = publicValues.slice(0, 32);
    const newRoot = publicValues.slice(32, 64);
    const batchCommitment = publicValues.slice(64, 96);
    const oldDepositChain = publicValues.slice(96, 128);
    const newDepositChain = publicValues.slice(128, 160);

    assert(
      oldRoot === this.stateRoot.value,
      "the proof does not start from the current root",
    );
    assert(
      batchCommitment === this.chunkAccumulator.value,
      "the proof is not for the batch that was posted",
    );
    assert(
      oldDepositChain === this.settledDepositChain.value,
      "the proof does not start from the settled deposit chain",
    );
    assert(
      newDepositChain === this.sealedDepositChain.value,
      "the batch does not credit exactly the deposits this contract accepted",
    );

    this.stateRoot.value = newRoot.toFixed({ length: 32 });
    this.settledDepositChain.value = this.sealedDepositChain.value;
    this.settledDepositCursor.value = this.sealedDepositCursor.value;

    // TODO: Actual ZK verification

    this.chunkAccumulator.delete();
    this.batchLength.delete();
    this.postedLength.delete();
    this.sealedDepositChain.delete();
    this.sealedDepositCursor.delete();
  }
}
