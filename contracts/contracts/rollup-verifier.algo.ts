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
  ed25519verifyBare,
  getBit,
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
 * The 256 bytes the guest commits:
 *
 * ```text
 * [  0.. 32)  old_root
 * [ 32.. 64)  new_root
 * [ 64.. 96)  batch_commitment
 * [ 96..128)  old_deposit_chain
 * [128..160)  new_deposit_chain
 * [160..192)  withdrawal_chain
 * [192..224)  old_request_chain
 * [224..256)  new_request_chain
 * ```
 *
 * Mirrors `public_values`. Nothing else escapes the proof, which is why the batch itself has to
 * arrive as chunks and be folded into a commitment the contract can compare against the third
 * word.
 *
 * The two pairs of chain ends are one mechanism aimed at two opposite failures. The deposit pair
 * makes a batch credit exactly what L1 accepted, so value cannot be minted. The request pair makes a
 * batch answer exactly the withdrawals L1 was told to force, so value cannot be trapped.
 *
 * `withdrawal_chain` is the odd one out: the only word this contract *stores* rather than checks.
 * The others are compared against values it already holds; this one is a claim about what the batch
 * authorized paying out, and it is checked later, one claim at a time, as the chain is unwound. See
 * `claimWithdrawal`.
 */
export type PublicValues = bytes<256>;

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
 * Minimum balance for one withdrawal queue box: `2500 + 400 * (key + value)`, over a 9-byte key
 * (`"w"` and an 8-byte batch number) and a 64-byte value.
 *
 * Advanced by whoever settles the batch and returned to them when the queue drains, so the app is
 * never out of pocket for holding a queue -- the same arrangement `DEPOSIT_BOX_MBR` makes for the
 * deposit side.
 */
const WITHDRAWAL_BOX_MBR = 31_700;

/**
 * Minimum balance for one exit record: `2500 + 400 * (key + value)`, over a 33-byte key (`"e"` and
 * a 32-byte rollup address) and an 8-byte value.
 *
 * Unlike the other two, this one is never returned. The box is a permanent record that an account
 * has been paid out, and it has to outlive the exit or the same account could be exited twice
 * against a state root that is frozen and will keep proving it.
 *
 * It is funded by withholding it from the exit itself rather than by a separate payment, which is
 * what makes the accounting close: the app pays out `amount - EXIT_BOX_MBR` and its own minimum
 * balance rises by exactly `EXIT_BOX_MBR`, so it ends up holding precisely what it is still
 * required to hold and not a microALGO more.
 */
const EXIT_BOX_MBR = 18_900;

/**
 * Minimum balance for one pending withdrawal request: `2500 + 400 * (key + value)`, over a 9-byte
 * key (`"r"` and an 8-byte nonce) and a 104-byte value.
 *
 * Advanced by the requester and returned by `pruneRequest` once the request has been answered, so
 * demanding an exit costs nothing but fees in the end.
 */
const REQUEST_BOX_MBR = 47_700;

/**
 * The one signature scheme a forced exit can check.
 *
 * Mirrors `Scheme::identifier` in the core crate. `"man"` is deliberately absent: a managed account
 * is one the sequencer signs for, so there is no key behind its `auth_address` and nothing a holder
 * could present here. `"f1h"` is absent because the hybrid Falcon encoding is not yet defined on the
 * Rust side -- the AVM has `falcon_verify`, so this becomes a small addition once it is, rather
 * than something to guess at now.
 */
const SCHEME_ED25519 = "edd";

/**
 * One pending deposit, exactly as much of it as anyone needs later.
 *
 * `recipient` and `amount` are the two fields the deposit chain commits to, and are what the
 * sequencer reads back to build a batch that folds to the same value. The other two carry the
 * escape hatch: `payer` is where a refund goes and `round` is the clock `signalEscape` reads.
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
   * payment, so a refund of any kind -- the minimum balance on `pruneDeposit`, the whole deposit on
   * `reclaimDeposit` -- has nowhere else to go.
   */
  payer: Account;
  /**
   * Round the deposit was accepted in.
   *
   * Read by `signalEscape`, and only ever for the oldest pending deposit. Nonces are handed out in
   * order and a round never goes backwards, so the head of the queue is the oldest thing waiting
   * and its age is the age of the censorship.
   */
  round: uint64;
};

/**
 * One batch's unclaimed payouts, held as the tip of a hash chain.
 *
 * There is no list of who is owed what, and there does not need to be one. Each claim is handed the
 * chain value standing immediately before its own fold; if folding the claim onto that value
 * reproduces `chain`, the claim was in the batch, and the value handed in becomes the new tip.
 * Paying a claim therefore consumes it -- the tip *is* the record of what is left, so there is no
 * separate nullifier and no per-withdrawal storage. The cost is that a queue unwinds newest-first.
 *
 * `chain` reaching 32 zero bytes means drained, unambiguously: getting back there any other way
 * would be a SHA-256 preimage of zero.
 */
type WithdrawalQueue = {
  /** Tip of the unclaimed remainder, mirroring `accumulate_withdrawal`. */
  chain: bytes<32>;
  /** Who advanced `WITHDRAWAL_BOX_MBR`, and gets it back when the queue drains. */
  funder: Account;
};

/**
 * One withdrawal the settlement chain has been asked to force, and has not yet seen answered.
 *
 * Filed here rather than handed to the sequencer, which is the entire point: a withdrawal the
 * sequencer is merely *asked* for can be dropped without anyone outside noticing, because L1 never
 * heard of it. One of these is folded into `requestChain`, and `verifyBatch` will not settle a batch
 * that has not consumed it -- so ignoring it is not censorship of one transaction, it is a refusal
 * to settle at all, which `signalEscape` already watches for.
 *
 * No amount, because a request does not name one: it empties the account. That is what makes forced
 * inclusion safe. A request for a specific sum can be unaffordable by the time the batch reaches it,
 * so a verifier would need a rule for what to do then -- and every such rule is a lever the
 * sequencer can pull. A request for the whole balance is always satisfiable.
 *
 * Fixed-width throughout, so the box is exactly 104 bytes.
 */
type RequestRecord = {
  /** The rollup account to empty. Not an Algorand address. */
  address: bytes<32>;
  /** The L1 account to pay. This one *is* an Algorand address. */
  recipient: Account;
  /** Who advanced `REQUEST_BOX_MBR`, and gets it back from `pruneRequest`. */
  requester: Account;
  /** Round the request was accepted in, and the second clock `signalEscape` reads. */
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
   * The fold over every withdrawal this contract has been asked to force, in the order it accepted
   * them.
   *
   * The deposit chain's mirror image, and the same mechanism pointed at the opposite failure. The
   * deposit chain stops a batch crediting value L1 never received; this one stops a batch *not*
   * paying out value L1 was told to release. Both work because the contract holds both ends and the
   * folds between two fixed points are determined.
   *
   * Without it, an ordinary withdrawal is a request the sequencer can silently decline forever
   * while settling everything else, and nothing on L1 would ever know.
   */
  requestChain = GlobalState<bytes<32>>();

  /** Nonce the next request will be filed under. Never reset; requests are strictly append-only. */
  requestCursor = GlobalState<uint64>();

  /** `requestChain` as of the last settled batch: the value the next batch has to anchor to. */
  settledRequestChain = GlobalState<bytes<32>>();

  /** First request nonce not yet answered. Everything below it is safe to prune. */
  settledRequestCursor = GlobalState<uint64>();

  /**
   * `requestChain` at the moment the open batch was opened, and the value it has to fold to.
   *
   * Copied rather than moved, exactly as `sealedDepositChain` is, so a request arriving mid-batch
   * belongs to the next one instead of invalidating the batch in flight.
   */
  sealedRequestChain = GlobalState<bytes<32>>();

  /** `requestCursor` at the same moment, and what `settledRequestCursor` becomes on settlement. */
  sealedRequestCursor = GlobalState<uint64>();

  /**
   * The pending queue, one box per request, keyed by nonce.
   *
   * Like `deposits`, kept out of the settlement path -- `openBatch`, `accumulateChunk` and
   * `verifyBatch` read no boxes, and adding requests must not change that. What they are for is
   * discovery: a sequencer needs the ordered pending list to build a batch that folds to the right
   * value, and a hash chain cannot be run backwards to recover it.
   */
  requests = BoxMap<uint64, RequestRecord>({ keyPrefix: "r" });

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
   * How many batches have settled, and so the number the next one takes.
   *
   * Only ever used to key a withdrawal queue. Monotonic and never reset, so two batches can never
   * share a box even if the first one's queue has already been drained and deleted.
   */
  batchNumber = GlobalState<uint64>();

  /**
   * Unclaimed payouts, one box per settled batch that had any.
   *
   * Per batch rather than one queue for the whole rollup, and that follows from the chain being
   * unwound: a pointer walking backwards cannot live on a value that settlement keeps pushing
   * forwards. Giving each batch its own chain -- anchored at zero every time, unlike the deposit
   * chain -- makes the queues independent, so a claim against one batch neither blocks nor is
   * blocked by another.
   *
   * Like `deposits`, deliberately outside the settlement path in the sense that matters: settling
   * touches at most this one box, whatever the batch withdrew, so the cost of settling still does
   * not depend on how much is queued.
   */
  withdrawals = BoxMap<uint64, WithdrawalQueue>({ keyPrefix: "w" });

  /**
   * Rollup addresses that have already been paid out by `forceExit`, and what each was paid.
   *
   * A nullifier, and it has to be one: after an escape the state root never moves again, so the
   * Merkle proof that an account holds a balance stays valid forever and would otherwise authorize
   * an unlimited number of identical payouts. Unlike a withdrawal queue -- where the chain tip is
   * consumed by the claim and so records itself -- a Merkle proof is not consumed by being used,
   * and the record has to be kept explicitly.
   *
   * Never deleted, for the same reason. The value is what was paid, which makes the boxes an
   * auditable record of where the app's balance went rather than a bare set of flags.
   */
  exits = BoxMap<bytes<32>, uint64>({ keyPrefix: "e" });

  /**
   * The escape hatch has been pulled. Set once and never cleared.
   *
   * Everything that moves the rollup forward -- `deposit`, `openBatch`, `verifyBatch` -- refuses
   * from here on, so `stateRoot` is final and the deposit queue can never be consumed by a batch.
   * That is what makes the pending suffix safe to refund in `reclaimDeposit`, and it is the
   * precondition a forced exit against the frozen root will need.
   *
   * One-way deliberately. A recoverable flush would have to distinguish a nonce voided by an
   * escape from one consumed by a batch, and with the sequencer free to resume between escapes
   * those ranges interleave -- there is no cursor comparison that separates them. Terminal means
   * there is only ever one voided range, and `nonce >= settledDepositCursor` names it exactly.
   */
  escaped = GlobalState<boolean>();

  /**
   * Round `executeEscape` becomes callable, once `signalEscape` has found a stale deposit.
   *
   * `hasValue` doubles as "an escape has been signalled", the same idiom `batchLength` uses for "a
   * batch is being posted". Deleted by `executeEscape`, and by `verifyBatch` -- a settlement is
   * proof of liveness and withdraws the accusation.
   */
  escapeDeadline = GlobalState<uint64>();

  /**
   * Rounds the oldest pending deposit may age before it counts as evidence the sequencer has
   * stopped.
   *
   * Set at creation rather than compiled in, for two reasons. There is no `UpdateApplication`
   * handler, so a baked-in constant could never be retuned. And the e2e has to be able to cross
   * this threshold -- a production value is hundreds of thousands of rounds, which no test can
   * generate, so the test deploys with a handful.
   */
  depositTimeout = GlobalState<uint64>();

  /**
   * Rounds between `signalEscape` and `executeEscape`.
   *
   * The grace period is what stops a signal from voiding a nearly-complete batch the instant the
   * timeout ticks over: a sequencer that is merely slow gets one more window to land a settlement,
   * and landing one clears the signal outright.
   */
  escapeGrace = GlobalState<uint64>();

  /**
   * Genesis: the empty ledger.
   *
   * `EMPTY_SUBTREE` in the tree is 32 zero bytes and an empty sparse tree hashes to it, so a
   * ledger with no accounts in it is the root below. Starting anywhere else would be claiming a
   * state no batch had ever proved its way to.
   *
   * The two escape parameters are arguments because they are the one thing about this contract a
   * deployment legitimately needs to choose. Both are measured in rounds; at roughly 2.8 seconds a
   * round, a week is about 216,000 and a day about 31,000. Setting them too low hands a griefer a
   * halt; too high, and a depositor waits that long to get their money back.
   */
  createApplication(depositTimeout: uint64, escapeGrace: uint64): void {
    this.stateRoot.value = bzero(32);
    this.depositChain.value = bzero(32);
    this.settledDepositChain.value = bzero(32);
    this.depositCursor.value = 0;
    this.settledDepositCursor.value = 0;

    this.requestChain.value = bzero(32);
    this.settledRequestChain.value = bzero(32);
    this.requestCursor.value = 0;
    this.settledRequestCursor.value = 0;

    this.escaped.value = false;
    this.depositTimeout.value = depositTimeout;
    this.escapeGrace.value = escapeGrace;
    this.batchNumber.value = 0;
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
   * A sequencer that stops posting strands every deposit that arrives after it does. The way out
   * is `signalEscape` / `executeEscape`, after which `reclaimDeposit` refunds this payment in full
   * to `payment.sender`; that is what `payer` and `round` are recorded for. Note the remedy is a
   * refund rather than a forced inclusion, and it has to be: a pending deposit already *cannot* be
   * skipped by a batch -- `verifyBatch` compares the fold -- so there is nothing to force. The only
   * failure this contract has to survive is the sequencer going away entirely.
   *
   * Refused once the escape has been executed. New money must not enter a rollup whose root can
   * never advance again.
   *
   * @returns The nonce the deposit was filed under, which is also its position in the chain.
   */
  deposit(payment: gtxn.PaymentTxn, recipient: bytes<32>): uint64 {
    assert(!this.escaped.value, "the rollup has escaped");

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
   * Demand that the rollup let an account out, whether the sequencer likes it or not.
   *
   * This is what makes withdrawals censorship-resistant. An ordinary `Withdrawal` is an L2
   * transaction handed to the sequencer, and a sequencer that simply never includes it is
   * indistinguishable from a busy one -- L1 never heard of it, so nothing on L1 can notice. Filing
   * it here folds it into `requestChain`, and `verifyBatch` cannot reach the value this contract
   * holds unless the batch consumed it. From that point the sequencer has two options, honour it or
   * settle nothing at all, and settling nothing is what `signalEscape` is already watching for.
   *
   * **The whole balance leaves.** No amount is named. A request for a specific sum can be
   * unaffordable by the time a batch reaches it, and then a verifier needs a rule for what to do --
   * every such rule being a lever the sequencer could pull to make a request evaporate. Emptying is
   * always satisfiable, so the only judgement left is whether there is enough to be worth paying at
   * all, and the guest makes that against a witness pinned to the state root.
   *
   * Authorized by the key the account derives from: `sha256("ADDR" || scheme || pubKey)` has to
   * equal `address` itself. That is deliberately a weaker check than `forceExit`'s, which tests the
   * `auth_address` out of a proven leaf and so would honour a rekey. This one has no leaf to read --
   * L1 knows only the state root, and a proof against it would be stale the moment a batch settled.
   * The two agree today because the state machine has no rekey transaction, so every account
   * reachable from genesis is authorized by its own address. **If a rekey kind is ever added, this
   * must grow an inclusion proof of `auth_address` or it will lock out rekeyed accounts.**
   *
   * `expectedNonce` is in the signature, so a signature authorizes one request and not a stream of
   * replays of it. It is asserted here for the same reason `openBatch` asserts its cursor: a request
   * that landed first should fail cheaply rather than produce a confusing signature error.
   *
   * @returns The nonce the request was filed under, which is also its position in the chain.
   */
  requestWithdrawal(
    payment: gtxn.PaymentTxn,
    expectedNonce: uint64,
    address: bytes<32>,
    recipient: Account,
    scheme: bytes<3>,
    pubKey: bytes<32>,
    signature: bytes<64>,
  ): uint64 {
    assert(!this.escaped.value, "the rollup has escaped");
    assertMatch(
      payment,
      {
        receiver: Global.currentApplicationAddress,
        closeRemainderTo: Global.zeroAddress,
        rekeyTo: Global.zeroAddress,
        amount: REQUEST_BOX_MBR,
      },
      "the request must cover its box minimum balance exactly",
    );

    const nonce = this.requestCursor.value;
    assert(nonce === expectedNonce, "a request arrived first");

    assert(scheme === Bytes(SCHEME_ED25519), "unsupported signature scheme");
    assert(
      sha256(Bytes("ADDR").concat(scheme).concat(pubKey)) === address,
      "the key does not derive this account",
    );
    assert(
      ed25519verifyBare(
        Bytes("WREQ")
          .concat(itob(Global.currentApplicationId.id))
          .concat(itob(nonce))
          .concat(address)
          .concat(recipient.bytes),
        signature,
        pubKey,
      ),
      "the request is not signed by the account's key",
    );

    this.requests(nonce).value = {
      address: address,
      recipient: recipient,
      requester: payment.sender,
      round: Global.round,
    };

    // Mirrors `accumulate_request`. No amount, for the reason above; no requester and no round, for
    // the reason `accumulate_deposit` omits its own -- the guest has to be able to rebuild every
    // field of this preimage from the batch bytes alone.
    this.requestChain.value = sha256(
      Bytes("REQUEST")
        .concat(this.requestChain.value)
        .concat(address)
        .concat(recipient.bytes),
    );
    this.requestCursor.value = nonce + 1;

    return nonce;
  }

  /**
   * Delete an answered request's box and return its minimum balance to whoever paid it.
   *
   * Permissionless, like `pruneDeposit`, and for the same reasons: only a request the chain has
   * already accounted for can be pruned, and the refund goes to the recorded `requester` rather than
   * the caller.
   *
   * Also allowed once the rollup has escaped, whatever the cursor says. An unanswered request is
   * exactly what an escape means -- the account is still on L2 and comes out through `forceExit`
   * instead -- so there is nothing left for the box to be waiting for.
   */
  pruneRequest(nonce: uint64): void {
    assert(
      nonce < this.settledRequestCursor.value || this.escaped.value,
      "a request cannot be pruned before the batch that answered it has settled",
    );

    const requester = this.requests(nonce).value.requester;
    this.requests(nonce).delete();

    itxn
      .payment({ receiver: requester, amount: REQUEST_BOX_MBR, fee: 0 })
      .submit();
  }

  /**
   * Delete a settled deposit's box and return its minimum balance to whoever paid it.
   *
   * Permissionless, because there is nothing to abuse: the nonce must be below
   * `settledDepositCursor`, so only a deposit the chain has already accounted for can be pruned,
   * and the refund goes to the recorded `payer` rather than the caller. Deleting the box drops the
   * app's own minimum balance by exactly the amount being sent, so the two cancel and the app
   * neither gains nor loses. The caller covers the inner transaction's fee.
   *
   * Still callable after an escape: a deposit below `settledDepositCursor` was consumed by a batch
   * that settled, so its box is stale bookkeeping either way.
   *
   * `DEPOSIT_BOX_MBR` is below the network's own minimum balance, so this fails if `payer` has
   * since closed their account. Self-healing rather than fatal -- the payer refunds their account
   * and anyone can then prune -- and it costs the app nothing to leave the box sitting there.
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
   * Refund a deposit the rollup will now never credit, once the escape has been executed.
   *
   * The counterpart to `pruneDeposit`, and the two together partition the queue: below
   * `settledDepositCursor` a deposit was consumed by a settled batch and only its box minimum
   * balance is owed, at or above it the deposit was never credited on L2 and the whole payment is.
   * The boundary is exact because a batch settles every deposit pending when it was opened, so the
   * unsettled deposits are always a contiguous suffix.
   *
   * That suffix is the only thing `escaped` has to be terminal for. While the sequencer can still
   * settle, "not yet credited" is a statement about right now; once it can't, it is permanent, and
   * a bare cursor comparison is enough to decide who is owed what. Nothing is written to the
   * deposit chain here and nothing needs to be -- with `verifyBatch` refusing forever, the chain is
   * dead state, and rewinding it would only be a second thing to keep consistent.
   *
   * Permissionless and in any order, like `pruneDeposit`: the refund goes to the recorded `payer`,
   * so the caller can only pay a fee on someone else's behalf. The payment covers the deposit and
   * the box minimum balance together, and deleting the box drops the app's own minimum balance by
   * that second part, so the app is left holding exactly the L2 balances it still owes.
   */
  reclaimDeposit(nonce: uint64): void {
    assert(
      this.escaped.value,
      "deposits can only be reclaimed after an escape",
    );
    assert(
      nonce >= this.settledDepositCursor.value,
      "this deposit was credited by a batch that settled",
    );
    assert(nonce < this.depositCursor.value, "no such deposit");

    const payer = this.deposits(nonce).value.payer;
    const amount = this.deposits(nonce).value.amount;
    this.deposits(nonce).delete();

    itxn
      .payment({
        receiver: payer,
        amount: amount + DEPOSIT_BOX_MBR,
        fee: 0,
      })
      .submit();
  }

  /**
   * Pay out one withdrawal from a settled batch's queue, and consume it.
   *
   * The queue is a hash chain and this unwinds it by one step. The caller supplies the value that
   * stood immediately before this withdrawal was folded in; if folding the claim onto that value
   * reproduces the tip the box is holding, the withdrawal really was in that batch, and the value
   * supplied becomes the new tip. Everything a caller needs is already on-chain -- the batch bytes
   * were posted in full before the batch could settle -- so the chain values are re-derivable by
   * anyone, not privileged knowledge held by the sequencer.
   *
   * Consuming and paying are the same step, which is what makes a second claim of the same
   * withdrawal impossible: the tip has moved past it and the fold no longer reproduces anything.
   * There is no nullifier to check and nothing stored per withdrawal.
   *
   * Claims run newest-first, and that is the price of the chain: unwinding is the only direction a
   * hash can be followed. It costs nothing in practice because this is permissionless and the
   * payout goes to the recipient the batch named -- so a claimer can only spend fees on someone
   * else's behalf, and anyone wanting their own payout can walk the queue down to it.
   *
   * Deliberately callable after an escape. These funds left L2 in a batch that settled; the rollup
   * halting afterwards does not unmake that.
   *
   * `MIN_WITHDRAWAL` in the guest is what makes the inner payment safe: below the network minimum
   * balance a payment to an account that does not yet exist fails, and a failure here would strand
   * every withdrawal queued behind this one.
   */
  claimWithdrawal(
    batchNumber: uint64,
    recipient: Account,
    amount: uint64,
    previousChain: bytes<32>,
  ): void {
    // Mirrors `accumulate_withdrawal`. Reproducing the tip is the whole authorization: it proves
    // this exact payout, at this exact position, was in the batch that settled.
    const folded = sha256(
      Bytes("WITHDRAW")
        .concat(previousChain)
        .concat(recipient.bytes)
        .concat(itob(amount)),
    );
    assert(
      folded === this.withdrawals(batchNumber).value.chain,
      "this is not the next unclaimed withdrawal of that batch",
    );

    itxn.payment({ receiver: recipient, amount: amount, fee: 0 }).submit();

    if (previousChain === bzero(32)) {
      // The queue is drained. Deleting the box drops the app's minimum balance by exactly what is
      // being returned, so the app neither gains nor loses.
      const funder = this.withdrawals(batchNumber).value.funder;
      this.withdrawals(batchNumber).delete();

      itxn
        .payment({ receiver: funder, amount: WITHDRAWAL_BOX_MBR, fee: 0 })
        .submit();
    } else {
      this.withdrawals(batchNumber).value.chain = previousChain;
    }
  }

  /**
   * Pay out an L2 balance against the frozen state root, on the holder's own authority.
   *
   * This is the escape hatch proper. `reclaimDeposit` rescues money that never made it into the
   * rollup; this rescues money that did. It needs no cooperation from anyone -- the state root is
   * final, the proof is checkable here, and the only permission it asks for is a signature from the
   * key the account itself names.
   *
   * Three independent things are established, and none of them substitutes for another:
   *
   * - **The account is real.** `siblings` is hashed up from the leaf and has to reproduce
   *   `stateRoot`. Only the inclusion case is accepted, which is why there is no counterpart to the
   *   `Slot::Neighbor` handling in `root_from_proof`: an account that exists always proves through
   *   its own position, and an account that does not exist has no balance to pay out.
   * - **The caller holds it.** `scheme` and `pubKey` have to hash to the `auth_address` in the very
   *   leaf just proven, and the signature has to check out under that key. Proving the leaf says
   *   what the balance is; the signature says who may move it.
   * - **It has not been paid already.** A frozen root proves the same leaf forever, so `exits` is
   *   what makes this once-only.
   *
   * The signed message names this application, so a signature cannot be carried to another
   * deployment where the same key controls the same address.
   *
   * `amount` must exceed `EXIT_BOX_MBR`, which is withheld to pay for the permanent record. An
   * account holding less than that costs more to write off than it is worth and cannot be exited --
   * the honest statement of a real limit, rather than a payout that quietly underflows.
   *
   * @param address The rollup address being exited, and the position in the tree being proven.
   * @param nonce Together with `amount` and `authAddress`, the account as the leaf commits to it.
   * @param siblings The proof path, `32 * depth` bytes, ordered root-first as `MerkleProof` holds
   *   them. Its length is the depth -- there is no separate field, and none is needed, because a
   *   path of the wrong length simply fails to reproduce the root.
   */
  forceExit(
    address: bytes<32>,
    nonce: uint64,
    amount: uint64,
    authAddress: bytes<32>,
    scheme: bytes<3>,
    pubKey: bytes<32>,
    signature: bytes<64>,
    recipient: Account,
    siblings: bytes,
  ): void {
    assert(this.escaped.value, "the rollup has not escaped");
    assert(!this.exits(address).exists, "this account has already exited");
    assert(
      amount > EXIT_BOX_MBR,
      "the balance does not cover the cost of recording the exit",
    );

    // Mirrors `address_from_public_key`. Checking the key against the account's own `auth_address`
    // -- rather than against `address` -- is what lets a rekeyed account still be exited by
    // whoever it was rekeyed to.
    assert(scheme === Bytes(SCHEME_ED25519), "unsupported signature scheme");
    assert(
      sha256(Bytes("ADDR").concat(scheme).concat(pubKey)) === authAddress,
      "the key does not control this account",
    );
    assert(
      ed25519verifyBare(
        Bytes("EXIT")
          .concat(itob(Global.currentApplicationId.id))
          .concat(address)
          .concat(recipient.bytes),
        signature,
        pubKey,
      ),
      "the exit is not signed by the account's key",
    );

    // Mirrors `leaf_hash`: the whole address is committed to, so a leaf cannot be relocated.
    let current = sha256(
      Bytes("LEAF")
        .concat(address)
        .concat(itob(nonce))
        .concat(itob(amount))
        .concat(authAddress),
    );

    // Mirrors the fold at the end of `root_from_proof`. `getBit` on a byte string counts from the
    // most significant bit of the first byte, which is exactly what `bit_at` does, so the two walk
    // the same path down the same tree.
    assert(
      siblings.length % 32 === 0,
      "the proof is not a whole number of siblings",
    );
    const depth: uint64 = siblings.length / 32;
    assert(depth <= 256, "the proof is deeper than the address space allows");

    for (let level: uint64 = depth; level > 0; level = level - 1) {
      const sibling = siblings.slice((level - 1) * 32, level * 32);

      // A zero bit means the path went left, so the proven subtree is the left child.
      current = getBit(address, level - 1)
        ? sha256(Bytes("NODE").concat(sibling).concat(current))
        : sha256(Bytes("NODE").concat(current).concat(sibling));
    }

    assert(
      current === this.stateRoot.value,
      "the account does not prove against the settled root",
    );

    this.exits(address).value = amount;

    itxn
      .payment({
        receiver: recipient,
        amount: amount - EXIT_BOX_MBR,
        fee: 0,
      })
      .submit();
  }

  /**
   * Do nothing, so that this transaction's opcode allowance can be spent by another one.
   *
   * The AVM gives each application call in a group 700 opcodes and pools them across the group, so
   * a call that needs more than its own share borrows from calls that need none. `forceExit` needs
   * that: `ed25519verify_bare` alone costs 1900, and the Merkle fold adds 35 per level on top.
   *
   * `nonce` is not read. It is there because two otherwise identical calls in one group would be
   * the same transaction, and the network rejects that -- so each filler needs one field that
   * differs, and this is the cheapest one to vary.
   *
   * Costs a fee and nothing else. There is no state it can touch and no assertion it can trip.
   */
  opUp(nonce: uint64): void {}

  /**
   * Accuse the sequencer of having stopped, by pointing at something it has left sitting.
   *
   * Two queues can accuse it, and they catch different failures. A stale **deposit** means value is
   * stuck outside the rollup. A stale **withdrawal request** means value is stuck inside it -- and
   * that is the one a selective censor would otherwise walk straight through, because a sequencer
   * that keeps crediting deposits while quietly declining to let anyone out keeps the deposit queue
   * spotless forever.
   *
   * Either queue's head is enough, and the head is the right thing to read: nonces are handed out
   * in round order, so nothing pending is older, and the head box is always present -- pruning only
   * reaches nonces below the settled cursor. Both share `depositTimeout`, because both mean the same
   * thing about the sequencer.
   *
   * These are the only box reads outside the settlement path, and they stay outside it: `openBatch`,
   * `accumulateChunk` and `verifyBatch` still read none, which is what keeps the cost of settling
   * independent of how much is queued.
   *
   * Permissionless, because the accusation is checkable and the answer to it is cheap: settle a
   * batch. `verifyBatch` clears the signal, so a sequencer that is merely slow loses nothing but
   * the fee someone else paid to file this.
   */
  signalEscape(): void {
    assert(!this.escaped.value, "the rollup has already escaped");
    assert(
      !this.escapeDeadline.hasValue,
      "an escape has already been signalled",
    );

    const depositsPending =
      this.settledDepositCursor.value < this.depositCursor.value;
    const requestsPending =
      this.settledRequestCursor.value < this.requestCursor.value;
    assert(depositsPending || requestsPending, "nothing is pending");

    let stale = false;
    if (depositsPending) {
      const head = this.deposits(this.settledDepositCursor.value).value.round;
      stale = Global.round > head + this.depositTimeout.value;
    }
    if (!stale && requestsPending) {
      const head = this.requests(this.settledRequestCursor.value).value.round;
      stale = Global.round > head + this.depositTimeout.value;
    }
    assert(stale, "nothing has been waiting long enough");

    this.escapeDeadline.value = Global.round + this.escapeGrace.value;
  }

  /**
   * Pull the escape hatch, once the grace period has run out with no settlement.
   *
   * From here `deposit`, `openBatch` and `verifyBatch` refuse permanently, `stateRoot` is final,
   * and every pending deposit is refundable through `reclaimDeposit`.
   *
   * Any open batch is discarded on the way, the same five keys `abandonBatch` deletes. Doing it
   * here rather than requiring the creator to go first matters: the whole premise is that the
   * sequencer is gone, so a path that needs the sequencer's cooperation is not an escape hatch.
   *
   * Permissionless. There is nothing left to gate -- the deadline is the authorization, and it can
   * only have been set by a deposit that really did go unanswered for `depositTimeout` rounds and
   * then `escapeGrace` more.
   */
  executeEscape(): void {
    assert(!this.escaped.value, "the rollup has already escaped");
    assert(this.escapeDeadline.hasValue, "no escape has been signalled");
    assert(
      Global.round > this.escapeDeadline.value,
      "the grace period has not run out",
    );

    this.escaped.value = true;
    this.escapeDeadline.delete();

    if (this.batchLength.hasValue) {
      this.chunkAccumulator.delete();
      this.batchLength.delete();
      this.postedLength.delete();
      this.sealedDepositChain.delete();
      this.sealedDepositCursor.delete();
      this.sealedRequestChain.delete();
      this.sealedRequestCursor.delete();
    }
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
    this.sealedRequestChain.delete();
    this.sealedRequestCursor.delete();
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
  openBatch(
    batchLength: uint64,
    expectedDepositCursor: uint64,
    expectedRequestCursor: uint64,
  ): void {
    assert(!this.escaped.value, "the rollup has escaped");
    // A second open would abandon a half-posted batch and start folding over its accumulator, so
    // a batch has to be finished before the next one begins. See `abandonBatch` for the way out.
    assert(!this.batchLength.hasValue, "a batch is already being posted");
    assert(
      this.depositCursor.value === expectedDepositCursor,
      "a deposit arrived after this batch was built",
    );
    assert(
      this.requestCursor.value === expectedRequestCursor,
      "a withdrawal request arrived after this batch was built",
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
    this.sealedRequestChain.value = this.requestChain.value;
    this.sealedRequestCursor.value = this.requestCursor.value;
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
   *
   * Settling also answers a pending `signalEscape`, because a batch consumes every deposit that
   * was pending when it was opened -- so afterwards nothing in the queue is older than that open,
   * and the accusation is stale by construction. `openBatch` deliberately does *not* clear it:
   * otherwise a sequencer could hold the escape off indefinitely by parking an open batch it never
   * intends to finish, which is exactly the failure being escaped from.
   */
  verifyBatch(publicValues: PublicValues): void {
    assert(!this.escaped.value, "the rollup has escaped");
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
    const withdrawalChain = publicValues.slice(160, 192);
    const oldRequestChain = publicValues.slice(192, 224);
    const newRequestChain = publicValues.slice(224, 256);

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
    assert(
      oldRequestChain === this.settledRequestChain.value,
      "the proof does not start from the settled request chain",
    );

    assert(
      newRequestChain === this.sealedRequestChain.value,
      "the batch does not answer exactly the withdrawal requests this contract accepted",
    );

    this.stateRoot.value = newRoot.toFixed({ length: 32 });
    this.settledDepositChain.value = this.sealedDepositChain.value;
    this.settledDepositCursor.value = this.sealedDepositCursor.value;
    this.settledRequestChain.value = this.sealedRequestChain.value;
    this.settledRequestCursor.value = this.sealedRequestCursor.value;

    // A batch that withdrew nothing folds to the genesis value and opens no queue, so the common
    // case costs one comparison and no box. Otherwise the tip goes into a box of its own, and the
    // minimum balance for it comes from a payment immediately before this call -- taken from the
    // group rather than the argument list so a settlement with no withdrawals is not made to carry
    // a funding transaction it has no use for.
    if (withdrawalChain !== bzero(32)) {
      assert(
        Txn.groupIndex > 0,
        "a batch with withdrawals must be funded for its queue box",
      );
      const funding = gtxn.PaymentTxn(Txn.groupIndex - 1);
      assertMatch(
        funding,
        {
          receiver: Global.currentApplicationAddress,
          closeRemainderTo: Global.zeroAddress,
          rekeyTo: Global.zeroAddress,
          amount: WITHDRAWAL_BOX_MBR,
        },
        "the withdrawal queue box must be funded with exactly its minimum balance",
      );

      this.withdrawals(this.batchNumber.value).value = {
        chain: withdrawalChain.toFixed({ length: 32 }),
        funder: funding.sender,
      };
    }

    this.batchNumber.value = this.batchNumber.value + 1;

    // TODO: Actual ZK verification

    this.chunkAccumulator.delete();
    this.batchLength.delete();
    this.postedLength.delete();
    this.sealedDepositChain.delete();
    this.sealedDepositCursor.delete();
    this.sealedRequestChain.delete();
    this.sealedRequestCursor.delete();

    // Unconditional: deleting a key that was never set is a no-op, and making this depend on
    // `hasValue` would only add a branch to the common path where nothing has been signalled.
    this.escapeDeadline.delete();
  }
}
