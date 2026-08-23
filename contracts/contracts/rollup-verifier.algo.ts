import {
  arc4,
  assert,
  assertMatch,
  BoxMap,
  bytes,
  Bytes,
  clone,
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
 * The 192 bytes the guest commits:
 *
 * ```text
 * [  0.. 32)  old_root
 * [ 32.. 64)  new_root
 * [ 64.. 96)  batch_commitment
 * [ 96..128)  old_inbox_chain
 * [128..160)  new_inbox_chain
 * [160..192)  withdrawal_chain
 * ```
 *
 * Mirrors `public_values`. Nothing else escapes the proof, which is why the batch itself has to
 * arrive as chunks and be folded into a commitment the contract can compare against the third
 * word.
 *
 * The inbox-chain pair binds the batch to one FIFO prefix containing both deposits and forced
 * withdrawals. It therefore prevents both minting value L1 never received and skipping an exit L1
 * was told to force.
 *
 * The withdrawal chain is the odd one out: the contract stores rather than compares it. It claims
 * what the batch authorized paying out, and is then spent one payout at a time by `payWithdrawal`
 * until it reaches `withdrawalTerminal()`. There is no count beside it because the chain carries
 * one: reaching the terminal is what says there are no more.
 */
export type PublicValues = bytes<192>;

/**
 * Minimum balance the network charges for one inbox box: `2500 + 400 * (key + value)`, over a
 * 9-byte key (`"i"` and an 8-byte index) and a 145-byte value.
 *
 * The depositor funds it as part of their payment and gets it back from `pruneDeposit` once the
 * deposit has settled, so a deposit costs nothing but fees in the end and the app never subsidises
 * one. Spam is paid for by the spammer for as long as it sits in the queue.
 */
const INBOX_BOX_MBR = 64_100;

/**
 * Obligations the rollup must discharge to earn one escape grace extension.
 *
 * An obligation is one unit of work L1 can see the sequencer owe and then see it do: one inbox entry
 * consumed by a settlement, or one payout made from a settled batch's chain. The two are counted
 * against the same tranche deliberately -- they are the two directions of the same duty, and the
 * watchdog has no business caring which one the sequencer is currently discharging.
 */
const ESCAPE_PROGRESS_TRANCHE = 256;

/**
 * Minimum balance for one exit record: `2500 + 400 * (key + value)`, over a 33-byte key (`"e"` and
 * a 32-byte rollup address) and an 8-byte value.
 *
 * Unlike the refundable queues, this one is never returned. The box is a permanent record that an
 * account has been paid out, and it has to outlive the exit or the same account could be exited
 * twice against a state root that is frozen and will keep proving it.
 *
 * It is funded by withholding it from the exit itself rather than by a separate payment, which is
 * what makes the accounting close: the app pays out `amount - EXIT_BOX_MBR` and its own minimum
 * balance rises by exactly `EXIT_BOX_MBR`, so it ends up holding precisely what it is still
 * required to hold and not a microALGO more.
 */
const EXIT_BOX_MBR = 18_900;

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
 * One unified L1 inbox entry, exactly as much of it as anyone needs later.
 *
 * `kind` distinguishes a deposit (`"d"`) from a forced withdrawal (`"w"`). `address` is the L2
 * deposit recipient or withdrawal account; `recipient` is zero for a deposit; and `amount` is zero
 * for a request. `payer` receives the refundable box minimum balance, while `round` is the escape
 * clock.
 *
 * `chainAfter` checkpoints the append-only inbox chain so `openBatch` can select a bounded FIFO
 * prefix. Fixed-width throughout, so the box is exactly 145 bytes.
 */
type InboxRecord = {
  kind: bytes<1>;
  /** The L2 address to credit or empty. Not an Algorand address. */
  address: bytes<32>;
  /** The withdrawal's L1 recipient, or zero for a deposit. */
  recipient: Account;
  /** Deposit amount, or zero for a withdrawal request. */
  amount: uint64;
  /** The L1 account that funded the box and receives its refund. */
  payer: Account;
  /** Round the entry was accepted. */
  round: uint64;
  /** Inbox-chain value immediately after this entry was appended. */
  chainAfter: bytes<32>;
};

/** The network- and application-specific domain shared with the guest and signing clients. */
function deploymentDomain(): bytes<32> {
  return sha256(
    Bytes("PAYMENT_ROLLUP_V1")
      .concat(Global.genesisHash)
      .concat(itob(Global.currentApplicationId.id)),
  );
}

/**
 * Where a batch's payout chain ends, and so the value `pendingWithdrawals` drains to.
 *
 * Mirrors `withdrawal_chain_terminal`. Recomputed rather than stored, which is the whole reason it
 * is bound to the deployment domain instead of to the batch: a batch-bound terminal would have to
 * be held in a global of its own, because the commitment it would come from is deleted the instant
 * the batch settles. Nothing is lost by that. The chain head only ever enters state from a
 * settlement's public values, never from a caller, so there is no other batch's chain to be spliced
 * onto this one and nothing for batch-binding to prevent.
 */
function withdrawalTerminal(): bytes<32> {
  return sha256(Bytes("WEND").concat(deploymentDomain()));
}

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

  /** Append-only fold over every deposit and forced withdrawal, in their exact L1 arrival order. */
  inboxChain = GlobalState<bytes<32>>();

  /** Index assigned to the next inbox entry. */
  inboxCursor = GlobalState<uint64>();

  /** Inbox-chain anchor and exclusive cursor reached by the last settled batch. */
  settledInboxChain = GlobalState<bytes<32>>();
  settledInboxCursor = GlobalState<uint64>();

  /** Inbox-chain checkpoint and exclusive cursor selected for the open batch. */
  sealedInboxChain = GlobalState<bytes<32>>();
  sealedInboxCursor = GlobalState<uint64>();

  /** Signature replay nonce for forced withdrawals; inbox position is tracked separately. */
  requestCursor = GlobalState<uint64>();

  /** Unified FIFO inbox, keyed by the global inbox index. */
  inbox = BoxMap<uint64, InboxRecord>({ keyPrefix: "i" });

  /**
   * Head of the payout chain the last settled batch committed, or absent once it has drained.
   *
   * The debt the rollup has taken on and not yet discharged, in one word. `hasValue` doubles as
   * "payouts are outstanding" -- the same idiom `batchLength` uses for "a batch is being posted" --
   * and that is what `openBatch` refuses on, so a batch's payouts are always made before the next
   * batch begins.
   *
   * Written only here, out of a settlement's public values, and never from a caller's arguments --
   * which is what makes it safe for `payWithdrawal` to be permissionless.
   */
  pendingWithdrawals = GlobalState<bytes<32>>();

  /**
   * Rollup addresses that have already been paid out by `forceExit`, and what each was paid.
   *
   * A nullifier, and it has to be one: after an escape the state root never moves again, so the
   * Merkle proof that an account holds a balance stays valid forever and would otherwise authorize
   * an unlimited number of identical payouts. A settled batch's payouts are nullified by their
   * position in `pendingWithdrawals`, but an escape exit belongs to no batch and no chain, so each
   * needs a permanent record of its own.
   *
   * Never deleted, for the same reason. The value is what was paid, which makes the boxes an
   * auditable record of where the app's balance went rather than a bare set of flags.
   */
  exits = BoxMap<bytes<32>, uint64>({ keyPrefix: "e" });

  /**
   * The escape hatch has been pulled. Set once and never cleared.
   *
   * Everything that moves the rollup forward -- `deposit`, `openBatch`, `verifyBatch` -- refuses
   * from here on, so `stateRoot` is final and the inbox can never be consumed by a batch.
   * That is what makes the pending suffix safe to refund in `reclaimDeposit`, and it is the
   * precondition a forced exit against the frozen root will need.
   *
   * One-way deliberately. A recoverable flush would have to distinguish a nonce voided by an
   * escape from one consumed by a batch, and with the sequencer free to resume between escapes
   * those ranges interleave -- there is no cursor comparison that separates them. Terminal means
   * there is only ever one voided range, and `index >= settledInboxCursor` names it exactly.
   */
  escaped = GlobalState<boolean>();

  /**
   * Round `executeEscape` becomes callable, once `signalEscape` has found stale pending work.
   *
   * `hasValue` doubles as "an escape has been signalled", the same idiom `batchLength` uses for "a
   * batch is being posted". Deleted by `executeEscape`, or once settlement reaches every recorded
   * target. Full obligation tranches may extend it without moving that target.
   */
  escapeDeadline = GlobalState<uint64>();

  /** Inbox frontier a pending escape signal requires settlement to reach. */
  escapeInboxTarget = GlobalState<uint64>();

  /**
   * Obligations discharged since the pending signal last bought a grace extension.
   *
   * The one counter both directions feed: `verifyBatch` credits the inbox entries its prefix
   * consumed, and `payWithdrawal` credits the payout it just made. Counting them together is what
   * stops the two mechanisms from starving each other -- an outstanding payout chain closes
   * `openBatch`, so without this a sequencer could be frozen out mid-drain for failing to settle
   * when settling was the one thing the drain was blocking.
   *
   * Lives and dies with `escapeDeadline`, since progress is only ever measured against a live
   * accusation. Reset rather than carried when a tranche is spent: at most one extension per call,
   * whatever the size of the credit, which is what keeps a single enormous settlement from buying
   * windows by the hundred.
   */
  escapeProgress = GlobalState<uint64>();

  /**
   * Rounds the oldest pending inbox entry may age before it counts as evidence the sequencer has
   * stopped.
   *
   * Applies to either kind of entry, which is the whole reason it is not named for deposits: a stale
   * deposit means value is stuck outside the rollup, a stale withdrawal request means value is stuck
   * inside it, and `signalEscape` reads the queue head without caring which it found.
   *
   * Set at creation rather than compiled in, for two reasons. There is no `UpdateApplication`
   * handler, so a baked-in constant could never be retuned. And the e2e has to be able to cross
   * this threshold -- a production value is hundreds of thousands of rounds, which no test can
   * generate, so the test deploys with a handful.
   */
  inboxTimeout = GlobalState<uint64>();

  /**
   * Rounds between `signalEscape` and `executeEscape`.
   *
   * The grace period is what stops a signal from voiding a nearly-complete batch the instant the
   * timeout ticks over. Each full tranche of discharged obligations earns one additional window,
   * while reaching the fixed target clears the signal outright.
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
   * halt; too high, and whoever is stuck in the inbox -- a depositor waiting to be credited, or an
   * account waiting to be let out -- waits that long for the hatch to open.
   */
  createApplication(inboxTimeout: uint64, escapeGrace: uint64): void {
    this.stateRoot.value = bzero(32);
    this.inboxChain.value = bzero(32);
    this.settledInboxChain.value = bzero(32);
    this.inboxCursor.value = 0;
    this.settledInboxCursor.value = 0;
    this.requestCursor.value = 0;

    this.escaped.value = false;
    this.inboxTimeout.value = inboxTimeout;
    this.escapeGrace.value = escapeGrace;
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
   * The payment must exceed `INBOX_BOX_MBR`, and the excess is what gets credited. `rekeyTo` and
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
   * @returns The unified inbox index assigned to the deposit.
   */
  deposit(payment: gtxn.PaymentTxn, recipient: bytes<32>): uint64 {
    assert(!this.escaped.value, "the rollup has escaped");

    assertMatch(
      payment,
      {
        receiver: Global.currentApplicationAddress,
        closeRemainderTo: Global.zeroAddress,
        rekeyTo: Global.zeroAddress,
        amount: { greaterThan: INBOX_BOX_MBR },
      },
      "the deposit must pay this app more than the box minimum balance",
    );

    const amount: uint64 = payment.amount - INBOX_BOX_MBR;
    const index = this.inboxCursor.value;

    const chainAfter = sha256(
      Bytes("INBOXD")
        .concat(this.inboxChain.value)
        .concat(recipient)
        .concat(itob(amount)),
    );

    this.inbox(index).value = {
      kind: Bytes("d").toFixed({ length: 1 }),
      address: recipient,
      recipient: Global.zeroAddress,
      amount: amount,
      payer: payment.sender,
      round: Global.round,
      chainAfter: chainAfter,
    };

    this.inboxChain.value = chainAfter;
    this.inboxCursor.value = index + 1;

    return index;
  }

  /**
   * Demand that the rollup let an account out, whether the sequencer likes it or not.
   *
   * This is what makes withdrawals censorship-resistant. An ordinary `Withdrawal` is an L2
   * transaction handed to the sequencer, and a sequencer that simply never includes it is
   * indistinguishable from a busy one -- L1 never heard of it, so nothing on L1 can notice. Filing
   * it here gives it a strict FIFO position in `inboxChain`. Earlier prefixes may settle first, but
   * no later inbox item can pass it. If it becomes stale, the fixed-target watchdog permits only
   * full-tranche progress to postpone escape.
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
   * @returns The unified inbox index assigned to the request. `expectedNonce` remains only the
   * signature replay nonce and is not the returned inbox position.
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
        amount: INBOX_BOX_MBR,
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
          .concat(deploymentDomain())
          .concat(itob(nonce))
          .concat(address)
          .concat(recipient.bytes),
        signature,
        pubKey,
      ),
      "the request is not signed by the account's key",
    );

    const index = this.inboxCursor.value;
    const chainAfter = sha256(
      Bytes("INBOXW")
        .concat(this.inboxChain.value)
        .concat(address)
        .concat(recipient.bytes),
    );

    this.inbox(index).value = {
      kind: Bytes("w").toFixed({ length: 1 }),
      address: address,
      recipient: recipient,
      amount: 0,
      payer: payment.sender,
      round: Global.round,
      chainAfter: chainAfter,
    };

    this.inboxChain.value = chainAfter;
    this.inboxCursor.value = index + 1;
    this.requestCursor.value = nonce + 1;

    return index;
  }

  /**
   * Delete an answered request's box and return its minimum balance to whoever paid it.
   *
   * Permissionless, like `pruneDeposit`, and for the same reasons: only a request the chain has
   * already accounted for can be pruned, and the refund goes to the recorded `payer` rather than
   * the caller.
   *
   * Also allowed once the rollup has escaped, whatever the cursor says. An unanswered request is
   * exactly what an escape means -- the account is still on L2 and comes out through `forceExit`
   * instead -- so there is nothing left for the box to be waiting for.
   */
  pruneRequest(index: uint64): void {
    const record = clone(this.inbox(index).value);
    assert(record.kind === Bytes("w"), "the inbox entry is not a request");
    assert(
      index < this.settledInboxCursor.value || this.escaped.value,
      "a request cannot be pruned before the batch that answered it has settled",
    );

    this.inbox(index).delete();

    itxn
      .payment({ receiver: record.payer, amount: INBOX_BOX_MBR, fee: 0 })
      .submit();
  }

  /**
   * Delete a settled deposit's box and return its minimum balance to whoever paid it.
   *
   * Permissionless, because there is nothing to abuse: the index must be below
   * `settledInboxCursor`, so only a deposit the chain has already accounted for can be pruned,
   * and the refund goes to the recorded `payer` rather than the caller. Deleting the box drops the
   * app's own minimum balance by exactly the amount being sent, so the two cancel and the app
   * neither gains nor loses. The caller covers the inner transaction's fee.
   *
   * Still callable after an escape: a deposit below `settledInboxCursor` was consumed by a batch
   * that settled, so its box is stale bookkeeping either way.
   *
   * `INBOX_BOX_MBR` is below the network's own minimum balance, so this fails if `payer` has
   * since closed their account. Self-healing rather than fatal -- the payer refunds their account
   * and anyone can then prune -- and it costs the app nothing to leave the box sitting there.
   */
  pruneDeposit(index: uint64): void {
    const record = clone(this.inbox(index).value);
    assert(record.kind === Bytes("d"), "the inbox entry is not a deposit");
    assert(
      index < this.settledInboxCursor.value,
      "a deposit cannot be pruned before the batch that consumed it has settled",
    );

    this.inbox(index).delete();

    itxn
      .payment({
        receiver: record.payer,
        amount: INBOX_BOX_MBR,
        fee: 0,
      })
      .submit();
  }

  /**
   * Refund a deposit the rollup will now never credit, once the escape has been executed.
   *
   * The counterpart to `pruneDeposit`, and the two together partition the queue: below
   * `settledInboxCursor` a deposit was consumed by a settled batch and only its box minimum
   * balance is owed, at or above it the deposit was never credited on L2 and the whole payment is.
   * The boundary is exact because every batch consumes a FIFO inbox prefix, so all unsettled entries
   * form one contiguous suffix.
   *
   * That suffix is the only thing `escaped` has to be terminal for. While the sequencer can still
   * settle, "not yet credited" is a statement about right now; once it can't, it is permanent, and
   * a bare cursor comparison is enough to decide who is owed what. Nothing is written to the
   * inbox chain here and nothing needs to be -- with `verifyBatch` refusing forever, the chain is
   * dead state, and rewinding it would only be a second thing to keep consistent.
   *
   * Permissionless and in any order, like `pruneDeposit`: the refund goes to the recorded `payer`,
   * so the caller can only pay a fee on someone else's behalf. The payment covers the deposit and
   * the box minimum balance together, and deleting the box drops the app's own minimum balance by
   * that second part, so the app is left holding exactly the L2 balances it still owes.
   */
  reclaimDeposit(index: uint64): void {
    assert(
      this.escaped.value,
      "deposits can only be reclaimed after an escape",
    );
    assert(
      index >= this.settledInboxCursor.value,
      "this deposit was credited by a batch that settled",
    );
    assert(index < this.inboxCursor.value, "no such inbox entry");

    const record = clone(this.inbox(index).value);
    assert(record.kind === Bytes("d"), "the inbox entry is not a deposit");
    this.inbox(index).delete();

    itxn
      .payment({
        receiver: record.payer,
        amount: record.amount + INBOX_BOX_MBR,
        fee: 0,
      })
      .submit();
  }

  /**
   * Make the next payout the settled batch committed, and step the chain past it.
   *
   * The sequencer's obligation rather than the recipient's errand. A settled batch has already
   * debited these balances on L2, so the rollup owes the money whether anyone comes to ask for it,
   * and `openBatch` will not let the sequencer continue until every one of them has been paid.
   *
   * The check is what makes this safe to be a bare fold. `tail` is the chain value that follows this
   * payout, so `sha256("WPAY" || tail || recipient || amount)` has to reproduce the head being held
   * -- and only the batch's genuine next payout does. Note the order that forces: the contract
   * cannot tell a right payout from a wrong one *after* making it, only before, which is why the
   * chain is built back to front. A chain folded the other way would have to pay first and discover
   * the mismatch at the end, by which point the money is gone and the committed value is
   * unreachable for good.
   *
   * That check is also the whole of the replay protection. A payout matches exactly one head, and
   * the head has moved on by the time the call returns, so the same payout can never be made twice
   * and needs no nullifier recorded anywhere. Two identical payouts in one batch are two distinct
   * positions in the chain, and each is made once.
   *
   * Permissionless, deliberately. Nothing a caller passes can redirect a payment -- the arguments
   * either reproduce the head or the call fails -- so the only thing an outsider can do here is pay
   * a fee on the sequencer's behalf. That is the liveness valve: if the sequencer stalls with a
   * chain outstanding, the recipients can drain it themselves.
   *
   * A payout is also an obligation discharged, and the sequencer's own payouts are credited against
   * a pending escape signal exactly as consumed inbox entries are. That is what makes the
   * `openBatch` gate safe: the drain the gate demands cannot be the reason the sequencer misses the
   * deadline for settling.
   *
   * No `escaped` guard either, for the same reason `pruneRequest` has none. These balances left L2 in
   * a batch that settled; the debt is real and survives the rollup freezing. An escape stops the
   * root advancing, not the rollup paying what it already owes.
   *
   * The payment cannot fail. `MIN_WITHDRAWAL` in the guest keeps every amount at or above the
   * network minimum balance, so it goes through even against a receiver that does not yet exist --
   * which matters far more here than it did for independent claims, because one unpayable payment
   * would block the rest of the chain and with it the next batch.
   */
  payWithdrawal(recipient: Account, amount: uint64, tail: bytes<32>): void {
    assert(this.pendingWithdrawals.hasValue, "no payouts are outstanding");
    assert(
      sha256(
        Bytes("WPAY").concat(tail).concat(recipient.bytes).concat(itob(amount)),
      ) === this.pendingWithdrawals.value,
      "this is not the next payout the batch committed",
    );

    if (tail === withdrawalTerminal()) {
      this.pendingWithdrawals.delete();
    } else {
      this.pendingWithdrawals.value = tail;
    }

    // Only the sequencer's own payouts answer an accusation. The signal says the sequencer has
    // stopped, and an outsider draining the chain is no evidence whatever that it has not -- so the
    // payout stays permissionless while the credit for it does not. `verifyBatch` needs no such
    // test, being creator-gated already, which is what makes the two sources of credit comparable.
    if (Txn.sender === Global.creatorAddress) {
      this.creditEscapeProgress(1);
    }

    itxn.payment({ receiver: recipient, amount: amount, fee: 0 }).submit();
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
   * The signed message names this application and network through `deploymentDomain`, so a
   * signature cannot be carried to another deployment where the same key controls the same address.
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
          .concat(deploymentDomain())
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
   * The oldest pending unified inbox entry can accuse it. A stale deposit means value is stuck
   * outside the rollup; a stale withdrawal request means value is stuck inside it.
   *
   * The head is the right and only thing to read: indices are handed out in round order, so nothing
   * pending is older, and pruning only reaches indices below the settled cursor.
   *
   * `signalEscape` reads one queue head. `openBatch` reads one checkpoint for a selected non-empty
   * prefix; neither cost depends on how much is queued.
   *
   * Permissionless, because the accusation is checkable. The sequencer either settles its way to the
   * recorded target or answers with a full tranche of discharged obligations -- inbox entries
   * consumed, payouts made, or any mix of the two. See `creditEscapeProgress`.
   */
  signalEscape(): void {
    assert(!this.escaped.value, "the rollup has already escaped");
    assert(
      !this.escapeDeadline.hasValue,
      "an escape has already been signalled",
    );

    assert(
      this.settledInboxCursor.value < this.inboxCursor.value,
      "nothing is pending",
    );

    const head = this.inbox(this.settledInboxCursor.value).value.round;
    assert(
      Global.round > head + this.inboxTimeout.value,
      "nothing has been waiting long enough",
    );

    this.escapeInboxTarget.value = this.inboxCursor.value;
    this.escapeProgress.value = 0;

    this.escapeDeadline.value = Global.round + this.escapeGrace.value;
  }

  /**
   * Credit `discharged` obligations against a pending accusation, buying a grace window per tranche.
   *
   * The answer to an accusation that the sequencer has stopped is work, and this is the one place
   * that judges it -- so a settlement and a payout are worth exactly the same per unit, and neither
   * can be starved by the other blocking it.
   *
   * At most one extension per call. The remainder is dropped rather than carried, which loses at
   * worst `ESCAPE_PROGRESS_TRANCHE - 1` obligations of credit and in exchange keeps a single
   * settlement that consumed a hundred thousand inbox entries from converting them into hundreds of
   * grace windows and neutering the watchdog outright.
   *
   * Extends from the existing deadline rather than from the current round, so windows accumulate
   * from where the accusation put them instead of resetting the clock on every call.
   *
   * Silent when nothing has been signalled, so callers need not know whether an accusation is live.
   */
  private creditEscapeProgress(discharged: uint64): void {
    if (!this.escapeDeadline.hasValue) {
      return;
    }

    const progress: uint64 = this.escapeProgress.value + discharged;
    if (progress >= ESCAPE_PROGRESS_TRANCHE) {
      this.escapeDeadline.value =
        this.escapeDeadline.value + this.escapeGrace.value;
      this.escapeProgress.value = 0;
    } else {
      this.escapeProgress.value = progress;
    }
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
   * `pendingWithdrawals` is deliberately left alone. An open batch was never settled and so owes
   * nothing, but an outstanding payout chain came from a batch that *did* settle -- those balances
   * have already left L2, and freezing the root does not unmake the debt. `payWithdrawal` keeps
   * working afterwards, and being permissionless it needs nobody's cooperation either.
   *
   * Permissionless. There is nothing left to gate -- the deadline is the authorization, and it can
   * only have been set by pending work that exceeded `inboxTimeout`, plus any grace extensions
   * earned by full FIFO tranches.
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
    this.escapeInboxTarget.delete();
    this.escapeProgress.delete();

    if (this.batchLength.hasValue) {
      this.chunkAccumulator.delete();
      this.batchLength.delete();
      this.postedLength.delete();
      this.sealedInboxChain.delete();
      this.sealedInboxCursor.delete();
    }
  }

  /**
   * Throw away a batch that cannot settle, so the next one can be opened.
   *
   * `openBatch` refuses while a batch is in flight and only `verifyBatch` clears that, so without
   * this a batch that can never settle -- a mis-cut chunk, public values that do not line up --
   * wedges the contract permanently. The inbox adds another value for a batch to disagree with.
   *
   * This is only possible because nothing was destroyed on the way in: `openBatch` copies
   * the inbox chain rather than resetting it, so abandoning is just forgetting the copy. A design
   * that reset the live chain per batch would have to splice entries that arrived mid-batch back
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
    this.sealedInboxChain.delete();
    this.sealedInboxCursor.delete();
  }

  /**
   * Start a batch, seeding the accumulator from the length its bytes are declared to have and
   * sealing the inbox chain the batch will have to fold to.
   *
   * Mirrors `chunk_accumulator_seed`.
   *
   * The target cursor may select any FIFO prefix from the settled cursor through the live cursor.
   * The record immediately before the endpoint stores the matching hash-chain checkpoint, so
   * opening reads at most one box regardless of prefix length. Later arrivals remain pending.
   *
   * Also the one place the payout chain gates progress. The rollup may not move on while it still
   * owes the last batch's withdrawals, which is what turns a payout from something a recipient has
   * to come and claim into something the sequencer has to do. One assertion covers it completely:
   * `verifyBatch` is the only thing that ever sets a chain outstanding, and it requires a batch to
   * be open, so no payouts can appear between here and the settlement that clears them.
   */
  openBatch(batchLength: uint64, targetInboxCursor: uint64): void {
    assert(
      Txn.sender === Global.creatorAddress,
      "only the creator may open a batch",
    );
    assert(!this.escaped.value, "the rollup has escaped");
    // A second open would abandon a half-posted batch and start folding over its accumulator, so
    // a batch has to be finished before the next one begins. See `abandonBatch` for the way out.
    assert(!this.batchLength.hasValue, "a batch is already being posted");
    assert(
      !this.pendingWithdrawals.hasValue,
      "the last batch's payouts have not all been made",
    );
    assert(
      targetInboxCursor >= this.settledInboxCursor.value,
      "the batch cannot move the inbox cursor backwards",
    );
    assert(
      targetInboxCursor <= this.inboxCursor.value,
      "the batch cannot consume an inbox entry that has not arrived",
    );

    this.chunkAccumulator.value = sha256(
      Bytes("BATCH").concat(deploymentDomain()).concat(itob(batchLength)),
    );
    this.batchLength.value = batchLength;
    this.postedLength.value = 0;

    // Written unconditionally, even with nothing pending -- `verifyBatch` compares it every time,
    // so `hasValue` must never become load-bearing here. Same discipline as `chunkAccumulator`.
    if (targetInboxCursor === this.settledInboxCursor.value) {
      this.sealedInboxChain.value = this.settledInboxChain.value;
    } else {
      this.sealedInboxChain.value = this.inbox(
        targetInboxCursor - 1,
      ).value.chainAfter;
    }
    this.sealedInboxCursor.value = targetInboxCursor;
  }

  /**
   * Fold one chunk into the accumulator.
   *
   * Mirrors `chunk_digest` composed with `accumulate_chunk`: the chunk is digested on its own,
   * untagged -- a chunk digest is only ever consumed inside the tagged preimage below, so it can
   * never be read as a seed or as an accumulator -- and the 69-byte fold step carries the tag.
   */
  accumulateChunk(chunk: Chunk): void {
    assert(
      Txn.sender === Global.creatorAddress,
      "only the creator may post a chunk",
    );
    assert(this.batchLength.hasValue, "no batch is being posted");
    assert(
      this.postedLength.value < this.batchLength.value,
      "the batch is already fully posted",
    );

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
   * - `publicValues[96..128]` against `settledInboxChain` -- where the batch's FIFO prefix begins.
   * - `publicValues[128..160]` against `sealedInboxChain` -- where it ends. Pinning both ends stops a
   *   prover choosing an anchor that makes a fabricated fold land correctly.
   * - the proof itself, over all 192 bytes.
   *
   * **All 192, not merely the words compared above.** The withdrawal chain has no prior L1 value to
   * compare against: it claims what the batch authorized paying out, and every payout made against
   * it is checked only against the chain itself. That makes the proof its only defence. A verifier
   * bound to a prefix would leave it an ordinary argument, allowing a chain that pays withdrawals no
   * batch contained. `PublicValues` is `bytes<192>` for exactly that reason.
   *
   * The two inbox checks make the selected FIFO prefix exactly L1's: inventing, dropping, reordering
   * or altering either kind of entry diverges the fold and never recovers.
   *
   * **None of that binds yet.** The proof is not verified -- see the TODO below -- and
   * `publicValues` is an ordinary argument, so a dishonest sequencer can read `sealedInboxChain`
   * straight out of global state and hand it back while the batch bytes say something else -- and
   * can put whatever it likes in the withdrawal chain. The
   * chain is the right mechanism and becomes airtight the moment the verifier lands, with no
   * redesign; until then the sequencer is trusted here exactly as it is already trusted with
   * `stateRoot`. What does hold today is data availability: the accumulator forces the real bytes
   * on-chain, so the fraud is detectable by replay, just not preventable.
   *
   * No box is read here, and none should ever be. That is what keeps the cost of settling
   * independent of how many inbox entries are queued -- and now of how much the batch withdrew, too,
   * since the payout chain is one global rather than a funded box.
   *
   * Nothing here bounds how many payouts a batch may commit. Nothing needs to: a sequencer that
   * commits a great many has to make every one of them, at its own expense, before it may open
   * another batch -- and because each one is an obligation the watchdog counts, a long drain buys
   * the time it takes rather than running the clock down. See `creditEscapeProgress`.
   *
   * Settlement clears a pending `signalEscape` when the settled cursor reaches its fixed snapshot.
   * While that target remains unresolved, the inbox entries this prefix consumed are credited as
   * obligations discharged, on the same counter `payWithdrawal` feeds. Later arrivals never move the
   * target. Once the deadline has passed no settlement can race `executeEscape`.
   */
  verifyBatch(publicValues: PublicValues): void {
    assert(
      Txn.sender === Global.creatorAddress,
      "only the creator may settle a batch",
    );
    assert(!this.escaped.value, "the rollup has escaped");
    assert(
      !this.escapeDeadline.hasValue ||
        Global.round <= this.escapeDeadline.value,
      "the escape deadline has passed",
    );
    assert(this.batchLength.hasValue, "no batch is being posted");
    assert(
      this.postedLength.value === this.batchLength.value,
      "the batch is not fully posted",
    );

    const oldRoot = publicValues.slice(0, 32);
    const newRoot = publicValues.slice(32, 64);
    const batchCommitment = publicValues.slice(64, 96);
    const oldInboxChain = publicValues.slice(96, 128);
    const newInboxChain = publicValues.slice(128, 160);
    const withdrawalChain = publicValues.slice(160, 192);

    assert(
      oldRoot === this.stateRoot.value,
      "the proof does not start from the current root",
    );
    assert(
      batchCommitment === this.chunkAccumulator.value,
      "the proof is not for the batch that was posted",
    );
    assert(
      oldInboxChain === this.settledInboxChain.value,
      "the proof does not start from the settled inbox chain",
    );
    assert(
      newInboxChain === this.sealedInboxChain.value,
      "the batch does not consume exactly the selected inbox prefix",
    );

    const oldSettledInboxCursor = this.settledInboxCursor.value;

    this.stateRoot.value = newRoot.toFixed({ length: 32 });
    this.settledInboxChain.value = this.sealedInboxChain.value;
    this.settledInboxCursor.value = this.sealedInboxCursor.value;

    // A batch that withdrew nothing commits the terminal itself, so the common case writes nothing
    // and the rollup is free to open the next batch immediately. Otherwise the head goes into state
    // and `openBatch` is closed until `payWithdrawal` has walked it back down to the terminal.
    //
    // No funding transaction and no box either way, which is what makes a withdrawing settlement
    // cost exactly what a non-withdrawing one does.
    if (withdrawalChain !== withdrawalTerminal()) {
      this.pendingWithdrawals.value = withdrawalChain.toFixed({ length: 32 });
    }

    // TODO: Actual ZK verification

    this.chunkAccumulator.delete();
    this.batchLength.delete();
    this.postedLength.delete();
    this.sealedInboxChain.delete();
    this.sealedInboxCursor.delete();

    if (this.escapeInboxTarget.hasValue) {
      if (this.settledInboxCursor.value >= this.escapeInboxTarget.value) {
        this.escapeInboxTarget.delete();
        this.escapeDeadline.delete();
        this.escapeProgress.delete();
      } else {
        // Falling short of the target still discharges obligations, and they are credited on the
        // same counter the drain feeds -- so a prefix too small to earn a window on its own is not
        // thrown away, it waits for the payouts that follow it.
        this.creditEscapeProgress(
          this.settledInboxCursor.value - oldSettledInboxCursor,
        );
      }
    }
  }
}
