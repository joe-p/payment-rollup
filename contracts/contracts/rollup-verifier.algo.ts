import {
  assert,
  bytes,
  Bytes,
  Contract,
  GlobalState,
  uint64,
} from "@algorandfoundation/algorand-typescript";
import { itob, sha256 } from "@algorandfoundation/algorand-typescript/op";

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

export class RollupVerifier extends Contract {
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
   * Start a batch, seeding the accumulator from the length its bytes are declared to have.
   *
   * Mirrors `chunk_accumulator_seed`.
   */
  openBatch(batchLength: uint64): void {
    // A second open would abandon a half-posted batch and start folding over its accumulator, so
    // a batch has to be finished before the next one begins.
    assert(!this.batchLength.hasValue, "a batch is already being posted");

    this.chunkAccumulator.value = sha256(Bytes("BATCH").concat(itob(batchLength)));
    this.batchLength.value = batchLength;
    this.postedLength.value = 0;
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
    assert(chunk.length === expected, "chunk is not the size its position allows");

    this.chunkAccumulator.value = sha256(
      Bytes("CHUNK").concat(this.chunkAccumulator.value).concat(sha256(chunk)),
    );
    this.postedLength.value = this.postedLength.value + chunk.length;
  }

  /**
   * Close a fully posted batch and hand back its commitment.
   *
   * Refusing to return anything until the declared length has been posted in full is what makes
   * the data available: stopping a chunk short leaves an accumulator that is not the commitment,
   * and a sequencer that cannot produce the commitment cannot advance the root.
   *
   * The commitment is only half of settlement -- the caller still has to check it against
   * `publicValues[64..96]`, check `publicValues[0..32]` against the root it holds, verify the
   * proof, and store `publicValues[32..64]`. None of that lives here yet.
   */
  finishBatch(): bytes<32> {
    assert(this.batchLength.hasValue, "no batch is being posted");
    assert(
      this.postedLength.value === this.batchLength.value,
      "the batch is not fully posted",
    );

    const commitment = this.chunkAccumulator.value;

    this.chunkAccumulator.delete();
    this.batchLength.delete();
    this.postedLength.delete();

    return commitment;
  }
}
