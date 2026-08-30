import { createHash } from "node:crypto";
import algosdk from "algosdk";
import nacl from "tweetnacl";
import {
  RollupVerifierFactory,
  RollupVerifierClient,
  RollupVerifierComposer,
} from "../contracts/clients/RollupVerifierClient";
import {
  Groth16Bn254LsigVerifier,
  decodeGnarkGroth16Bn254Proof,
  decodeGnarkGroth16Bn254Vk,
  type Groth16Bn254Proof,
} from "snarkjs-algorand";

import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";

/**
 * Must equal `CHUNK_SIZE` in the contract and in the guest. The fixtures emit it as `chunkSize` so
 * a test can assert the three agree rather than trusting that they do.
 */
export const CHUNK_SIZE = 4094;

/**
 * Minimum balance one inbox box costs: `2500 + 400 * (key + value)`, over a 9-byte key (`"i"` and an
 * 8-byte index) and a 145-byte record.
 *
 * Written out here and nowhere in the contract, which measures what a box charged it rather than
 * naming a figure. A caller has no such option -- the payment has to be built before the box exists
 * -- so this is a prediction of the contract's measurement, and one the contract will reject if it
 * is wrong.
 */
export const INBOX_BOX_MBR = 64_100n;

/**
 * Smallest withdrawal the guest will prove, in microALGO. Mirrors `MIN_WITHDRAWAL` in the core
 * crate.
 *
 * Equal to the network minimum balance, which is what lets `payWithdrawal` pay out with an inner
 * transaction that cannot fail for want of a receiver account -- and so what keeps one payout from
 * blocking the rest of its batch's chain.
 */
export const MIN_WITHDRAWAL = 100_000n;

/**
 * Minimum balance for the permanent record that an account has been force-exited, over a 33-byte key
 * (`"e"` and a 32-byte rollup address) and an 8-byte value.
 *
 * Withheld from the exit rather than paid separately, and never returned: the record has to outlive
 * the payout or a frozen state root would keep authorizing the same one. Like {@link INBOX_BOX_MBR}
 * this only predicts what the contract measures for itself -- it is here to report what a caller will
 * actually receive, not to tell the contract what to withhold.
 */
export const EXIT_BOX_MBR = 18_900n;

/** Largest group the network will accept, and so the most chunks one send can carry. */
const MAX_GROUP_SIZE = 16;

/**
 * Rounds an inbox entry of either kind -- a deposit or a forced withdrawal request -- may sit
 * unsequenced before {@link RollupVerifier.signalEscape} will accept it as evidence the sequencer has
 * stopped, and rounds between that signal and {@link RollupVerifier.executeEscape}.
 *
 * A week and a day, at roughly 2.8 seconds a round. Deployment-time arguments rather than contract
 * constants because there is no `UpdateApplication` handler to retune them later -- and because the
 * e2e has to be able to actually cross the threshold, which it cannot do with numbers this size.
 */
export const INBOX_TIMEOUT_ROUNDS = 216_000n;
export const ESCAPE_GRACE_ROUNDS = 31_000n;

/** SP1 6.4's recursion verification-key root. */
export const SP1_RECURSION_VKEY_ROOT = Buffer.from(
  "002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352",
  "hex",
);

/** The proof fields emitted by SP1's Groth16 prover. */
export type Sp1Groth16Proof = {
  /** SP1's 352-byte encoding: three metadata words followed by the 256-byte gnark proof. */
  encodedProof: Uint8Array;
  /** vkey hash, journal hash, exit code, recursion-vkey root, and proof nonce. */
  publicInputs: readonly [string, string, string, string, string];
};

export type RollupVerifierConfig = {
  /** `sp1_verifier::GROTH16_VK_BYTES` for the SP1 release used by the prover. */
  groth16VerificationKey: Uint8Array;
  /** `SP1VerifyingKey::hash_bn254()`, encoded as a big-endian uint256. */
  programVkeyHash: Uint8Array;
  recursionVkeyRoot?: Uint8Array;
  inboxTimeout?: bigint;
  escapeGrace?: bigint;
  /** Use the pre-generated Falcon fixture's zero-genesis, app-zero deployment domain. */
  testDeployment?: boolean;
};

/** Decode SP1's `0x`-prefixed `SP1VerifyingKey::bytes32()` deployment value. */
export function decodeSp1VkeyHash(value: string): Uint8Array {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("SP1 program vkey must be exactly 32 hexadecimal bytes");
  }
  return new Uint8Array(Buffer.from(hex, "hex"));
}

interface BatchProofVerifier {
  address(): Promise<algosdk.Address>;
  validate(proof: Sp1Groth16Proof | undefined): void;
  verify(
    composer: RollupVerifierComposer<any>,
    appClient: RollupVerifierClient,
    sender: algosdk.AddressWithTransactionSigner,
    publicValues: Uint8Array,
    proof: Sp1Groth16Proof | undefined,
  ): Promise<void>;
}

class LsigBatchProofVerifier implements BatchProofVerifier {
  private readonly verifier: Groth16Bn254LsigVerifier;

  constructor(algorand: AlgorandClient, verificationKey: Uint8Array) {
    this.verifier = new Groth16Bn254LsigVerifier({
      totalLsigs: 3,
      appOffset: 1,
      algorand,
      vk: decodeGnarkGroth16Bn254Vk(verificationKey),
    });
  }

  async address(): Promise<algosdk.Address> {
    return (await this.verifier.lsigAccount()).addr;
  }

  validate(proof: Sp1Groth16Proof | undefined): void {
    this.witness(proof);
  }

  private witness(proof: Sp1Groth16Proof | undefined) {
    if (!proof) throw new Error("an SP1 Groth16 proof is required");
    if (proof.encodedProof.byteLength !== 352) {
      throw new Error("SP1's encoded Groth16 proof must be exactly 352 bytes");
    }
    if (proof.publicInputs.length !== 5) {
      throw new Error(
        "SP1 Groth16 proofs must have exactly five public inputs",
      );
    }
    return {
      proof: decodeGnarkGroth16Bn254Proof(proof.encodedProof.subarray(96)),
      signals: proof.publicInputs.map((input) => BigInt(input)),
    };
  }

  async verify(
    composer: RollupVerifierComposer<any>,
    appClient: RollupVerifierClient,
    sender: algosdk.AddressWithTransactionSigner,
    publicValues: Uint8Array,
    proof: Sp1Groth16Proof | undefined,
  ): Promise<void> {
    const witness = this.witness(proof);
    const verifierLsig = await this.verifier.lsigAccount();
    await this.verifier.verificationParams({
      composer,
      ...witness,
      paramsCallback: async ({ lsigParams, lsigsFee, args }) => {
        const verifier = await appClient.algorand.createTransaction.payment({
          ...lsigParams,
          amount: microAlgo(0),
          receiver: appClient.appAddress,
        });
        composer.verifyBatch({
          sender: sender.address,
          signer: sender.txnSigner,
          args: {
            // `createTransaction` returns a bare transaction and drops the signer that
            // `lsigParams` carried, so it has to be reattached here. Without it the group's
            // default signer is asked for this one too, and the LogicSig address it is sent
            // from has no key to sign with.
            verifier: { txn: verifier, signer: verifierLsig.signer },
            ...args,
            publicValues,
          },
          extraFee: lsigsFee,
        });
      },
    });
  }
}

class MockBatchProofVerifier implements BatchProofVerifier {
  constructor(private readonly signer: algosdk.AddressWithTransactionSigner) {}

  async address(): Promise<algosdk.Address> {
    return this.signer.address;
  }

  validate(): void {}

  async verify(
    composer: RollupVerifierComposer<any>,
    appClient: RollupVerifierClient,
    sender: algosdk.AddressWithTransactionSigner,
    publicValues: Uint8Array,
  ): Promise<void> {
    const digest = createHash("sha256").update(publicValues).digest();
    digest[0]! &= 0b00011111;
    const verifier = await appClient.algorand.createTransaction.payment({
      sender: this.signer.address,
      signer: this.signer.txnSigner,
      receiver: appClient.appAddress,
      amount: microAlgo(0),
      staticFee: microAlgo(0),
    });
    const emptyProof: Groth16Bn254Proof = {
      piA: new Uint8Array(64),
      piB: new Uint8Array(128),
      piC: new Uint8Array(64),
    };
    composer.verifyBatch({
      sender: sender.address,
      signer: sender.txnSigner,
      args: {
        verifier,
        signals: [0n, algosdk.bytesToBigInt(digest), 0n, 0n, 0n],
        proof: emptyProof,
        publicValues,
      },
      extraFee: microAlgo(1_000),
    });
  }
}

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

/** Network- and application-specific domain shared by signatures, the guest, and the contract. */
export function deploymentDomain(
  genesisHash: Uint8Array,
  appId: bigint,
): Uint8Array {
  const tag = new TextEncoder().encode("PAYMENT_ROLLUP_V1");
  const preimage = new Uint8Array(tag.length + 32 + 8);
  preimage.set(tag);
  preimage.set(genesisHash, tag.length);
  new DataView(preimage.buffer).setBigUint64(tag.length + 32, appId);
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

function l2TransactionMessage(
  kind: "PAY" | "WDR",
  domain: Uint8Array,
  sender: Uint8Array,
  nonce: bigint,
  destination: Uint8Array,
  amount: bigint,
): Uint8Array {
  const tag = new TextEncoder().encode(kind);
  const message = new Uint8Array(3 + 32 + 32 + 8 + 32 + 8);
  message.set(tag);
  message.set(domain, 3);
  message.set(sender, 35);
  const view = new DataView(message.buffer);
  view.setBigUint64(67, nonce);
  message.set(destination, 75);
  view.setBigUint64(107, amount);
  return message;
}

/** Bytes an L2 payment signs, including its deployment and network domain. */
export const paymentMessage = (
  domain: Uint8Array,
  sender: Uint8Array,
  nonce: bigint,
  receiver: Uint8Array,
  amount: bigint,
) => l2TransactionMessage("PAY", domain, sender, nonce, receiver, amount);

/** Bytes an ordinary L2 withdrawal signs, including its deployment and network domain. */
export const withdrawalMessage = (
  domain: Uint8Array,
  sender: Uint8Array,
  nonce: bigint,
  recipient: algosdk.Address,
  amount: bigint,
) =>
  l2TransactionMessage(
    "WDR",
    domain,
    sender,
    nonce,
    recipient.publicKey,
    amount,
  );

/** A `BoxMap<uint64, _>` key: the map's one-character prefix and the key, big-endian. */
function boxName(prefix: string, key: bigint): Uint8Array {
  const name = new Uint8Array(9);
  name.set(new TextEncoder().encode(prefix));
  new DataView(name.buffer).setBigUint64(1, key);

  return name;
}

/** The box a deposit or forced withdrawal request is filed in. */
const inboxBoxName = (index: bigint) => boxName("i", index);

/**
 * The bytes a holder signs to demand that their account be let out.
 *
 * Mirrors the preimage `requestWithdrawal` builds. The deployment domain prevents cross-network
 * and cross-application replay; the nonce authorizes exactly one request.
 */
export function withdrawalRequestMessage(
  domain: Uint8Array,
  nonce: bigint,
  address: Uint8Array,
  recipient: algosdk.Address,
): Uint8Array {
  const tag = new TextEncoder().encode("WREQ");
  const message = new Uint8Array(tag.length + 32 + 8 + 32 + 32);
  const view = new DataView(message.buffer);

  message.set(tag);
  message.set(domain, tag.length);
  view.setBigUint64(tag.length + 32, nonce);
  message.set(address, tag.length + 40);
  message.set(recipient.publicKey, tag.length + 40 + 32);

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
 * Mirrors the preimage `forceExit` builds. The deployment domain prevents cross-network and
 * cross-application replay.
 */
export function exitMessage(
  domain: Uint8Array,
  address: Uint8Array,
  recipient: algosdk.Address,
): Uint8Array {
  const tag = new TextEncoder().encode("EXIT");
  const message = new Uint8Array(tag.length + 32 + 32 + 32);

  message.set(tag);
  message.set(domain, tag.length);
  message.set(address, tag.length + 32);
  message.set(recipient.publicKey, tag.length + 32 + 32);

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
  private algorand: AlgorandClient;

  private proofVerifier?: BatchProofVerifier;

  private testDeployment: boolean;

  constructor(
    algorand: AlgorandClient,
    appId: bigint,
    proofVerifier?: BatchProofVerifier,
    testDeployment = false,
  ) {
    this.algorand = algorand;
    this.appClient = algorand.client.getTypedAppClientById(
      RollupVerifierClient,
      {
        appId,
      },
    );
    this.proofVerifier = proofVerifier;
    this.testDeployment = testDeployment;
  }

  async deploymentDomain(): Promise<Uint8Array> {
    if (this.testDeployment) return deploymentDomain(new Uint8Array(32), 0n);
    const { genesisHash } = await this.algorand.getSuggestedParams();
    return deploymentDomain(genesisHash!, this.appClient.appId);
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
    config: RollupVerifierConfig,
  ) {
    const proofVerifier = new LsigBatchProofVerifier(
      algorand,
      config.groth16VerificationKey,
    );
    return this.createWithVerifier(
      algorand,
      creator,
      proofVerifier,
      config.programVkeyHash,
      config.recursionVkeyRoot ?? SP1_RECURSION_VKEY_ROOT,
      config.inboxTimeout ?? INBOX_TIMEOUT_ROUNDS,
      config.escapeGrace ?? ESCAPE_GRACE_ROUNDS,
      config.testDeployment ?? false,
    );
  }

  /** Deploy with a trusted signer in place of the Groth16 LogicSig. Contract-state tests only. */
  static async createForTesting(
    algorand: AlgorandClient,
    creator: algosdk.AddressWithTransactionSigner,
    inboxTimeout: bigint = INBOX_TIMEOUT_ROUNDS,
    escapeGrace: bigint = ESCAPE_GRACE_ROUNDS,
  ) {
    if (process.env.NODE_ENV !== "test") {
      throw new Error("createForTesting is only available when NODE_ENV=test");
    }
    return this.createWithVerifier(
      algorand,
      creator,
      new MockBatchProofVerifier(creator),
      new Uint8Array(32),
      new Uint8Array(32),
      inboxTimeout,
      escapeGrace,
      false,
    );
  }

  private static async createWithVerifier(
    algorand: AlgorandClient,
    creator: algosdk.AddressWithTransactionSigner,
    proofVerifier: BatchProofVerifier,
    programVkeyHash: Uint8Array,
    recursionVkeyRoot: Uint8Array,
    inboxTimeout: bigint,
    escapeGrace: bigint,
    testDeployment: boolean,
  ) {
    if (
      programVkeyHash.byteLength !== 32 ||
      recursionVkeyRoot.byteLength !== 32
    ) {
      throw new Error("SP1 verification-key hashes must be exactly 32 bytes");
    }
    const factory = algorand.client.getTypedAppFactory(RollupVerifierFactory, {
      deployTimeParams: { TEST_DEPLOYMENT: testDeployment ? 1 : 0 },
    });

    const result = await factory.send.create.createApplication({
      sender: creator.address,
      signer: creator.txnSigner,
      note: `Created on ${Date.now()}`,
      args: {
        verifierAddress: await proofVerifier.address(),
        programVkeyHash,
        recursionVkeyRoot,
        inboxTimeout,
        escapeGrace,
      },
    });

    const verifier = new RollupVerifier(
      algorand,
      result.appClient.appId,
      proofVerifier,
      testDeployment,
    );

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

  /** Reconnect to a deployed rollup with the SP1 key used to derive its verifier LogicSig. */
  static connect(
    algorand: AlgorandClient,
    appId: bigint,
    groth16VerificationKey: Uint8Array,
    testDeployment = false,
  ): RollupVerifier {
    return new RollupVerifier(
      algorand,
      appId,
      new LsigBatchProofVerifier(algorand, groth16VerificationKey),
      testDeployment,
    );
  }

  /** Index the next deposit or forced withdrawal request will take. */
  async inboxCursor(): Promise<bigint> {
    return (await this.appClient.state.global.inboxCursor()) ?? 0n;
  }

  /** First inbox entry not yet consumed by a settled batch. */
  async settledInboxCursor(): Promise<bigint> {
    return (await this.appClient.state.global.settledInboxCursor()) ?? 0n;
  }

  /**
   * Move `amount` microALGO into the rollup, credited to the L2 address `recipient`.
   *
   * The payment carries the inbox box's minimum balance on top of `amount`, so the depositor advances it
   * and gets it back from {@link pruneDeposit} once the deposit has settled.
   *
   * @returns The unified inbox index the deposit was filed under.
   */
  async deposit(
    sender: algosdk.AddressWithTransactionSigner,
    recipient: Uint8Array,
    amount: bigint,
  ): Promise<bigint> {
    const index = await this.inboxCursor();

    const payment = await this.appClient.algorand.createTransaction.payment({
      sender: sender.address,
      receiver: this.appClient.appAddress,
      amount: microAlgo(amount + INBOX_BOX_MBR),
    });

    const result = await this.appClient.send.deposit({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { payment, recipient },
      boxReferences: [inboxBoxName(index)],
    });

    return result.return!;
  }

  /** Reclaim a settled deposit's box, refunding its minimum balance to the account that paid it. */
  async pruneDeposit(
    sender: algosdk.AddressWithTransactionSigner,
    index: bigint,
  ): Promise<void> {
    await this.appClient.send.pruneDeposit({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { index },
      boxReferences: [inboxBoxName(index)],
      // Covers the refund's inner transaction, whose own fee the contract sets to zero.
      extraFee: microAlgo(1_000),
    });
  }

  /** Signature nonce the next withdrawal request will take. */
  async requestCursor(): Promise<bigint> {
    return (await this.appClient.state.global.requestCursor()) ?? 0n;
  }

  /**
   * Demand from L1 that an account be emptied to `recipient`, whether the sequencer likes it or not.
   *
   * The whole balance leaves; no amount is named. The request takes a strict FIFO position in the
   * shared inbox. Earlier prefixes may settle first, but once the request becomes stale the escape
   * watchdog requires full-prefix progress to keep extending its deadline.
   *
   * `secretKey` is the 64-byte Ed25519 secret for the key `address` derives from; it never leaves
   * this process. Padded with `opUp` fillers because verifying the signature costs more opcodes than
   * one application call is given.
   *
   * @returns The unified inbox index the request was filed under.
   */
  async requestWithdrawal(
    sender: algosdk.AddressWithTransactionSigner,
    address: Uint8Array,
    pubKey: Uint8Array,
    recipient: string,
    secretKey: Uint8Array,
  ): Promise<bigint> {
    const [nonce, index] = await Promise.all([
      this.requestCursor(),
      this.inboxCursor(),
    ]);
    const signature = nacl.sign.detached(
      withdrawalRequestMessage(
        await this.deploymentDomain(),
        nonce,
        address,
        algosdk.decodeAddress(recipient),
      ),
      secretKey,
    );

    const payment = await this.appClient.algorand.createTransaction.payment({
      sender: sender.address,
      receiver: this.appClient.appAddress,
      amount: microAlgo(INBOX_BOX_MBR),
    });

    const senderSigner = { sender: sender.address, signer: sender.txnSigner };
    let group: RollupVerifierComposer<any> = this.appClient.newGroup();
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
        boxReferences: [inboxBoxName(index)],
      })
      .send();

    return result.returns![0] as bigint;
  }

  /** Reclaim an answered request's box, refunding its minimum balance to whoever filed it. */
  async pruneRequest(
    sender: algosdk.AddressWithTransactionSigner,
    index: bigint,
  ): Promise<void> {
    await this.appClient.send.pruneRequest({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { index },
      boxReferences: [inboxBoxName(index)],
      extraFee: microAlgo(1_000),
    });
  }

  /**
   * Refund a deposit the rollup will never credit, in full, to the account that paid it.
   *
   * Only after {@link executeEscape}. The counterpart to {@link pruneDeposit}: below
   * `settledInboxCursor` a batch consumed the deposit and only the box minimum balance is owed,
   * at or above it the whole payment is.
   */
  async reclaimDeposit(
    sender: algosdk.AddressWithTransactionSigner,
    index: bigint,
  ): Promise<void> {
    await this.appClient.send.reclaimDeposit({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { index },
      boxReferences: [inboxBoxName(index)],
      // Covers the refund's inner transaction, whose own fee the contract sets to zero.
      extraFee: microAlgo(1_000),
    });
  }

  /**
   * Accuse the sequencer of having stopped, by pointing at the oldest pending inbox entry.
   *
   * Permissionless. The contract reads the entry's round and snapshots the live cursor as a fixed
   * target. Full 256-item FIFO advances may extend the deadline, but later arrivals never move it.
   */
  async signalEscape(
    sender: algosdk.AddressWithTransactionSigner,
  ): Promise<void> {
    const [settled, live] = await Promise.all([
      this.settledInboxCursor(),
      this.inboxCursor(),
    ]);

    await this.appClient.send.signalEscape({
      sender: sender.address,
      signer: sender.txnSigner,
      args: {},
      boxReferences: settled < live ? [inboxBoxName(settled)] : [],
    });
  }

  /**
   * Pull the escape hatch once the deadline, including any earned FIFO-progress extensions, has run
   * out.
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
    const signature = nacl.sign.detached(
      exitMessage(await this.deploymentDomain(), exit.address, recipient),
      secretKey,
    );

    const siblings = new Uint8Array(exit.siblings.length * 32);
    exit.siblings.forEach((s, i) => siblings.set(s, i * 32));

    const senderSigner = { sender: sender.address, signer: sender.txnSigner };
    const fillers =
      Math.ceil(
        forceExitOpcodeCost(exit.siblings.length) / OPCODE_BUDGET_PER_CALL,
      ) - 1;

    let group: RollupVerifierComposer<any> = this.appClient.newGroup();
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

  /**
   * Head of the payout chain the last settled batch committed, or `undefined` once it has drained.
   *
   * While this has a value the rollup owes withdrawals and {@link RollupVerifier.verifyBatch} cannot
   * open the next batch.
   */
  async pendingWithdrawals(): Promise<Uint8Array | undefined> {
    // The generated accessor wraps a byte-slice global, and the wrapper is truthy even when the key
    // is absent -- so unwrap before deciding whether anything is outstanding.
    return (
      await this.appClient.state.global.pendingWithdrawals()
    ).asByteArray();
  }

  /**
   * Make the next payout the settled batch committed.
   *
   * `tail` is the chain value that follows this payout, which the contract folds together with the
   * other two arguments and compares against the head it holds -- so only the batch's genuine next
   * payout is accepted, and only once. Take these from `withdrawals` in the fixtures, or from
   * `withdrawal_links` in the core crate, and submit them in order.
   *
   * Permissionless: the payout goes to `recipient` whoever calls this.
   */
  async payWithdrawal(
    sender: algosdk.AddressWithTransactionSigner,
    recipient: string,
    amount: bigint,
    tail: Uint8Array,
  ): Promise<void> {
    await this.appClient.send.payWithdrawal({
      sender: sender.address,
      signer: sender.txnSigner,
      args: { recipient, amount, tail },
      // Covers the payout's inner transaction, whose own fee the contract sets to zero.
      extraFee: microAlgo(1_000),
    });
  }

  /**
   * Walk a settled batch's whole payout chain, in the one order the contract accepts.
   *
   * The sequencer's obligation after every settlement that withdrew anything: until this has run to
   * the end, {@link RollupVerifier.verifyBatch} cannot open another batch.
   */
  async drainWithdrawals(
    sender: algosdk.AddressWithTransactionSigner,
    links: { recipient: string; amount: bigint; tail: Uint8Array }[],
  ): Promise<void> {
    for (const link of links) {
      await this.payWithdrawal(sender, link.recipient, link.amount, link.tail);
    }
  }

  /**
   * Post a batch and settle it: open, accumulate every chunk, then verify.
   *
   * The inbox entries the batch consumes must already have been filed. `verifyBatch` compares the
   * L1 inbox chain against the batch's fold, so a missing or out-of-order entry fails at the end.
   *
   * The previous batch's payouts must all have been made, or `openBatch` refuses -- see
   * {@link RollupVerifier.drainWithdrawals}. Settling itself needs no funding transaction and
   * touches no box, whatever the batch withdraws.
   *
   * An optional cursor target selects the exclusive end of the unified inbox prefix this batch
   * processes. It defaults to the live cursor and may stop earlier to split a backlog across batches.
   */
  async verifyBatch(
    sender: algosdk.AddressWithTransactionSigner,
    batch: Uint8Array,
    publicValues: Uint8Array,
    options: { inboxCursor?: bigint; proof?: Sp1Groth16Proof } = {},
  ): Promise<void> {
    if (publicValues.byteLength !== 192) {
      throw new Error("public values must be exactly 192 bytes");
    }
    if (!this.proofVerifier) {
      throw new Error(
        "this client has no proof verifier; use RollupVerifier.create or connect",
      );
    }
    this.proofVerifier.validate(options.proof);

    const batchLength = batch.byteLength;
    const senderSigner = { sender: sender.address, signer: sender.txnSigner };
    const settledInboxCursor = await this.settledInboxCursor();
    const targetInboxCursor = options.inboxCursor ?? (await this.inboxCursor());
    const checkpointBoxes =
      targetInboxCursor > settledInboxCursor
        ? [inboxBoxName(targetInboxCursor - 1n)]
        : [];

    await this.appClient.send.openBatch({
      ...senderSigner,
      args: {
        batchLength,
        targetInboxCursor,
      },
      boxReferences: checkpointBoxes,
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

    await this.settlePostedBatch(sender, publicValues, options.proof);
  }

  /** Verify and settle a batch whose open/chunk transactions were submitted separately. */
  async settlePostedBatch(
    sender: algosdk.AddressWithTransactionSigner,
    publicValues: Uint8Array,
    proof?: Sp1Groth16Proof,
  ): Promise<void> {
    if (publicValues.byteLength !== 192) {
      throw new Error("public values must be exactly 192 bytes");
    }

    if (!this.proofVerifier) {
      throw new Error(
        "this client has no proof verifier; use RollupVerifier.create or connect",
      );
    }
    this.proofVerifier.validate(proof);
    const verificationGroup = this.appClient.newGroup();
    await this.proofVerifier.verify(
      verificationGroup,
      this.appClient,
      sender,
      publicValues,
      proof,
    );
    await verificationGroup.send();
  }
}
