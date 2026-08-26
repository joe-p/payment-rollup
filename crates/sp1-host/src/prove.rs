//! Groth16 proofs of a settlement, generated on the Succinct Prover Network.
//!
//! This is the half of a settlement the rest of the crate cannot produce. [`Settlement`] runs
//! [`payment_rollup::execute`] natively and so already knows the 192 bytes a proof would commit;
//! what it does not have is the proof that the replay happened. That is what a
//! [`Groth16Prover`] adds, and it adds it by running the same `execute` inside the zkVM -- the
//! guest is that function wrapped in io and nothing else.
//!
//! Compiled only under the `prove` feature. See this crate's `Cargo.toml` for why.

use sp1_sdk::{
    Elf, HashableKey, ProvingKey, SP1ProvingKey, SP1Stdin,
    blocking::{NetworkProver, ProveRequest, Prover, ProverClient},
    include_elf,
    network::{NetworkClient, NetworkMode},
};
use std::time::Instant;

use crate::{ProofFixture, Settlement};

/// The guest, compiled for the zkVM by this crate's build script.
pub const GUEST_ELF: Elf = include_elf!("sp1-guest");

/// The credential the network authenticates with, read from the environment by the SDK.
const PRIVATE_KEY_VAR: &str = "NETWORK_PRIVATE_KEY";

/// Feed a settlement to the guest, in the order the guest reads it.
///
/// The five writes are the guest's five `sp1_zkvm::io::read_vec` calls, in that order -- the io is
/// positional, so this function and `sp1-guest`'s `main` have to be read together. It lives here,
/// shared by proving and by [`crate::report`], because two copies of a positional list are two
/// things to keep in step with the guest instead of one.
pub(crate) fn stdin_for(settlement: &Settlement) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&settlement.domain());
    stdin.write_slice(&settlement.old_root());
    stdin.write_slice(&settlement.inbox_chain_from());
    stdin.write_slice(settlement.batch_bytes());
    stdin.write_slice(settlement.sidecar_bytes());

    stdin
}

/// A network connection and a set-up proving key, held together so a run of several scenarios pays
/// for the setup once.
///
/// Setup is a function of the ELF alone, and the ELF does not change between scenarios, so
/// rebuilding this per block would be spending minutes to arrive back at the same proving key.
pub struct Groth16Prover {
    client: NetworkProver,
    pk: SP1ProvingKey,
    vkey: String,
}

impl Groth16Prover {
    /// Connect to the network and set up the guest program.
    ///
    /// `network` is a [`NetworkMode`] name: `mainnet` (equivalently `auction`) or `reserved`
    /// (equivalently `hosted`).
    pub fn new(network: &str) -> Result<Self, String> {
        let mode: NetworkMode = network.parse()?;
        dotenvy::dotenv().ok();

        // Checked here only to fail cleanly. The SDK reads the variable itself, and panics rather
        // than returns when it is missing -- a panic out of a CLI reads as a bug in the tool
        // rather than as the missing credential it is.
        if !std::env::var(PRIVATE_KEY_VAR).is_ok_and(|key| !key.is_empty()) {
            return Err(format!(
                "{PRIVATE_KEY_VAR} is not set -- proving on the network needs the Secp256k1 key \
                 the requests are signed with"
            ));
        }

        let client = ProverClient::builder()
            .network_for(NetworkMode::Reserved)
            .rpc_url("http://127.0.0.1:50061")
            .build();

        let started = Instant::now();
        let pk = client
            .setup(GUEST_ELF)
            .map_err(|error| format!("setting the guest program up failed: {error}"))?;
        let vkey = pk.verifying_key().bytes32();
        eprintln!(
            "prover ready in {:?} ({network}, vkey {vkey})",
            started.elapsed()
        );

        Ok(Self { client, pk, vkey })
    }

    /// The program's verifying key, which is what a verifier has to be pinned to.
    ///
    /// One per ELF rather than one per block, which is why it is read off the prover rather than
    /// out of a proof.
    pub fn vkey(&self) -> &str {
        &self.vkey
    }

    /// Prove one settlement, and check the proof agrees with the native replay before returning it.
    pub fn prove(&self, settlement: &Settlement) -> Result<ProofFixture, String> {
        let stdin = stdin_for(settlement);

        let started = Instant::now();
        let proof = self
            .client
            .prove(&self.pk, stdin)
            .groth16()
            .run()
            .map_err(|error| format!("the network failed to prove the block: {error}"))?;
        eprintln!("  proved in {:?}", started.elapsed());

        // The guest and the host run the same `execute`, so these two disagreeing means the zkVM
        // and native builds have drifted apart -- which is the one thing worth failing loudly over
        // rather than writing into a fixture and shipping.
        if proof.public_values.as_slice() != settlement.public_values().as_slice() {
            return Err(
                "the proof commits public values the native replay did not produce".to_string(),
            );
        }

        // Read before the proof is taken apart: this is the encoding an onchain verifier takes,
        // and it is assembled from the selector and the proof together.
        let bytes = proof.bytes();

        let groth16 = proof.proof.try_as_groth_16().ok_or_else(|| {
            "the network returned something other than a Groth16 proof".to_string()
        })?;

        Ok(ProofFixture {
            bytes,
            vkey: self.vkey.clone(),
            public_inputs: groth16.public_inputs,
            encoded_proof: groth16.encoded_proof,
            verifier_hash: groth16.groth16_vkey_hash,
        })
    }
}
