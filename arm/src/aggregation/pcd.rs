use crate::aggregation::{BatchCU, BatchLP};
use crate::constants::COMPLIANCE_VK;
use crate::proving_system;
use crate::utils::words_to_bytes;
use crate::{compliance::ComplianceInstance, logic_instance::LogicInstance};
use risc0_zkvm::{
    default_prover, Digest, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, VerifierContext,
};
use serde::{Deserialize, Serialize};

/// A trait to aggregate proofs across nodes.
///
/// In PCD terminology the [StepInstance] and [StepProof] are
/// the local data of each node. The local data and the input
/// [PcdMessage]s form the witness of the aggregation program.
pub trait PCDAggregation {
    /// Number of input aggregations (and proofs to verify) at each step.
    const INPUT_ARITY: usize;

    /// Returns the ELF of the aggregation program.
    fn proving_key() -> &'static [u8];

    /// Returns (the words of) the image id of the aggregation program.
    fn verifying_key() -> Digest;

    /// Computes the output message from the input messages and the local data.
    fn aggregate_step(
        input_aggregations: &[PcdMessage],
        step_instance: &StepInstance,
    ) -> PcdMessage {
        assert_eq!(
            input_aggregations.len(),
            <Self as PCDAggregation>::INPUT_ARITY,
            "incorrect number of input aggregations"
        );

        let mut h_in_vec = Vec::new();
        let mut d_in_vec = Vec::new();
        for aggregation in input_aggregations {
            h_in_vec.push(aggregation.step_output_digest);
            d_in_vec.push(aggregation.step_program_digest);
        }
        let h_out = crate::hash::commit_step_output_with_sha(&h_in_vec, &step_instance.output);
        let d_out = crate::hash::commit_step_program_with_sha(&d_in_vec, &step_instance.program);

        PcdMessage {
            step_output_digest: h_out,
            step_program_digest: d_out,
        }
    }

    /// Proves correctness of [PCDAggregation::aggregate_step] and
    /// verifies the input [PcdProof]s and [StepProof].
    fn prove_step(
        input_aggregations: &[PcdMessage],
        input_proofs: &[PcdProof],
        step_instance: &StepInstance,
        step_proof: &StepProof,
        output_node: bool,
    ) -> Option<PcdProof> {
        // Sanity check
        assert_eq!(
            input_aggregations.len(),
            <Self as PCDAggregation>::INPUT_ARITY,
            "incorrect number of input aggregations"
        );

        let mut base_case = true;
        if !input_proofs.is_empty() {
            // If not base case
            assert_eq!(
                input_proofs.len(),
                <Self as PCDAggregation>::INPUT_ARITY,
                "incorrect number of input proofs"
            );
            base_case = false;
        }

        let mut env_builder = ExecutorEnv::builder();

        // Add all proofs as assumptions.
        env_builder.add_assumption(step_proof.0.clone());
        if !base_case {
            for ip in input_proofs {
                env_builder.add_assumption(ip.0.clone());
            }
        }

        // Write all inputs. Make sure the corresponding guest circuit
        // reads in the same order.
        env_builder
            .write(&<Self as PCDAggregation>::verifying_key())
            .unwrap();
        for aggregation in input_aggregations {
            env_builder
                .write(&(
                    aggregation.step_output_digest,
                    aggregation.step_program_digest,
                ))
                .unwrap();
        }

        let env = env_builder
            .write(&(&step_instance.program, &step_instance.output.clone()))
            .unwrap()
            .build()
            .unwrap();

        // If not an output node, prove fast.
        let prover_opts = if output_node {
            #[cfg(feature = "fast_aggregation")]
            {
                ProverOpts::fast()
            }

            #[cfg(all(not(feature = "fast_aggregation"), feature = "groth16_aggregation"))]
            {
                ProverOpts::groth16()
            }

            #[cfg(all(
                not(feature = "fast_aggregation"),
                not(feature = "groth16_aggregation")
            ))]
            {
                ProverOpts::succinct()
            }
        } else {
            ProverOpts::fast()
        };

        let prover = default_prover();

        // Prove step.
        let next_receipt = prover.prove_with_ctx(
            env,
            &VerifierContext::default(),
            <Self as PCDAggregation>::proving_key(),
            &prover_opts,
        );

        match next_receipt {
            Ok(pi) => Some(PcdProof(pi.receipt.inner)),
            Err(_) => None,
        }
    }

    /// Verifies validity of a step aggregation.
    fn verify_step(aggregation: &PcdMessage, proof: &PcdProof) -> Option<()> {
        // Form the instance.
        let ag_program_key = <Self as PCDAggregation>::verifying_key();
        let h_out = aggregation.step_output_digest;
        let d_out = aggregation.step_program_digest;
        let pcd_instance = risc0_zkvm::serde::to_vec(&(ag_program_key, h_out, d_out)).ok()?;

        // Verify the receipt.
        let receipt = Receipt::new(proof.0.clone(), words_to_bytes(&pcd_instance).to_vec());
        receipt.verify(ag_program_key).ok()
    }
}

/// The input and output of an aggregation node (step).
#[derive(PartialEq, Debug, Clone)]
pub struct PcdMessage {
    /// A binding commitment to all verified step outputs
    /// that this aggregation attests to.
    pub step_output_digest: Digest,

    /// A binding commitment to all verified step programs
    /// that this aggregation attests to.
    pub step_program_digest: Digest,
}

impl Default for PcdMessage {
    fn default() -> Self {
        PcdMessage {
            step_output_digest: Digest::ZERO,
            step_program_digest: Digest::ZERO,
        }
    }
}

/// The output and program to verify at each aggregation node (step).
/// Thus, an instance of the 'universal relation' that a zkVM realize.
#[derive(Debug, Clone)]
pub struct StepInstance {
    /// The image id (aka verifying key) of the program to verify
    /// at an aggregation node (step).
    pub program: Digest,

    /// The serialized words of the program's output.
    pub output: Vec<u32>,
}

impl StepInstance {
    /// Generic constructor.
    pub fn new<I, VK>(output: I, image_id: VK) -> StepInstance
    where
        I: serde::Serialize,
        VK: Into<Digest>,
    {
        StepInstance {
            program: image_id.into(),
            output: risc0_zkvm::serde::to_vec(&output).unwrap(),
        }
    }
}

impl From<BatchCU> for Vec<StepInstance> {
    fn from(value: BatchCU) -> Self {
        let mut step_instances = Vec::new();
        for cu_instance in value.instances.into_iter() {
            let output: ComplianceInstance = proving_system::journal_to_instance(&cu_instance);
            let image_id = *COMPLIANCE_VK;
            step_instances.push(StepInstance::new(output, image_id));
        }
        step_instances
    }
}

impl From<BatchLP> for Vec<StepInstance> {
    fn from(value: BatchLP) -> Self {
        let mut step_instances = Vec::new();
        for (lp_instance, lp_key) in value.instances.into_iter().zip(value.keys.into_iter()) {
            let output: LogicInstance = proving_system::journal_to_instance(&lp_instance);
            let image_id = lp_key;
            step_instances.push(StepInstance::new(output, image_id));
        }
        step_instances
    }
}

/// A proof attesting to the correctness of an [PcdMessage].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcdProof(pub InnerReceipt);

/// A proof attesting to the correctness of a [StepInstance].
#[derive(Debug)]
pub struct StepProof(pub Receipt);

impl TryFrom<BatchCU> for Vec<StepProof> {
    type Error = &'static str;
    fn try_from(value: BatchCU) -> Result<Self, Self::Error> {
        match value.receipts.clone() {
            None => Err("base proofs are empty"),
            Some(receipts) => Ok(receipts.iter().map(|sp| StepProof(sp.clone())).collect()),
        }
    }
}

impl TryFrom<BatchLP> for Vec<StepProof> {
    type Error = &'static str;
    fn try_from(value: BatchLP) -> Result<Self, Self::Error> {
        match value.receipts {
            None => Err("base proofs are empty"),
            Some(receipts) => Ok(receipts.iter().map(|sp| StepProof(sp.clone())).collect()),
        }
    }
}
