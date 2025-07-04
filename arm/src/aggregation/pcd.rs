use crate::compliance_unit::ComplianceUnit;
use crate::proving_system;
use crate::{compliance::ComplianceInstance, logic_instance::LogicInstance};
use crate::{constants::COMPLIANCE_VK, logic_proof::LogicProof};

use risc0_zkvm::{
    default_prover, Digest, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, VerifierContext,
};
use serde::{Deserialize, Serialize};

use crate::constants::{
    BTREE_AGGREGATION_PK, BTREE_AGGREGATION_VK, SEQUENTIAL_AGGREGATION_PK,
    SEQUENTIAL_AGGREGATION_VK,
};

use super::sequential::SequentialAggregation;

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
        
        #[cfg(feature = "fast_aggregation")]
        let prover_opts = &ProverOpts::fast();

         #[cfg(not(feature = "fast_aggregation"))]
        let prover_opts = &ProverOpts::succinct();
        
        let prover = default_prover();

        // Aggregate and prove step.
        let next_receipt = prover //.prove(env, <Self as PCDAggregation>::proving_key());
            .prove_with_ctx(
                env,
                &VerifierContext::default(),
                <Self as PCDAggregation>::proving_key(),
                &prover_opts,
            );

        match next_receipt {
            Ok(pi) => Some(PcdProof(pi.receipt)),
            Err(_) => None,
        }
    }

    /// Verifies validity of a step aggregation.
    fn verify_step(aggregation: &PcdMessage, proof: &PcdProof) -> bool {
        let (receipt_program_key, receipt_aggregation): (Digest, PcdMessage) =
            proof.extract_outputs();

        // Check the receipt contains the right aggregation key.
        if receipt_program_key != <Self as PCDAggregation>::verifying_key() {
            return false;
        }

        // Check the receipt contains the right aggregation.
        if receipt_aggregation != *aggregation {
            return false;
        }

        // Verify the receipt.
        proof
            .0
            .verify(<Self as PCDAggregation>::verifying_key())
            .is_ok()
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

// Should not fail. TODO: TryFrom.
impl From<LogicProof> for StepInstance {
    fn from(value: LogicProof) -> Self {
        let output: LogicInstance = proving_system::journal_to_instance(&value.instance);
        let image_id: [u8; 32] = value.verifying_key.try_into().unwrap();
        StepInstance::new(output, image_id)
    }
}

// Should not fail. TODO: TryFrom.
impl From<ComplianceUnit> for StepInstance {
    fn from(value: ComplianceUnit) -> Self {
        let output: ComplianceInstance = proving_system::journal_to_instance(&value.instance);
        let image_id = *COMPLIANCE_VK;
        StepInstance::new(output, image_id)
    }
}

/// A proof attesting to the correctness of an [PcdMessage].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcdProof(pub Receipt);

/// A proof attesting to the correctness of a [StepInstance].
#[derive(Debug)]
pub struct StepProof(pub Receipt);

impl PcdProof {
    /// Returns the aggregation program key and the aggregation.
    pub fn extract_outputs(&self) -> (Digest, PcdMessage) {
        let (agg_vk, step_output_digest,step_program_digest): (Digest, Digest, Digest) = self.0
            .journal
            .decode()
            .expect(
            "It should deserialize into the aggregation vk, step outputs digest, and step programs digest.",
        );

        (
            agg_vk,
            PcdMessage {
                step_output_digest,
                step_program_digest,
            },
        )
    }
}

// Should not fail. TODO: TryFrom.
impl From<LogicProof> for StepProof {
    fn from(value: LogicProof) -> Self {
        let inner: InnerReceipt = bincode::deserialize(&value.proof).unwrap();
        let receipt = Receipt::new(inner, value.instance);
        StepProof(receipt)
    }
}

// Should not fail. TODO: TryFrom.
impl From<ComplianceUnit> for StepProof {
    fn from(value: ComplianceUnit) -> Self {
        let inner: InnerReceipt = bincode::deserialize(&value.proof).unwrap();
        let receipt = Receipt::new(inner, value.instance);
        StepProof(receipt)
    }
}

impl PCDAggregation for SequentialAggregation {
    const INPUT_ARITY: usize = 1;

    fn proving_key() -> &'static [u8] {
        SEQUENTIAL_AGGREGATION_PK
    }

    fn verifying_key() -> Digest {
        *SEQUENTIAL_AGGREGATION_VK
    }
}

pub struct BtreeAggregation;

impl PCDAggregation for BtreeAggregation {
    const INPUT_ARITY: usize = 2;

    fn proving_key() -> &'static [u8] {
        BTREE_AGGREGATION_PK
    }

    fn verifying_key() -> Digest {
        *BTREE_AGGREGATION_VK
    }
}
