use crate::transaction::Transaction;

use super::pcd::{PCDAggregation, PcdMessage, PcdProof, StepInstance, StepProof};

pub struct SequentialAggregation;

impl SequentialAggregation {
    /// Aggregate instances in a transcript.
    pub fn aggregate_transcript(instances: &[StepInstance]) -> PcdMessage {
        let mut aggregated_instances = PcdMessage::default();

        for instance in instances {
            aggregated_instances = <SequentialAggregation as PCDAggregation>::aggregate_step(
                &[aggregated_instances],
                instance,
            );
        }

        aggregated_instances
    }

    /// Prove correctnes of an aggregation trasncript.
    pub fn prove_transcript_aggregation(
        instances: &[StepInstance],
        proofs: &[StepProof],
    ) -> Option<PcdProof> {
        if instances.len() != proofs.len() {
            // Can't aggregate.
            return None;
        }

        let mut agg = PcdMessage::default();
        let mut agg_proof = Vec::new();
        for (instance, proof) in instances.iter().zip(proofs.iter()) {
            let proof_out = <SequentialAggregation as PCDAggregation>::prove_step(
                &[agg.clone()],
                &agg_proof,
                instance,
                proof,
            )?;

            (_, agg) = proof_out.extract_outputs();
            agg_proof = vec![proof_out];
        }
        Some(agg_proof.pop().unwrap())
    }

    /// Prove correctnes of the transcript induced by a transaction.
    pub fn prove_transaction_aggregation(tx: &Transaction) -> Option<PcdProof> {
        let (instances, proofs) = SequentialAggregation::transaction_transcript(tx);
        SequentialAggregation::prove_transcript_aggregation(&instances, &proofs)
    }

    /// Verifies the correctness of the transcript induced by the transaction.
    pub fn verify_transaction_aggregation(tx: &Transaction, proof: &PcdProof) -> bool {
        let (instances, _) = SequentialAggregation::transaction_transcript(tx);
        let aggregation = SequentialAggregation::aggregate_transcript(&instances);

        // Verify last PCD step for the aggregated instance and proof.
        <SequentialAggregation as PCDAggregation>::verify_step(&aggregation, proof)
    }

    /// Derives the transcript induced by the transaction.
    pub fn transaction_transcript(tx: &Transaction) -> (Vec<StepInstance>, Vec<StepProof>) {
        let mut step_instances: Vec<StepInstance> = Vec::new();
        let mut step_proofs: Vec<StepProof> = Vec::new();

        for action in tx.actions.iter() {
            for cu in action.get_compliance_units() {
                step_instances.push(cu.clone().into());
                step_proofs.push(cu.clone().into());
            }
            for logic_proof in action.logic_verifier_inputs.iter() {
                step_instances.push(logic_proof.clone().into());
                step_proofs.push(logic_proof.clone().into());
            }
        }

        (step_instances, step_proofs)
    }
}
