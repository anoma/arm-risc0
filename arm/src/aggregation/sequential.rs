use risc0_zkvm::Digest;

use crate::{
    aggregation::constants::{SEQUENTIAL_AGGREGATION_PK, SEQUENTIAL_AGGREGATION_VK},
    error::ArmError,
    proving_system::ProofType,
    transaction::Transaction,
};

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

    /// Prove correctness of an aggregation transcript.
    pub fn prove_transcript_aggregation(
        instances: &[StepInstance],
        proofs: &[StepProof],
        proof_type: ProofType,
    ) -> Result<PcdProof, ArmError> {
        if instances.len() != proofs.len() {
            // Can't aggregate.
            return Err(ArmError::ProveFailed(
                "Mismatch in number of individual instances and proofs".into(),
            ));
        }

        let mut agg = PcdMessage::default();
        let mut agg_proof = Vec::new();
        for (pos, (instance, proof)) in instances.iter().zip(proofs.iter()).enumerate() {
            let proof_out = <SequentialAggregation as PCDAggregation>::prove_step(
                &[agg.clone()],
                &agg_proof,
                instance,
                proof,
                pos == instances.len() - 1,
                proof_type,
            )?;

            agg = <SequentialAggregation as PCDAggregation>::aggregate_step(&[agg], instance);
            agg_proof = vec![proof_out];
        }
        agg_proof
            .pop()
            .ok_or(ArmError::ProveFailed("Error popping out pcd proof".into()))
    }

    /// Prove correctness of the transcript induced by a transaction.
    pub fn prove_transaction_aggregation(
        tx: &Transaction,
        proof_type: ProofType,
    ) -> Result<PcdProof, ArmError> {
        if let (instances, Some(proofs)) = &SequentialAggregation::transaction_transcript(tx)? {
            SequentialAggregation::prove_transcript_aggregation(instances, proofs, proof_type)
        } else {
            Err(ArmError::ProveFailed(
                "Error deriving transcript for proving (individual instances and proofs)".into(),
            ))
        }
    }

    /// Verifies the correctness of a transcript aggregation.
    pub fn verify_transcript_aggregation(
        instances: &[StepInstance],
        proof: &PcdProof,
    ) -> Result<(), ArmError> {
        let aggregation = SequentialAggregation::aggregate_transcript(instances);

        // Verify last PCD step for the aggregated instance and proof.
        <SequentialAggregation as PCDAggregation>::verify_step(&aggregation, proof)
    }

    /// Verifies the correctness of the transcript induced by the transaction.
    pub fn verify_transaction_aggregation(
        tx: &Transaction,
        proof: &PcdProof,
    ) -> Result<(), ArmError> {
        let (instances, _) = SequentialAggregation::transaction_transcript(tx)?;
        SequentialAggregation::verify_transcript_aggregation(&instances, proof)
    }

    /// Derives the transcript induced by the transaction.
    pub fn transaction_transcript(
        tx: &Transaction,
    ) -> Result<(Vec<StepInstance>, Option<Vec<StepProof>>), ArmError> {
        let batch_cu = tx.get_batch_cu();
        let batch_lp = tx.get_batch_lp()?;
        let mut step_instances: Vec<StepInstance> = batch_cu.clone().try_into()?;
        step_instances.append(
            &mut <super::BatchLP as TryInto<Vec<StepInstance>>>::try_into(batch_lp.clone())?,
        );

        let sp_cu: Option<Vec<StepProof>> = batch_cu.try_into().ok();
        let sp_lp: Option<Vec<StepProof>> = batch_lp.try_into().ok();

        // We need the step proofs to prove aggregation, but not to verify the aggregation.
        let mut step_proofs: Option<Vec<StepProof>> = None;
        if let (Some(sp_cu), Some(mut sp_lp)) = (sp_cu, sp_lp) {
            let mut sp = sp_cu;
            sp.append(&mut sp_lp);
            step_proofs = Some(sp);
        };

        Ok((step_instances, step_proofs))
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
