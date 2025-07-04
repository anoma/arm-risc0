use risc0_zkvm::Digest;

use crate::{
    aggregation::{
        constants::{SEQUENTIAL_AGGREGATION_PK, SEQUENTIAL_AGGREGATION_VK},
        BatchCU, BatchLP,
    },
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
    ) -> Option<PcdProof> {
        if instances.len() != proofs.len() {
            // Can't aggregate.
            return None;
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
            )?;

            agg = <SequentialAggregation as PCDAggregation>::aggregate_step(&vec![agg], instance);
            agg_proof = vec![proof_out];
        }
        Some(agg_proof.pop().unwrap())
    }

    /// Prove correctness of the transcript induced by a transaction.
    pub fn prove_transaction_aggregation(tx: &Transaction) -> Option<PcdProof> {
        let (instances, proofs) = SequentialAggregation::transaction_transcript(tx)?;
        SequentialAggregation::prove_transcript_aggregation(&instances, &proofs?)
    }

    /// Verifies the correctness of a transcript aggregation.
    pub fn verify_transcript_aggregation(
        instances: &[StepInstance],
        proof: &PcdProof,
    ) -> Option<()> {
        let aggregation = SequentialAggregation::aggregate_transcript(instances);

        // Verify last PCD step for the aggregated instance and proof.
        <SequentialAggregation as PCDAggregation>::verify_step(&aggregation, proof)
    }

    /// Verifies the correctness of the transcript induced by the transaction.
    pub fn verify_transaction_aggregation(tx: &Transaction, proof: &PcdProof) -> Option<()> {
        let (instances, _) = SequentialAggregation::transaction_transcript(tx)?;
        SequentialAggregation::verify_transcript_aggregation(&instances, proof)
    }

    /// Derives the transcript induced by the transaction.
    pub fn transaction_transcript(
        tx: &Transaction,
    ) -> Option<(Vec<StepInstance>, Option<Vec<StepProof>>)> {
        let batch_cu: BatchCU = tx.clone().into();
        let batch_lp: BatchLP = tx.clone().try_into().ok()?;
        let mut step_instances: Vec<StepInstance> = batch_cu.clone().into();
        step_instances.append(&mut <BatchLP as Into<Vec<StepInstance>>>::into(
            batch_lp.clone(),
        ));

        let sp_cu: Option<Vec<StepProof>> = batch_cu.try_into().ok();
        let sp_lp: Option<Vec<StepProof>> = batch_lp.try_into().ok();
        let step_proofs: Option<Vec<StepProof>> = if sp_cu.is_some() && sp_lp.is_some() {
            let mut sp = sp_cu.unwrap();
            sp.append(&mut sp_lp.unwrap());
            Some(sp)
        } else {
            None
        };

        Some((step_instances, step_proofs))
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
