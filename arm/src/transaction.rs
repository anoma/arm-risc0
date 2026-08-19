//! Host/zkVM engine operations on [`Transaction`]: delta proving and
//! verification, aggregation, receipt handling. The transaction wire types
//! and their pure structural checks live in `anoma-rm-core` and are
//! re-exported here unchanged.

pub use arm_core::transaction::*;

#[cfg(feature = "aggregation")]
use crate::aggregation_instance::AggregationInstance;
use crate::constants::global_kind_table_hash;
#[cfg(all(feature = "aggregation", feature = "prove", feature = "abi_encoding"))]
use crate::constants::BATCH_AGGREGATION_EVM_PK;
#[cfg(all(feature = "aggregation", feature = "abi_encoding"))]
use crate::constants::BATCH_AGGREGATION_EVM_VK;
#[cfg(all(
    feature = "aggregation",
    feature = "prove",
    not(feature = "abi_encoding")
))]
use crate::constants::BATCH_AGGREGATION_PK;
#[cfg(feature = "aggregation")]
use crate::constants::COMPLIANCE_VK;
#[cfg(all(feature = "aggregation", feature = "prove"))]
use crate::{
    aggregation_witness::{ActionWitness, AggregationWitness},
    proving_system::ProofType,
};
#[cfg(all(feature = "aggregation", not(feature = "abi_encoding")))]
use crate::{constants::BATCH_AGGREGATION_VK, utils::words_to_bytes};
#[cfg(feature = "aggregation")]
use risc0_zkvm::Receipt;
#[cfg(all(feature = "aggregation", feature = "prove"))]
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use risc0_zkvm::{Digest, InnerReceipt};

use crate::{
    delta_proof::{self, DeltaInstance},
    error::ArmError,
    logic_proof::LogicVerifier,
};

/// Generates the delta proof for the transaction if it contains a delta witness.
pub fn generate_delta_proof(tx: Transaction) -> Result<Transaction, ArmError> {
    tx.check_representation()?;

    match tx.delta_proof {
        Delta::Witness(ref witness) => {
            let msg = get_delta_msg(&tx)?;
            let proof = delta_proof::prove(&msg, witness)?;
            let delta_proof = Delta::Proof(proof);
            Ok(Transaction {
                actions: tx.actions,
                delta_proof,
                expected_balance: tx.expected_balance,
                aggregation: tx.aggregation,
            })
        }
        Delta::Proof(_) => Ok(tx),
    }
}

/// Verifies all the proofs and corresponding checks in the transaction.
pub fn verify(tx: &Transaction) -> Result<(), ArmError> {
    // A transaction must carry exactly one representation. Rejecting the
    // "both present" case here prevents a crafted transaction from
    // pairing a genuine (but unrelated) aggregation proof with
    // unverified, attacker-controlled `actions` and having the delta /
    // nullifier checks silently run against the unverified `actions`
    // instead of the proof-backed `aggregation.instance`.
    tx.check_representation()?;

    match &tx.delta_proof {
        Delta::Proof(ref proof) => {
            let instance = delta(tx)?;
            delta_proof::verify(proof, &instance)?;

            // Check for nullifier duplication across all compliance units
            nf_duplication_check(tx)?;
            kind_table_commitment_check(tx)?;

            if tx.aggregation.is_some() {
                #[cfg(not(feature = "aggregation"))]
                return Err(ArmError::ProofVerificationFailed(
                    "feature `aggregation` is not enabled".into(),
                ));

                #[cfg(feature = "aggregation")]
                verify_aggregation(tx)?;
            } else {
                let actions = tx.actions.as_ref().ok_or(ArmError::MissingActions)?;
                for action in actions {
                    crate::action::verify(action)?;
                }
            }
            Ok(())
        }
        Delta::Witness(_) => Err(ArmError::ExpectedDeltaProof),
    }
}

/// Checks that all compliance units in the transaction commit to the same kind table,
/// and that the commitment matches the loaded global kind table.
///
/// When `aggregation` is present it is authoritative: the commitment is
/// read from the proof-backed `aggregation.instance` (cross-action
/// consistency was already enforced in-circuit by the aggregation
/// guest), never from `actions`, even if both happen to be populated.
pub fn kind_table_commitment_check(tx: &Transaction) -> Result<(), ArmError> {
    let commitment = if let Some(agg) = &tx.aggregation {
        agg.instance.kind_table_commitment
    } else if let Some(actions) = &tx.actions {
        let mut iter = actions.iter();
        let Some(first) = iter.next() else {
            return Ok(());
        };
        let expected =
            crate::compliance_unit::get_instance(&first.compliance_unit)?.kind_table_commitment;
        for action in iter {
            let commitment = crate::compliance_unit::get_instance(&action.compliance_unit)?
                .kind_table_commitment;
            if commitment != expected {
                return Err(ArmError::KindTableCommitmentMismatch);
            }
        }
        expected
    } else {
        return Err(ArmError::MissingActions);
    };

    let global_hash = global_kind_table_hash().ok_or(ArmError::KindTableNotLoaded)?;
    if commitment != *global_hash {
        return Err(ArmError::KindTableGlobalMismatch);
    }
    Ok(())
}

/// Inner check for nullifier duplication across all compliance units.
///
/// When `aggregation` is present it is authoritative: nullifiers are
/// read from the proof-backed `aggregation.instance`, never from
/// `actions`, even if both happen to be populated on this value.
pub fn nf_duplication_check(tx: &Transaction) -> Result<(), ArmError> {
    if let Some(agg) = &tx.aggregation {
        agg.instance.nf_duplication_check()
    } else if let Some(actions) = &tx.actions {
        let mut seen_nullifiers = std::collections::HashSet::new();
        for action in actions {
            let compliance_instance =
                crate::compliance_unit::get_instance(&action.compliance_unit)?;
            for consumed_nullifier in compliance_instance
                .consumed_publics
                .iter()
                .map(|p| p.resource_nullifier)
            {
                if !seen_nullifiers.insert(consumed_nullifier) {
                    return Err(ArmError::NullifierDuplication);
                }
            }
        }
        Ok(())
    } else {
        Err(ArmError::MissingActions)
    }
}

/// Constructs the delta message as the concatenation of each action's
/// action tree root (32 bytes each).
///
/// When `aggregation` is present it is authoritative; see
/// [`nf_duplication_check`].
fn get_delta_msg(tx: &Transaction) -> Result<Vec<u8>, ArmError> {
    if let Some(agg) = &tx.aggregation {
        Ok(agg.instance.delta_msg())
    } else if let Some(actions) = &tx.actions {
        let mut msg = Vec::with_capacity(actions.len() * 32);
        for action in actions {
            msg.extend(crate::action::get_delta_msg(action)?);
        }
        Ok(msg)
    } else {
        Err(ArmError::MissingActions)
    }
}

/// Returns the DeltaInstance constructed from the sum of all actions'
/// deltas and their message.
///
/// When `aggregation` is present it is authoritative; see
/// [`nf_duplication_check`].
pub fn delta(tx: &Transaction) -> Result<DeltaInstance, ArmError> {
    let msg = get_delta_msg(tx)?;
    if let Some(agg) = &tx.aggregation {
        let points = agg
            .instance
            .actions
            .iter()
            .map(crate::aggregation_instance::delta_projective)
            .collect::<Result<Vec<_>, _>>()?;
        DeltaInstance::new(&points, msg)
    } else if let Some(actions) = &tx.actions {
        let points = actions
            .iter()
            .map(crate::action::delta)
            .collect::<Result<Vec<_>, _>>()?;
        DeltaInstance::new(&points, msg)
    } else {
        Err(ArmError::MissingActions)
    }
}

/// Composes two transactions by concatenating their actions and combining their delta witnesses.
/// Both transactions must carry a `Delta::Witness` and must not have been aggregated.
pub fn compose(tx1: Transaction, tx2: Transaction) -> Result<Transaction, ArmError> {
    tx1.check_representation()
        .map_err(|_| ArmError::CannotComposeAggregated)?;
    tx2.check_representation()
        .map_err(|_| ArmError::CannotComposeAggregated)?;
    let actions1 = tx1.actions.ok_or(ArmError::CannotComposeAggregated)?;
    let actions2 = tx2.actions.ok_or(ArmError::CannotComposeAggregated)?;
    let mut actions = actions1;
    actions.extend(actions2);
    let delta = match (tx1.delta_proof, tx2.delta_proof) {
        (Delta::Witness(witness1), Delta::Witness(witness2)) => {
            Delta::Witness(delta_proof::compose(&witness1, &witness2)?)
        }
        _ => return Err(ArmError::IncompatibleDeltaTypes),
    };
    Ok(Transaction::create(actions, delta))
}

/// Returns all compliance inner receipts in the transaction.
pub fn get_compliance_inner_receipts(tx: &Transaction) -> Result<Vec<InnerReceipt>, ArmError> {
    let mut compliance_inner_receipts = Vec::new();
    for cu in tx.get_compliance_units() {
        let inner_receipt = crate::compliance_unit::get_inner_receipt(cu)?;
        compliance_inner_receipts.push(inner_receipt);
    }
    Ok(compliance_inner_receipts)
}

/// Returns all logic inner receipts in the transaction.
pub fn get_logic_inner_receipts(tx: &Transaction) -> Result<Vec<InnerReceipt>, ArmError> {
    let mut logic_inner_receipts = Vec::new();
    for action in tx.actions.as_deref().unwrap_or(&[]) {
        let logic_inputs = action.get_logic_verifier_inputs();
        for lp in logic_inputs.iter() {
            let inner_receipt = crate::logic_proof::get_inner_receipt(lp)?;
            logic_inner_receipts.push(inner_receipt);
        }
    }
    Ok(logic_inner_receipts)
}

/// Returns all compliance instances in the transaction.
pub fn get_compliance_instances(tx: &Transaction) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    for cu in tx.get_compliance_units() {
        result.push(cu.instance.clone());
    }
    result
}

/// Returns all logic verifiers in the transaction.
pub fn get_logic_verifiers(tx: &Transaction) -> Result<Vec<LogicVerifier>, ArmError> {
    let mut result = Vec::new();
    for action in tx.actions.as_deref().unwrap_or(&[]) {
        let logic_verifiers = crate::action::get_logic_verifiers(action)?;
        result.extend(logic_verifiers);
    }
    Ok(result)
}

/// Returns all logic verifying keys and instances in the transaction.
pub fn get_logic_vks_and_instances(
    tx: &Transaction,
) -> Result<(Vec<Digest>, Vec<Vec<u8>>), ArmError> {
    let mut vks = Vec::new();
    let mut instances = Vec::new();
    for lp in get_logic_verifiers(tx)? {
        vks.push(lp.verifying_key);
        instances.push(lp.instance);
    }
    Ok((vks, instances))
}

/// Aggregates all the transaction proofs.
///
/// On success, `tx.aggregation` is populated with the proof and decoded
/// `AggregationInstance`, and `tx.actions` is set to `None` (the
/// individual proofs and witnesses are no longer needed).
#[cfg(all(feature = "aggregation", feature = "prove"))]
pub fn aggregate(tx: &mut Transaction, proof_type: ProofType) -> Result<(), ArmError> {
    if tx.base_proofs_are_empty() {
        return Err(ArmError::ProveFailed(
            "Cannot aggregate: transaction has already been aggregated (actions is None)".into(),
        ));
    }

    let actions = tx.actions.as_ref().ok_or(ArmError::MissingActions)?;

    if actions.is_empty() {
        return Err(ArmError::ProveFailed(
            "Cannot aggregate: transaction has no actions".into(),
        ));
    }
    let mut env_builder = ExecutorEnv::builder();
    let mut action_witnesses = Vec::with_capacity(actions.len());

    for action in actions {
        let compliance_instance = crate::compliance_unit::get_instance(&action.compliance_unit)?;
        env_builder.add_assumption(crate::compliance_unit::get_inner_receipt(
            &action.compliance_unit,
        )?);

        // Positional matching: logic_verifier_inputs must be in canonical
        // tag order (consumed nullifiers then created commitments), which is
        // the same order ComplianceInstance::tags() produces. This mirrors
        // action::get_logic_verifiers and avoids the silent overwrite that
        // a HashMap would cause when duplicate tags are present.
        let tags: Vec<Digest> = compliance_instance.tags().collect();
        if tags.len() != action.logic_verifier_inputs.len() {
            return Err(ArmError::TagNotFound);
        }
        let n_consumed = compliance_instance.consumed_publics.len();
        let (consumed_lvis, created_lvis) = action.logic_verifier_inputs.split_at(n_consumed);

        let mut consumed_app_data = Vec::with_capacity(n_consumed);
        for (lvi, tag) in consumed_lvis.iter().zip(&tags[..n_consumed]) {
            if lvi.tag != *tag {
                return Err(ArmError::TagNotFound);
            }
            env_builder.add_assumption(crate::logic_proof::get_inner_receipt(lvi)?);
            consumed_app_data.push(lvi.app_data.clone());
        }

        let mut created_app_data = Vec::with_capacity(compliance_instance.created_publics.len());
        for (lvi, tag) in created_lvis.iter().zip(&tags[n_consumed..]) {
            if lvi.tag != *tag {
                return Err(ArmError::TagNotFound);
            }
            env_builder.add_assumption(crate::logic_proof::get_inner_receipt(lvi)?);
            created_app_data.push(lvi.app_data.clone());
        }

        action_witnesses.push(ActionWitness {
            compliance_instance,
            consumed_app_data,
            created_app_data,
        });
    }

    let witnesses = AggregationWitness {
        compliance_key: COMPLIANCE_VK,
        actions: action_witnesses,
    };

    let env = env_builder
        .write(&witnesses)
        .map_err(|_| ArmError::WriteWitnessFailed)?
        .build()
        .map_err(|_| ArmError::BuildProverEnvFailed)?;

    let prover_opts = match proof_type {
        ProofType::Succinct => ProverOpts::succinct(),
        ProofType::Groth16 => ProverOpts::groth16(),
    };

    let prover = default_prover();

    // Prove batch.
    #[cfg(feature = "abi_encoding")]
    let pk = BATCH_AGGREGATION_EVM_PK;
    #[cfg(not(feature = "abi_encoding"))]
    let pk = BATCH_AGGREGATION_PK;

    let agg_receipt = prover
        .prove_with_ctx(env, &VerifierContext::default(), pk, &prover_opts)
        .map_err(|err| ArmError::ProveFailed(format!("Proof generation failed: {}", err)))?
        .receipt;

    // Decode the AggregationInstance from the journal.
    #[cfg(feature = "abi_encoding")]
    let instance: AggregationInstance =
        crate::aggregation_instance::abi_decode_instance(&agg_receipt.journal.bytes)
            .map_err(|_| ArmError::InstanceSerializationFailed)?;
    #[cfg(not(feature = "abi_encoding"))]
    let instance: AggregationInstance = agg_receipt
        .journal
        .decode()
        .map_err(|_| ArmError::InstanceSerializationFailed)?;

    let proof = bincode::serialize(&agg_receipt.inner).map_err(|_| ArmError::SerializationError)?;

    tx.aggregation = Some(Aggregation { proof, instance });
    tx.actions = None;
    Ok(())
}

/// Verifies the aggregated proof of the transaction.
#[cfg(feature = "aggregation")]
pub fn verify_aggregation(tx: &Transaction) -> Result<(), ArmError> {
    tx.check_representation()?;

    let agg = tx
        .aggregation
        .as_ref()
        .ok_or_else(|| ArmError::ProofVerificationFailed("Missing aggregation".into()))?;

    let inner_receipt: InnerReceipt =
        bincode::deserialize(&agg.proof).map_err(|_| ArmError::InnerReceiptDeserializationError)?;

    #[cfg(feature = "abi_encoding")]
    let (journal_bytes, vk) = {
        use crate::aggregation_instance::abi_encode_instance;
        (
            abi_encode_instance(agg.instance.clone()),
            BATCH_AGGREGATION_EVM_VK,
        )
    };
    #[cfg(not(feature = "abi_encoding"))]
    let (journal_bytes, vk) = {
        let words = risc0_zkvm::serde::to_vec(&agg.instance)
            .map_err(|_| ArmError::InstanceSerializationFailed)?;
        (words_to_bytes(&words).to_vec(), BATCH_AGGREGATION_VK)
    };

    let receipt = Receipt::new(inner_receipt, journal_bytes);

    receipt.verify(vk).map_err(|err| {
        ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
    })?;

    if agg.instance.compliance_key != COMPLIANCE_VK {
        return Err(ArmError::ProofVerificationFailed(
            "aggregation compliance_key does not match expected COMPLIANCE_VK".into(),
        ));
    }

    Ok(())
}
