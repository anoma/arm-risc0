//! Host/zkVM engine operations on [`Transaction`]: delta proving and
//! verification, aggregation, receipt handling. The transaction wire types
//! and their pure structural checks live in `anoma-rm-core` and are
//! re-exported here unchanged.

pub use arm_core::transaction::*;

#[cfg(feature = "aggregation")]
use crate::aggregation_instance::AggregationInstance;
#[cfg(all(feature = "aggregation", feature = "prove"))]
use crate::constants::BATCH_AGGREGATION_EVM_PK;
#[cfg(feature = "aggregation")]
use crate::constants::BATCH_AGGREGATION_EVM_VK;
#[cfg(all(feature = "aggregation", feature = "prove"))]
use crate::constants::BATCH_AGGREGATION_PK;
#[cfg(feature = "aggregation")]
use crate::constants::{BATCH_AGGREGATION_VK, COMPLIANCE_VK};
use crate::proving_system::JournalEncoding;
#[cfg(feature = "aggregation")]
use crate::utils::words_to_bytes;
#[cfg(all(feature = "aggregation", feature = "prove"))]
use crate::{
    action::Action,
    aggregation_witness::{ActionWitness, AggregationWitness},
    proving_system::ProofType,
};
use risc0_zkvm::InnerReceipt;
#[cfg(feature = "aggregation")]
use risc0_zkvm::Receipt;
#[cfg(all(feature = "aggregation", feature = "prove"))]
use risc0_zkvm::{default_prover, ExecutorEnv, ExecutorEnvBuilder, ProverOpts, VerifierContext};

use crate::{
    delta_proof::{self, DeltaInstance},
    error::ArmError,
    logic_proof::LogicVerifier,
    Digest,
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
///
/// `kind_tree_root` is the expected Merkle root of the kind tree for the
/// target chain. Callers that use the loaded global tree should obtain it
/// via `kind_tree_root()` and propagate the `None` case as an error rather
/// than panicking.
///
/// `encoding` selects how the batch aggregation journal is interpreted when
/// the transaction carries an aggregation proof. Pass [`JournalEncoding::Risc0Serde`]
/// for the default RISC Zero / Solana path or [`JournalEncoding::Abi`] for the
/// EVM path. For non-aggregated transactions the parameter is ignored.
pub fn verify(
    tx: &Transaction,
    kind_tree_root: Digest,
    encoding: JournalEncoding,
) -> Result<(), ArmError> {
    // A transaction must carry exactly one representation. Rejecting the
    // "both present" case here prevents a crafted transaction from
    // pairing a genuine (but unrelated) aggregation proof with
    // unverified, attacker-controlled `actions` and having the delta /
    // nullifier checks silently run against the unverified `actions`
    // instead of the proof-backed `aggregation.instance`.
    tx.check_representation()?;

    // `encoding` is only consumed inside the `#[cfg(feature = "aggregation")]` path below;
    // this binding suppresses the unused-variable warning when that feature is off.
    #[cfg(not(feature = "aggregation"))]
    let _ = encoding;

    match &tx.delta_proof {
        Delta::Proof(ref proof) => {
            let instance = delta(tx)?;
            delta_proof::verify(proof, &instance)?;

            // Check for nullifier duplication across all compliance units
            nf_duplication_check(tx)?;
            kind_tree_root_check(tx, kind_tree_root)?;

            if tx.aggregation.is_some() {
                #[cfg(not(feature = "aggregation"))]
                return Err(ArmError::ProofVerificationFailed(
                    "feature `aggregation` is not enabled".into(),
                ));

                #[cfg(feature = "aggregation")]
                verify_aggregation(tx, encoding)?;
            } else {
                let actions = tx.actions.as_ref().ok_or(ArmError::MissingActions)?;
                for (action_index, action) in actions.iter().enumerate() {
                    crate::action::verify(action).map_err(|source| ArmError::InAction {
                        action: action_index,
                        source: Box::new(source),
                    })?;
                }
            }
            Ok(())
        }
        Delta::Witness(_) => Err(ArmError::ExpectedDeltaProof),
    }
}

/// Checks that all compliance units in the transaction commit to a consistent
/// kind tree root, and that the effective root matches `expected`.
///
/// Actions that committed [`arm_core::merkle_path::PADDING_LEAF`] (no kind
/// tree used) are compatible with any root; only actions with a real root
/// participate in the consistency check. The effective root is the shared
/// real root, or `PADDING_LEAF` if every action used none.
///
/// A transaction whose effective root is `PADDING_LEAF` (all resources fell
/// back to `hash_to_curve`) passes the check regardless of `expected`:
/// such a transaction is not bound to any kind tree and is valid on any
/// chain.
///
/// When `aggregation` is present it is authoritative: the root is read from
/// the proof-backed `aggregation.instance` (cross-action consistency was
/// already enforced in-circuit by the aggregation guest), never from
/// `actions`, even if both happen to be populated.
pub fn kind_tree_root_check(tx: &Transaction, expected: Digest) -> Result<(), ArmError> {
    let padding = arm_core::merkle_path::PADDING_LEAF;

    let root = if let Some(agg) = &tx.aggregation {
        agg.instance.kind_tree_root
    } else if let Some(actions) = &tx.actions {
        let mut effective: Option<Digest> = None;
        for action in actions {
            let r = crate::compliance_unit::get_instance(&action.compliance_unit)?.kind_tree_root;
            if r != padding {
                match effective {
                    None => effective = Some(r),
                    Some(prev) if prev != r => return Err(ArmError::KindTreeRootMismatch),
                    _ => {}
                }
            }
        }
        effective.unwrap_or(padding)
    } else {
        return Err(ArmError::MissingActions);
    };

    if root != padding && root != expected {
        return Err(ArmError::KindTreeRootExpectedMismatch);
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
                .resource_instances
                .iter()
                .filter(|p| p.is_consumed())
                .map(|p| p.tag())
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
    tx1.check_representation()?;
    tx2.check_representation()?;
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

/// The batch aggregation guest's input for `actions`: the witness the guest
/// reads, with each action's compliance proof and each of its logic proofs
/// added to `env_builder` as assumptions. `compliance_vk` is the compliance
/// circuit's verifying key the guest checks the compliance proofs against.
///
/// [`aggregate`] proves with this input on the default prover; a caller with
/// its own prover builds the same input here and adds its own executor
/// settings to `env_builder`.
#[cfg(all(feature = "aggregation", feature = "prove"))]
pub fn aggregation_witness(
    actions: &[Action],
    compliance_vk: Digest,
    env_builder: &mut ExecutorEnvBuilder<'_>,
) -> Result<AggregationWitness, ArmError> {
    let mut action_witnesses = Vec::with_capacity(actions.len());

    for (action_index, action) in actions.iter().enumerate() {
        let in_action = |source: ArmError| ArmError::InAction {
            action: action_index,
            source: Box::new(source),
        };
        let compliance_instance = crate::compliance_unit::get_instance(&action.compliance_unit)?;
        env_builder.add_assumption(crate::compliance_unit::get_inner_receipt(
            &action.compliance_unit,
        )?);

        // Positional matching: logic_verifier_inputs must be in the order of
        // the unit's resources, which is the same order
        // ComplianceInstance::tags() produces. This mirrors
        // action::get_logic_verifiers and avoids the silent overwrite that
        // a HashMap would cause when duplicate tags are present.
        let tags: Vec<Digest> = compliance_instance.tags().collect();
        if tags.len() != action.logic_verifier_inputs.len() {
            return Err(in_action(ArmError::LogicVerifierInputCountMismatch {
                expected: tags.len(),
                found: action.logic_verifier_inputs.len(),
            }));
        }

        let mut app_data = Vec::with_capacity(tags.len());
        for (position, (lvi, tag)) in action.logic_verifier_inputs.iter().zip(&tags).enumerate() {
            if lvi.tag != *tag {
                return Err(in_action(ArmError::LogicVerifierTagMismatch {
                    position,
                    expected: *tag,
                    found: lvi.tag,
                }));
            }
            env_builder.add_assumption(crate::logic_proof::get_inner_receipt(lvi)?);
            app_data.push(lvi.app_data.clone());
        }

        action_witnesses.push(ActionWitness {
            compliance_instance,
            app_data,
        });
    }

    Ok(AggregationWitness {
        compliance_vk,
        actions: action_witnesses,
    })
}

/// Aggregates all the transaction proofs.
///
/// `encoding` controls which batch aggregation ELF is used and how the
/// resulting journal is decoded:
/// - [`JournalEncoding::Risc0Serde`] uses the standard RISC Zero / Solana ELF
///   and decodes the journal with `risc0_zkvm::serde`.
/// - [`JournalEncoding::Abi`] uses the EVM ABI ELF and ABI-decodes the journal.
///
/// On success, `tx.aggregation` is populated with the proof and decoded
/// `AggregationInstance`, and `tx.actions` is set to `None` (the
/// individual proofs and witnesses are no longer needed).
#[cfg(all(feature = "aggregation", feature = "prove"))]
pub fn aggregate(
    tx: &mut Transaction,
    proof_type: ProofType,
    encoding: JournalEncoding,
) -> Result<(), ArmError> {
    tx.check_representation()?;

    let actions = tx.actions.as_ref().ok_or(ArmError::AlreadyAggregated)?;

    if actions.is_empty() {
        return Err(ArmError::EmptyActions);
    }

    let mut env_builder = ExecutorEnv::builder();
    let witnesses = aggregation_witness(actions, COMPLIANCE_VK, &mut env_builder)?;

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
    let pk = match encoding {
        JournalEncoding::Risc0Serde => BATCH_AGGREGATION_PK,
        JournalEncoding::Abi => BATCH_AGGREGATION_EVM_PK,
    };

    let agg_receipt = prover
        .prove_with_ctx(env, &VerifierContext::default(), pk, &prover_opts)
        .map_err(|err| ArmError::ProveFailed(format!("Proof generation failed: {}", err)))?
        .receipt;

    // Decode the AggregationInstance from the journal.
    let instance: AggregationInstance = match encoding {
        JournalEncoding::Risc0Serde => agg_receipt
            .journal
            .decode()
            .map_err(|_| ArmError::InstanceSerializationFailed)?,
        JournalEncoding::Abi => {
            crate::aggregation_instance::abi_decode_instance(&agg_receipt.journal.bytes)
                .map_err(|_| ArmError::InstanceSerializationFailed)?
        }
    };

    let proof =
        bincode::serialize(&agg_receipt.inner).map_err(|_| ArmError::SerializationFailed)?;

    tx.aggregation = Some(Aggregation { proof, instance });
    tx.actions = None;
    Ok(())
}

/// Verifies the aggregated proof of the transaction.
///
/// `encoding` must match the encoding used when the proof was generated
/// (i.e. the same value passed to [`aggregate`]). The journal bytes are
/// re-derived from `tx.aggregation.instance` using the chosen encoding and
/// checked against the receipt's commitment. Passing the wrong encoding
/// causes proof verification to fail.
#[cfg(feature = "aggregation")]
pub fn verify_aggregation(tx: &Transaction, encoding: JournalEncoding) -> Result<(), ArmError> {
    tx.check_representation()?;

    let agg = tx
        .aggregation
        .as_ref()
        .ok_or(ArmError::MissingAggregation)?;

    if agg.instance.compliance_vk != COMPLIANCE_VK {
        return Err(ArmError::VerifyingKeyMismatch);
    }

    let inner_receipt: InnerReceipt = bincode::deserialize(&agg.proof)
        .map_err(|_| ArmError::InnerReceiptDeserializationFailed)?;

    let (journal_bytes, vk) = match encoding {
        JournalEncoding::Risc0Serde => {
            let words = risc0_zkvm::serde::to_vec(&agg.instance)
                .map_err(|_| ArmError::InstanceSerializationFailed)?;
            (words_to_bytes(&words).to_vec(), BATCH_AGGREGATION_VK)
        }
        JournalEncoding::Abi => {
            use crate::aggregation_instance::abi_encode_instance;
            (
                abi_encode_instance(agg.instance.clone()),
                BATCH_AGGREGATION_EVM_VK,
            )
        }
    };

    let receipt = Receipt::new(inner_receipt, journal_bytes);

    receipt.verify(vk).map_err(|err| {
        ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
    })?;

    Ok(())
}
