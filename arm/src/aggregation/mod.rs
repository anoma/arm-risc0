use risc0_zkvm::{Digest, InnerReceipt, Receipt};
use serde::{Deserialize, Serialize};

use crate::{
    aggregation::{batch::BatchProof, pcd::PcdProof},
    compliance::CIWords,
    compliance_unit::sigma::SigmaProtocol,
    compliance_unit::CUInner,
    constants::COMPLIANCE_SIGMABUS_VK,
    error::ArmError,
    logic_proof::LogicVerifier,
    transaction::Transaction,
    utils::bytes_to_words,
};

pub mod batch;
pub mod constants;
pub mod pcd;
pub mod sequential;

/// Supported strategies to aggregate.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AggregationStrategy {
    Sequential,
    Batch,
}

/// Aggregation proof discriminating by strategies.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum AggregationProof {
    /// A PCD-based aggregation proof generated with a sequential transcript.
    Sequential(PcdProof),
    /// A batch aggregation proof.
    Batch(BatchProof),
}

/// Holds the compliance instances, compliance key, and compliance proofs (if all present)
/// of a transaction.
#[derive(Debug, Clone)]
pub(crate) struct BatchCU {
    pub(crate) instances: Vec<CIWords>,
    pub(crate) compliance_vk: Digest,
    pub(crate) receipts: Option<Vec<Receipt>>,
}

/// Holds resource logic instances, keys, and proofs (if all present).
#[derive(Debug, Clone)]
pub(crate) struct BatchLP {
    pub(crate) instances: Vec<Vec<u32>>,
    pub(crate) keys: Vec<Digest>,
    pub(crate) receipts: Option<Vec<Receipt>>,
}

impl<ComplianceUnit: CUInner> Transaction<ComplianceUnit> {
    fn get_batch_cu(&self) -> Result<BatchCU, ArmError> {
        let cus: Vec<&ComplianceUnit> = self
            .actions
            .iter()
            .flat_map(|a| a.get_compliance_units())
            .collect();

        let cu_instances_words: Vec<CIWords> = cus
            .iter()
            .map(|cu| cu.circuit_instance_words())
            .collect::<Result<_, _>>()?;

        let cu_instances_bytes: Vec<&[u8]> =
            cus.iter().map(|cu| cu.circuit_instance_bytes()).collect();

        let inner_receipts: Option<Vec<InnerReceipt>> = if self.base_proofs_are_empty() {
            None
        } else {
            let inner_receipts: Vec<Result<InnerReceipt, _>> = cus
                .iter()
                .map(|cu| {
                    let inner: Result<InnerReceipt, _> =
                        bincode::deserialize(cu.circuit_proof_bytes().unwrap());
                    inner
                })
                .collect();
            let ir: Result<Vec<InnerReceipt>, _> = inner_receipts.into_iter().collect();
            ir.ok()
        };

        match inner_receipts {
            None => Ok(BatchCU {
                instances: cu_instances_words,
                compliance_vk: ComplianceUnit::verifying_key(),
                receipts: None,
            }),
            Some(ir_vec) => {
                let r: Vec<Receipt> = ir_vec
                    .into_iter()
                    .zip(cu_instances_bytes)
                    .map(|(ir, i)| Receipt::new(ir, i.to_vec()))
                    .collect();

                Ok(BatchCU {
                    instances: cu_instances_words,
                    compliance_vk: ComplianceUnit::verifying_key(),
                    receipts: Some(r),
                })
            }
        }
    }

    fn get_batch_lp(&self) -> Result<BatchLP, ArmError> {
        let mut lps: Vec<LogicVerifier> = Vec::new();

        for action in self.actions.iter() {
            let mut lp_vec: Vec<LogicVerifier> = action.get_logic_verifiers()?;
            lps.append(&mut lp_vec);
        }

        let (logic_instances_bytes, logic_instances_words): (Vec<Vec<u8>>, Vec<Vec<u32>>) = lps
            .iter()
            .map(|lp| (lp.instance.clone(), bytes_to_words(&lp.instance)))
            .unzip();

        let inner_receipts: Option<Vec<InnerReceipt>> = if self.base_proofs_are_empty() {
            None
        } else {
            let inner_receipts: Vec<Result<InnerReceipt, _>> = lps
                .iter()
                .map(|lp| {
                    let inner: Result<InnerReceipt, _> =
                        bincode::deserialize(&lp.proof.clone().unwrap());
                    inner
                })
                .collect();
            let ir: Result<Vec<InnerReceipt>, _> = inner_receipts.into_iter().collect();
            ir.ok()
        };

        let keys = lps.into_iter().map(|lp| lp.verifying_key).collect();

        match inner_receipts {
            None => Ok(BatchLP {
                instances: logic_instances_words,
                keys,
                receipts: None,
            }),
            Some(ir_vec) => {
                let r: Vec<Receipt> = ir_vec
                    .into_iter()
                    .zip(logic_instances_bytes.clone())
                    .map(|(ir, i)| Receipt::new(ir, i))
                    .collect();

                let batch_lp = BatchLP {
                    instances: logic_instances_words,
                    keys,
                    receipts: Some(r),
                };
                Ok(batch_lp)
            }
        }
    }

    /// Returns `true` if any compliance or resource logic proof is `None`.
    fn base_proofs_are_empty(&self) -> bool {
        for a in self.actions.iter() {
            if a.get_compliance_units()
                .iter()
                .any(|cu| cu.circuit_proof_bytes().is_none())
            {
                return true;
            }
            if a.get_logic_verifier_inputs()
                .iter()
                .any(|lp| lp.proof.is_none())
            {
                return true;
            }
        }

        false
    }

    /// Batch-verifies the sigma proofs for Sigmabus compliance units.
    /// For any other unit type, it does nothing.
    fn verify_sigmas_maybe(&self) -> Result<(), ArmError> {
        if ComplianceUnit::verifying_key() == *COMPLIANCE_SIGMABUS_VK {
            println!("[DEBUG:] veryfying sigmas");
            let mut deltas = Vec::new();
            let mut sigmaproofs = Vec::new();
            for a in self.actions.iter() {
                for cu in a.get_compliance_units() {
                    let delta_sp = cu.get_sigma_verifier_inputs()?;
                    deltas.push(delta_sp.0);
                    sigmaproofs.push(delta_sp.1);
                }
            }
            SigmaProtocol::batch_verify(&deltas, &sigmaproofs)
        } else {
            // Do nothing
            Ok(())
        }
    }
}
