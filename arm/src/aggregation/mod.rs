use risc0_zkvm::{Digest, InnerReceipt, Receipt};
use serde::{Deserialize, Serialize};

use crate::{
    aggregation::{batch::BatchProof, pcd::PcdProof},
    compliance_unit::ComplianceUnit,
    logic_proof::LogicVerifier,
    transaction::Transaction,
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

/// Holds the compliance instances, and compliance proofs (if all present)
/// of a transaction.
#[derive(Debug, Clone)]
pub(crate) struct BatchCU {
    pub(crate) instances: Vec<Vec<u8>>,
    pub(crate) receipts: Option<Vec<Receipt>>,
}

impl From<Transaction> for BatchCU {
    fn from(value: Transaction) -> Self {
        let cus: Vec<ComplianceUnit> = value
            .actions
            .iter()
            .flat_map(|a| a.get_compliance_units().clone())
            .collect();

        let cu_instances: Vec<Vec<u8>> = cus.iter().map(|cu| cu.instance.clone()).collect();

        let inner_receipts: Option<Vec<InnerReceipt>> = if base_proofs_are_empty(&value) {
            None
        } else {
            let inner_receipts: Vec<Result<InnerReceipt, _>> = cus
                .iter()
                .map(|cu| {
                    let inner: Result<InnerReceipt, _> =
                        bincode::deserialize(&cu.proof.clone().unwrap());
                    inner
                })
                .collect();
            let ir: Result<Vec<InnerReceipt>, _> = inner_receipts.into_iter().collect();
            ir.ok()
        };

        match inner_receipts {
            None => BatchCU {
                instances: cu_instances,
                receipts: None,
            },
            Some(ir_vec) => {
                let r: Vec<Receipt> = ir_vec
                    .into_iter()
                    .zip(cu_instances.clone())
                    .map(|(ir, i)| Receipt::new(ir, i))
                    .collect();

                BatchCU {
                    instances: cu_instances,
                    receipts: Some(r),
                }
            }
        }
    }
}

/// Holds resource logic instances, keys, and proofs (if all present).
#[derive(Debug, Clone)]
pub(crate) struct BatchLP {
    pub(crate) instances: Vec<Vec<u8>>,
    pub(crate) keys: Vec<Digest>,
    pub(crate) receipts: Option<Vec<Receipt>>,
}

impl TryFrom<Transaction> for BatchLP {
    type Error = &'static str;

    fn try_from(value: Transaction) -> Result<Self, Self::Error> {
        let mut lps: Vec<LogicVerifier> = Vec::new();

        for action in value.actions.iter() {
            let mut lp_vec: Vec<LogicVerifier> = action.clone().try_into()?;
            lps.append(&mut lp_vec);
        }

        let logic_instances: Vec<Vec<u8>> = lps.iter().map(|lp| lp.instance.clone()).collect();

        let inner_receipts: Option<Vec<InnerReceipt>> = if base_proofs_are_empty(&value) {
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

        let keys_arr: Result<Vec<[u32; 8]>, _> = lps
            .into_iter()
            .map(|lp| lp.verifying_key.try_into())
            .collect();
        if keys_arr.is_err() {
            return Err("Error converting resource logic verification keys into digests");
        }
        let keys = keys_arr.unwrap().into_iter().map(Digest::new).collect();

        match inner_receipts {
            None => Ok(BatchLP {
                instances: logic_instances,
                keys,
                receipts: None,
            }),
            Some(ir_vec) => {
                let r: Vec<Receipt> = ir_vec
                    .into_iter()
                    .zip(logic_instances.clone())
                    .map(|(ir, i)| Receipt::new(ir, i))
                    .collect();

                let batch_lp = BatchLP {
                    instances: logic_instances,
                    keys,
                    receipts: Some(r),
                };
                Ok(batch_lp)
            }
        }
    }
}

/// Returns `true` if any compliance or resource logic proof is `None`.
fn base_proofs_are_empty(tx: &Transaction) -> bool {
    for a in tx.actions.iter() {
        if a.get_compliance_units().iter().any(|cu| cu.proof.is_none()) {
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
