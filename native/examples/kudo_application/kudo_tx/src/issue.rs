use aarm::{
    action::Action,
    transaction::{Delta, Transaction},
};
use aarm_core::{compliance::ComplianceWitness, delta_proof::DeltaWitness};
use denomination_logic::DENOMINATION_ELF;
use kudo_core::{
    denomination_logic_witness::DenominationLogicWitness, kudo_logic_witness::KudoLogicWitness,
    receive_logic_witness::ReceiveLogicWitness,
};
use kudo_logic::KUDO_LOGIC_ELF;
use receive_logic::RECEIVE_ELF;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct IssueWitness {
    issued_kudo_witness: KudoLogicWitness,
    issued_denomination_witness: DenominationLogicWitness,
    issued_receive_witness: ReceiveLogicWitness,
    ephemeral_kudo_witness: KudoLogicWitness,
    ephemeral_denomination_witness: DenominationLogicWitness,
}

impl IssueWitness {
    pub fn create_tx(&self) -> Transaction {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units
            // Compliance unit 1: the ephemeral_kudo_resource and the issued_kudo_resource
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness = ComplianceWitness::from_resources(
                    self.ephemeral_kudo_witness.kudo_resource.clone(),
                    self.ephemeral_kudo_witness.nf_key.clone(),
                    self.issued_kudo_witness.kudo_resource.clone(),
                );

                (
                    generate_compliance_proof(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 2: the issued_receive__resource and the issued_denomination_resource
            let (compliance_unit_2, delta_witness_2) = {
                let compliance_witness = ComplianceWitness::from_resources(
                    self.issued_receive_witness.receive_resource.clone(),
                    self.issued_receive_witness.nf_key.clone(),
                    self.issued_denomination_witness
                        .denomination_resource
                        .clone(),
                );

                (
                    generate_compliance_proof(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 3: a padding resource and the issued_denomination_resource

            // Generate logic proofs
            let issued_kudo_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.issued_kudo_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        KUDO_LOGIC_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            let issued_denomination_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.issued_denomination_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        DENOMINATION_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            let issued_receive_logic_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.issued_receive_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        RECEIVE_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            let ephemeral_kudo_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.ephemeral_kudo_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        KUDO_LOGIC_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            let ephemeral_denomination_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.ephemeral_denomination_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        DENOMINATION_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            (
                Action::new(
                    vec![compliance_unit_1, compliance_unit_2],
                    vec![
                        issued_kudo_receipt,
                        issued_denomination_receipt,
                        issued_receive_logic_receipt,
                        ephemeral_kudo_receipt,
                        ephemeral_denomination_receipt,
                    ],
                ),
                DeltaWitness::from_scalars(&[delta_witness_1, delta_witness_2]),
            )
        };

        // Create the transaction
        Transaction::new(vec![action], Delta::Witness(delta_witness))
    }
}

// TODO: Move this to aarm
use aarm_core::constants::TREE_DEPTH;
use compliance_circuit::COMPLIANCE_GUEST_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext};

fn generate_compliance_proof(witness: &ComplianceWitness<TREE_DEPTH>) -> Receipt {
    let env = ExecutorEnv::builder()
        .write(witness)
        .unwrap()
        .build()
        .unwrap();

    default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            COMPLIANCE_GUEST_ELF,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt
}
