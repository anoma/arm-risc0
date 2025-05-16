use aarm::{
    action::Action,
    logic_proof::{LogicProof, LogicProver},
    transaction::{Delta, Transaction},
    utils::groth16_prove,
};
use aarm_core::{
    compliance::ComplianceWitness, constants::COMMITMENT_TREE_DEPTH, delta_proof::DeltaWitness,
    merkle_path::MerklePath,
};
use compliance_circuit::COMPLIANCE_GUEST_ELF;
use kudo_core::{denomination::Denomination, kudo_logic_witness::KudoLogicWitness};
use kudo_logic::{KUDO_LOGIC_ELF, KUDO_LOGIC_ID};

#[derive(Clone)]
pub struct BurnInstance<D: Denomination + LogicProver> {
    pub burned_kudo_witness: KudoLogicWitness, // consumed resource
    pub burned_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    pub burned_denomination: D,                   // created resource
    pub ephemeral_kudo_witness: KudoLogicWitness, // created resource
    pub ephemeral_denomination: D,                // consumed resource
}

impl<D: Denomination + LogicProver> BurnInstance<D> {
    pub fn create_tx(&self) -> Transaction {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units
            // Compliance unit 1: the ephemeral_kudo_resource and the issued_kudo_resource

            println!("Generating compliance unit 1");
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources_with_path(
                        self.burned_kudo_witness.kudo_resource,
                        self.burned_kudo_witness.kudo_nf_key,
                        self.burned_kudo_path,
                        self.burned_denomination.resource(),
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 2: the issued_receive_resource and the issued_denomination_resource
            println!("Generating compliance unit 2");
            let (compliance_unit_2, delta_witness_2) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.ephemeral_denomination.resource(),
                        self.ephemeral_denomination.nf_key(),
                        self.ephemeral_kudo_witness.denomination_resource,
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the burned kudo logic proof");
            let burned_kudo_proof = {
                let receipt = groth16_prove(&self.burned_kudo_witness, KUDO_LOGIC_ELF);
                LogicProof {
                    receipt,
                    verifying_key: KUDO_LOGIC_ID.into(),
                }
            };

            println!(
                "Generating the denomination logic proof corresponding to the burned kudo resource"
            );
            let burned_denomination_proof = self.burned_denomination.prove();

            println!("Generating the ephemeral kudo logic proof");
            let ephemeral_kudo_proof = {
                let receipt = groth16_prove(&self.ephemeral_kudo_witness, KUDO_LOGIC_ELF);
                LogicProof {
                    receipt,
                    verifying_key: KUDO_LOGIC_ID.into(),
                }
            };

            println!("Generating the denomination logic proof corresponding to the ephemeral kudo resource");
            let ephemeral_denomination_proof = self.ephemeral_denomination.prove();

            (
                Action::new(
                    vec![compliance_unit_1, compliance_unit_2],
                    vec![
                        burned_kudo_proof,
                        burned_denomination_proof,
                        ephemeral_kudo_proof,
                        ephemeral_denomination_proof,
                    ],
                ),
                DeltaWitness::from_scalars(&[delta_witness_1, delta_witness_2]),
            )
        };

        // Create the transaction
        Transaction::new(vec![action], Delta::Witness(delta_witness))
    }
}
