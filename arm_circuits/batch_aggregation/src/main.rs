use risc0_zkvm::{default_prover, Digest, ExecutorEnv, InnerReceipt, Receipt};

use arm::{logic_proof::LogicVerifier, transaction::generate_test_transaction};

use batch_aggregation_methods::{BATCH_AGGREGATION_ELF, BATCH_AGGREGATION_ID};

pub fn main() {
    let tx = generate_test_transaction(2);
    let cu_1 = tx.actions[0].get_compliance_units()[0].clone();
    let cu_2 = tx.actions[1].get_compliance_units()[0].clone();
    let lv_1: Vec<LogicVerifier> = tx.actions[0].clone().try_into().unwrap();
    let lp_1 = lv_1[0].clone();
    let lv_2: Vec<LogicVerifier> = tx.actions[1].clone().try_into().unwrap();
    let lp_2 = lv_2[0].clone();

    let mut inner: InnerReceipt = bincode::deserialize(&cu_1.proof.unwrap()).unwrap();
    let cu_1_receipt = Receipt::new(inner, cu_1.instance.clone().to_vec());
    inner = bincode::deserialize(&cu_2.proof.unwrap()).unwrap();
    let cu_2_receipt = Receipt::new(inner, cu_2.instance.clone().to_vec());
    inner = bincode::deserialize(&lp_1.proof.unwrap()).unwrap();
    let lp_1_receipt = Receipt::new(inner, lp_1.instance.clone().to_vec());
    inner = bincode::deserialize(&lp_2.proof.unwrap()).unwrap();
    let lp_2_receipt = Receipt::new(inner, lp_2.instance.clone().to_vec());

    // Test batch aggregation (both compliance and resource logic instances).
    let compliance_key: Digest = *arm::constants::COMPLIANCE_VK;
    let env = ExecutorEnv::builder()
        .add_assumption(cu_1_receipt)
        .add_assumption(cu_2_receipt)
        .add_assumption(lp_1_receipt)
        .add_assumption(lp_2_receipt)
        .write(&vec![cu_1.instance, cu_2.instance])
        .unwrap()
        .write(&compliance_key)
        .unwrap()
        .write(&vec![lp_1.instance, lp_2.instance])
        .unwrap()
        .write(&vec![
            Digest::new(lp_1.verifying_key.try_into().unwrap()),
            Digest::new(lp_2.verifying_key.try_into().unwrap()),
        ])
        .unwrap()
        .build()
        .unwrap();

    let batch_receipt = default_prover()
        .prove(env, BATCH_AGGREGATION_ELF)
        .unwrap()
        .receipt;

    batch_receipt.verify(BATCH_AGGREGATION_ID).unwrap();

    println!("Success!");
}
