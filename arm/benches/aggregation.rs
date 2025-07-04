use std::time::Instant;

use arm::aggregation::{
    pcd::PcdProof,
    proof::{AggregationProof, AggregationStrategy},
};

// For Kudos:
use app::{
    kudo_main::KudoMainInfo, simple_receive::SimpleReceiveInfo, transfer_tx::build_transfer_tx,
};
use arm::{
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    logic_proof::LogicProver,
    merkle_path::{MerklePath, COMMITMENT_TREE_DEPTH},
    nullifier_key::NullifierKey,
    resource::Resource,
    transaction::{generate_test_transaction, Transaction},
};
use kudo_logic_witness::utils::{compute_kudo_label, compute_kudo_value};
use risc0_zkvm::InnerReceipt;

// For the test transaction will aggregate up to 3*MAX_ACTIONS proofs.
const MAX_ACTIONS: usize = 3;

fn main() {
    benchmark_test_transaction();
    benchmark_kudo_transfer();
}

fn benchmark_test_transaction() {
    println!("TEST TRANSACTION BENCHMARKS");

    println!("Generating test transaction...");
    let tx = generate_test_transaction(1);

    println!("Benchmarking for up to {:?} aggregations", 3 * MAX_ACTIONS);
    for n in 0..MAX_ACTIONS {
        let mut dummy_tx = expand_tx_with_actions(&tx, n);
        benchmark_aggregation(&mut dummy_tx, AggregationStrategy::Sequential);
    }
}

fn benchmark_aggregation(tx: &mut Transaction, strategy: AggregationStrategy) {
    println!(
        "\tNumber of aggregated proofs: {:?}",
        number_aggregations(&tx)
    );
    println!("\tStrategy: {:?}", strategy);

    let aggregation_timer = Instant::now();
    tx.aggregate(strategy);

    let prove_duration = aggregation_timer.elapsed();
    println!("\tAggregation time {:?}", prove_duration);

    let verification_timer = Instant::now();
    let verify_res = tx.verify_aggregation();
    let verify_time = verification_timer.elapsed();
    assert_eq!(true, verify_res);
    println!("\tVerification time {:?}", verify_time);
    println!(
        "\tAggregation proof size - Journal + Seal (bytes): {:?}",
        tx.aggregation_proof.clone().unwrap().len()
    );

    // Print receipt type.
    let agg_proof = AggregationProof::from_bytes(&tx.aggregation_proof.clone().unwrap()).unwrap();
    match agg_proof {
        AggregationProof::Sequential(PcdProof(receipt)) => match receipt.inner {
            InnerReceipt::Composite(cmp) => println!(
                "\tAggregation proof type: Composite. Number of segments: {:?}",
                cmp.segments.len()
            ),
            InnerReceipt::Succinct(_) => println!("\tAggregation proof type: Succinct."),
            InnerReceipt::Groth16(_) => println!("\tAggregation proof type: Groth16."),
            InnerReceipt::Fake(_) => println!("\tAggregation proof type: Fake."),
            _ => {}
        },
    }

    println!("\tBase proofs size (bytes): {:?}", base_proofs_size(&tx));
    println!("");
}

fn benchmark_kudo_transfer() {
    println!("KUDO TRANSFER BENCHMARKS");

    println!("Generating kudo transfer transaction...");
    let kudo_timer = Instant::now();
    let mut tx = generate_kudo_transfer_transaction();
    let kudo_gen_time = kudo_timer.elapsed();
    println!("Time to generate Kudo transfer tx: {:?}", kudo_gen_time);

    benchmark_aggregation(&mut tx, AggregationStrategy::Sequential);
}

fn generate_kudo_transfer_transaction() -> Transaction {
    use kudo_logic_witness::utils::generate_receive_signature;

    let kudo_logic = KudoMainInfo::verifying_key_as_bytes();
    let issuer_sk = AuthorizationSigningKey::new();
    let issuer = AuthorizationVerifyingKey::from_signing_key(&issuer_sk);
    let kudo_lable = compute_kudo_label(&kudo_logic, &issuer);
    let owner_sk = AuthorizationSigningKey::new();
    let owner = AuthorizationVerifyingKey::from_signing_key(&owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    let (kudo_nf_key, kudo_nk_cm) = NullifierKey::random_pair();

    let (receiver_pk, receiver_signature) = {
        let sk = AuthorizationSigningKey::new();
        let pk = AuthorizationVerifyingKey::from_signing_key(&sk);
        let signature =
            generate_receive_signature(&SimpleReceiveInfo::verifying_key_as_bytes(), &sk);
        (pk, signature)
    };
    let (_receiver_nf_key, receiver_nk_commitment) = NullifierKey::random_pair();
    let nonce = vec![0u8; 32]; // Random nonce for the ephemeral resource

    let consumed_kudo_resource = Resource::create(
        kudo_logic, kudo_lable, 100, kudo_value, false, nonce, kudo_nk_cm,
    );

    build_transfer_tx(
        &issuer,
        &owner_sk,
        &consumed_kudo_resource,
        &kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
        &receiver_pk,
        &receiver_signature,
        &receiver_nk_commitment,
    )
}

fn number_aggregations(tx: &Transaction) -> usize {
    let mut i: usize = 0;

    for a in tx.actions.iter() {
        i += a.get_compliance_units().len();
        i += a.get_logic_verifier_inputs().len();
    }

    i
}

/// Returns a dummy transaction with `tx.actions` + `num_actions` actions in it.
fn expand_tx_with_actions(tx: &Transaction, num_actions: usize) -> Transaction {
    let mut actions = tx.actions.clone();

    for _ in 0..num_actions {
        let a = tx.actions[0].clone();
        actions.push(a);
    }

    Transaction {
        actions: actions,
        delta_proof: tx.delta_proof.clone(),
        expected_balance: None,
        aggregation_proof: None,
    }
}

/// Returns the total size of all proofs in the tx.
fn base_proofs_size(tx: &Transaction) -> usize {
    let mut proof_size = 0;
    for action in tx.actions.iter() {
        for cu in action.compliance_units.iter() {
            proof_size += cu.proof.len();
        }
        for lp in action.logic_verifier_inputs.iter() {
            proof_size += lp.proof.len();
        }
    }

    proof_size
}
