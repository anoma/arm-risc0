/// Execution proof generation benchmarks.
///
/// These benchmarks measure wall-clock time of the execution proof prover
/// across different batch sizes (transaction count) and compliance-unit counts.
///
/// # Running on CPU
///
/// ```sh
/// cargo bench --features prove -p execution-proof
/// ```
///
/// # Running on GPU (CUDA)
///
/// Build with the `cuda` feature to enable RISC0's GPU prover backend.
/// RISC0 selects CUDA automatically when the feature is compiled in and a
/// compatible GPU is present — no extra environment variables are required.
///
/// ```sh
/// cargo bench --features prove,cuda -p execution-proof
/// ```
///
/// To compare CPU vs GPU, save two baselines:
///
/// ```sh
/// cargo bench --features prove      -p execution-proof -- --save-baseline cpu
/// cargo bench --features prove,cuda -p execution-proof -- --save-baseline gpu
/// cargo bench --features prove,cuda -p execution-proof -- --baseline      cpu
/// ```
///
/// # Fast / dev-mode iteration
///
/// Set `RISC0_DEV_MODE=1` to skip actual proof generation and validate only
/// the witness-assembly logic without the multi-minute prover overhead.
///
/// ```sh
/// RISC0_DEV_MODE=1 cargo bench --features prove -p execution-proof
/// ```
use anoma_rm_risc0::{
    constants::{BATCH_AGGREGATION_VK_BYTES, COMPLIANCE_VK_BYTES},
    execution_proof::{ExecutionProofWitness, TxInput},
    incremental_merkle_tree::IncrementalMerkleTree,
    indexed_merkle_tree::IndexedMerkleTree,
    proving_system::ProofType,
    transaction::{Delta, Transaction},
    CoreDeltaWitness, Digest, TransactionExt,
};
use anoma_rm_risc0_test_app::create_an_action_with_multiple_compliances;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use execution_proof_methods::EXECUTION_PROOF_GUEST_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, VerifierContext};
use std::time::Duration;

fn vk(bytes: &[u8; 32]) -> Digest {
    Digest::try_from(bytes.as_slice()).expect("vk bytes")
}

/// Prove an execution witness.  Mirrors the logic in `src/main.rs::prove`.
fn do_prove(witness: &ExecutionProofWitness) -> risc0_zkvm::Receipt {
    let mut env_builder = ExecutorEnv::builder();

    for tx in &witness.transactions {
        let inner: InnerReceipt = bincode::deserialize(&tx.aggregation_proof).unwrap();
        env_builder.add_assumption(inner);
    }

    let env = env_builder.write(witness).unwrap().build().unwrap();

    default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            EXECUTION_PROOF_GUEST_ELF,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt
}

/// Build one aggregated transaction: `n_compliances` compliance units,
/// a distinct `nonce` so all nullifiers across a batch remain unique.
fn build_aggregated_tx(n_compliances: usize, nonce: u8) -> Transaction {
    let (action, dw) =
        create_an_action_with_multiple_compliances(n_compliances, nonce, ProofType::Succinct);
    let mut tx = Transaction::create(
        vec![action],
        Delta::Witness(CoreDeltaWitness(dw.to_bytes())),
    )
    .generate_delta_proof()
    .unwrap();
    tx.aggregate(ProofType::Succinct).unwrap();
    tx
}

/// Assemble an `ExecutionProofWitness` from pre-aggregated transactions.
/// A fresh `IndexedMerkleTree` is used so every benchmark iteration starts
/// from the same initial tree state.
fn build_witness(transactions: Vec<Transaction>) -> ExecutionProofWitness {
    let mut nullifier_tree = IndexedMerkleTree::new();
    let mut nullifier_witnesses = Vec::new();

    for tx in &transactions {
        for action in &tx.actions {
            for cu in action.get_compliance_units() {
                let w = nullifier_tree
                    .insert(cu.instance.consumed_nullifier)
                    .unwrap();
                nullifier_witnesses.push(w);
            }
        }
    }

    let tx_infos: Vec<TxInput> = transactions
        .iter()
        .map(|tx| TxInput::from_transaction(tx).expect("tx to tx_info"))
        .collect();

    ExecutionProofWitness {
        transactions: tx_infos,
        commitment_tree: IncrementalMerkleTree::new(3),
        old_nullifier_tree_root: IndexedMerkleTree::new().root(),
        nullifier_witnesses,
        batch_aggregation_vk: vk(&BATCH_AGGREGATION_VK_BYTES),
        compliance_vk: vk(&COMPLIANCE_VK_BYTES),
    }
}

/// Vary the number of transactions in a batch (1 compliance unit each).
fn bench_by_tx_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("execution_proof/tx_count");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    for n_txs in [1usize, 2, 4, 8, 16] {
        // Build all transactions outside the timing loop.
        let transactions: Vec<Transaction> = (0..n_txs)
            .map(|i| build_aggregated_tx(1, i as u8))
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(n_txs),
            &transactions,
            |b, txs| {
                b.iter_with_setup(|| build_witness(txs.clone()), |witness| do_prove(&witness));
            },
        );
    }

    group.finish();
}

/// Vary the number of compliance units per transaction (single transaction).
fn bench_by_compliance_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("execution_proof/compliance_count");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    for n_compliances in [1usize, 2, 4] {
        let tx = build_aggregated_tx(n_compliances, 0);

        group.bench_with_input(BenchmarkId::from_parameter(n_compliances), &tx, |b, tx| {
            b.iter_with_setup(
                || build_witness(vec![tx.clone()]),
                |witness| do_prove(&witness),
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_by_tx_count, bench_by_compliance_count);
criterion_main!(benches);
