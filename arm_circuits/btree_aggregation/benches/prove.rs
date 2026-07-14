use arm::{
    aggregation::pcd::{PCDAggregation, PcdMessage, PcdProof, StepInstance, StepProof},
    transaction::generate_test_transaction,
};
use btree_aggregation_methods::{BTREE_AGGREGATION_ELF, BTREE_AGGREGATION_ID};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use risc0_zkvm::Digest;
use std::time::Duration;

const ACTION_COUNTS: &[usize] = &[1, 2, 4];

struct BTreeAggregation;

impl PCDAggregation for BTreeAggregation {
    const INPUT_ARITY: usize = 2;

    fn proving_key() -> &'static [u8] {
        BTREE_AGGREGATION_ELF
    }

    fn verifying_key() -> Digest {
        Digest::from(BTREE_AGGREGATION_ID)
    }
}

/// Prove N steps using the btree circuit in a linear schedule:
/// each step takes the previous aggregation result as both child inputs.
fn prove_btree_aggregation(
    instances: &[StepInstance],
    proofs: &[StepProof],
) -> Option<PcdProof> {
    if instances.len() != proofs.len() || instances.is_empty() {
        return None;
    }

    let zero = PcdMessage::default();
    let mut curr_agg = zero;
    let mut curr_proof: Option<PcdProof> = None;

    for (pos, (instance, proof)) in instances.iter().zip(proofs.iter()).enumerate() {
        let is_last = pos == instances.len() - 1;
        let input_aggs = [curr_agg.clone(), curr_agg.clone()];

        let step_out = match &curr_proof {
            None => {
                // Base case: no previous aggregation proof
                <BTreeAggregation as PCDAggregation>::prove_step(
                    &input_aggs,
                    &[],
                    instance,
                    proof,
                    is_last,
                )?
            }
            Some(prev) => {
                <BTreeAggregation as PCDAggregation>::prove_step(
                    &input_aggs,
                    &[prev.clone(), prev.clone()],
                    instance,
                    proof,
                    is_last,
                )?
            }
        };

        curr_agg =
            <BTreeAggregation as PCDAggregation>::aggregate_step(&input_aggs, instance);
        curr_proof = Some(step_out);
    }

    curr_proof
}

fn bench_btree_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("btree_aggregation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));

    for &n in ACTION_COUNTS {
        group.bench_with_input(BenchmarkId::new("prove", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let tx = generate_test_transaction(n);
                    let (instances, proofs) =
                        arm::aggregation::sequential::SequentialAggregation::transaction_transcript(
                            &tx,
                        )
                        .expect("transcript");
                    (instances, proofs.expect("step proofs"))
                },
                |(instances, proofs)| {
                    prove_btree_aggregation(&instances, &proofs)
                        .expect("btree aggregation proof")
                },
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_btree_aggregation);
criterion_main!(benches);
