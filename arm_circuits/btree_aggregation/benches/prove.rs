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

/// Recursively prove a range of steps in O(log N) critical-path depth.
///
/// For n >= 3, `instances[mid]` (mid = (start+end)/2) is the subtree root: it
/// takes the independent left [start, mid-1] and right [mid+1, end] sub-proofs
/// as its two child inputs, giving depth ceil(log2(n)).  For n == 2 we fall
/// back to the linear 2-step schedule (the only option when one half is empty).
/// `is_final` drives `ProverOpts::succinct()` at the root of the whole tree.
fn prove_btree_range(
    instances: &[StepInstance],
    proofs: &[StepProof],
    start: usize,
    end: usize,
    is_final: bool,
) -> Option<(PcdMessage, PcdProof)> {
    let n = end - start + 1;
    let zero = PcdMessage::default();

    if n == 1 {
        let input_aggs = [zero.clone(), zero];
        let pcd = <BTreeAggregation as PCDAggregation>::prove_step(
            &input_aggs,
            &[],
            &instances[start],
            &proofs[start],
            is_final,
        )?;
        let msg =
            <BTreeAggregation as PCDAggregation>::aggregate_step(&input_aggs, &instances[start]);
        return Some((msg, pcd));
    }

    if n == 2 {
        // Cannot split into two non-empty halves with a mid-point root, so use
        // the linear fallback: prove start as a base case, then end takes it as
        // both child inputs (depth 2, same as sequential for 2 steps).
        let base_aggs = [zero.clone(), zero.clone()];
        let base_pcd = <BTreeAggregation as PCDAggregation>::prove_step(
            &base_aggs,
            &[],
            &instances[start],
            &proofs[start],
            false,
        )?;
        let base_msg = <BTreeAggregation as PCDAggregation>::aggregate_step(
            &base_aggs,
            &instances[start],
        );

        let input_aggs = [base_msg.clone(), base_msg.clone()];
        let pcd = <BTreeAggregation as PCDAggregation>::prove_step(
            &input_aggs,
            &[base_pcd.clone(), base_pcd],
            &instances[end],
            &proofs[end],
            is_final,
        )?;
        let msg =
            <BTreeAggregation as PCDAggregation>::aggregate_step(&input_aggs, &instances[end]);
        return Some((msg, pcd));
    }

    // n >= 3: prove left and right halves independently, then combine at mid.
    let mid = (start + end) / 2;
    let (left_msg, left_pcd) = prove_btree_range(instances, proofs, start, mid - 1, false)?;
    let (right_msg, right_pcd) = prove_btree_range(instances, proofs, mid + 1, end, false)?;

    let input_aggs = [left_msg, right_msg];
    let root_pcd = <BTreeAggregation as PCDAggregation>::prove_step(
        &input_aggs,
        &[left_pcd, right_pcd],
        &instances[mid],
        &proofs[mid],
        is_final,
    )?;
    let root_msg =
        <BTreeAggregation as PCDAggregation>::aggregate_step(&input_aggs, &instances[mid]);

    Some((root_msg, root_pcd))
}

fn prove_btree_aggregation(instances: &[StepInstance], proofs: &[StepProof]) -> Option<PcdProof> {
    if instances.len() != proofs.len() || instances.is_empty() {
        return None;
    }
    let n = instances.len();
    prove_btree_range(instances, proofs, 0, n - 1, true).map(|(_, pcd)| pcd)
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
