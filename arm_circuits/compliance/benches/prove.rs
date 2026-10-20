/// Compliance circuit benchmarks.
///
/// Measures wall-clock prove time with three kind-tree configurations:
/// - `empty_tree`: the circuit falls back to `hash_to_curve` for every resource.
/// - `file_tree`:  kind bases are pre-computed in `kind_tree.json`; the circuit
///                  resolves them via a Merkle path, skipping `hash_to_curve`.
/// - `tree_size`:  varying kind-tree sizes (8, 32, 128, 512, 1024, 2048 entries)
///                  × resource counts (2, 8, 16) to measure how Merkle path depth
///                  (`⌈log₂ N⌉` hashes) interacts with per-resource scaling.
///
/// Each `empty_tree` and `file_tree` configuration is benchmarked with 2, 8,
/// and 16 consumed/created resources to measure per-resource scaling.
///
/// # Running on CPU
///
/// ```sh
/// cargo bench --features prove -p compliance
/// ```
///
/// # Running on GPU (CUDA)
///
/// ```sh
/// cargo bench --features prove,cuda -p compliance
/// ```
///
/// # Fast / dev-mode iteration
///
/// Set `RISC0_DEV_MODE=1` to skip actual proof generation and validate only
/// the witness-assembly logic without the multi-minute prover overhead.
///
/// ```sh
/// RISC0_DEV_MODE=1 cargo bench --features prove -p compliance
/// ```
use anoma_rm_risc0::compliance::{ComplianceWitness, KindTreeEntry, INITIAL_ROOT};
use anoma_rm_risc0::constants::{global_kind_tree, init_kind_tree_from_file, kind_tree, KindTree};
use anoma_rm_risc0::nullifier_key::NullifierKey;
use anoma_rm_risc0::resource::{ConsumedResourceWitness, Resource};
use compliance_methods::COMPLIANCE_GUEST_ELF;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use risc0_zkvm::{default_prover, Digest, ExecutorEnv, ProverOpts};
use std::time::Duration;

const RESOURCE_COUNTS: &[usize] = &[2, 8, 16];
/// Kind-tree sizes for the tree-size scaling benchmark.
const TREE_SIZES: &[usize] = &[8, 32, 128, 512, 1024, 2048];

fn do_prove(witness: &ComplianceWitness) {
    let env = ExecutorEnv::builder()
        .write(witness)
        .unwrap()
        .build()
        .unwrap();
    default_prover()
        .prove_with_opts(env, COMPLIANCE_GUEST_ELF, &ProverOpts::succinct())
        .unwrap();
}

/// Build a compliance witness for `count` consumed/created resources using
/// `kt` to resolve kind paths. Each consumed resource gets a unique nonce
/// via its index in the last byte.
fn make_witness_with_tree(
    logic_ref: Digest,
    label_ref: Digest,
    count: usize,
    kt: &KindTree,
) -> ComplianceWitness {
    let nf_key = NullifierKey::default();

    let consumed_data: Vec<ConsumedResourceWitness> = (0..count)
        .map(|i| {
            let mut nonce = [0u8; 32];
            nonce[31] = i as u8;
            let resource = Resource {
                logic_ref,
                label_ref,
                quantity: 1,
                value_ref: Digest::default(),
                is_ephemeral: false,
                nonce,
                nk_commitment: nf_key.commit(),
                rand_seed: [0u8; 32],
            };
            ConsumedResourceWitness::from_resource(resource, nf_key.clone())
        })
        .collect();

    let nullifiers: Vec<Digest> = consumed_data
        .iter()
        .map(|w| w.resource.nullifier(&nf_key).unwrap())
        .collect();

    let created_resources: Vec<Resource> = (0..count)
        .map(|i| {
            let nonce = Resource::derive_nonce_from_nullifiers(i as u32, &nullifiers).unwrap();
            Resource {
                logic_ref,
                label_ref,
                quantity: 1,
                value_ref: Digest::default(),
                is_ephemeral: false,
                nonce,
                nk_commitment: nf_key.commit(),
                rand_seed: [0u8; 32],
            }
        })
        .collect();

    let kind_paths = kt.kind_paths_for(&consumed_data, &created_resources);
    ComplianceWitness {
        consumed_data,
        created_resources,
        ephemeral_root: INITIAL_ROOT,
        rcv: [vec![0u8; 31], vec![1u8]].concat(),
        kind_paths,
    }
}

/// Build a compliance witness using the global kind tree (or an empty one if
/// the global tree has not been loaded yet).
fn make_witness(logic_ref: Digest, label_ref: Digest, count: usize) -> ComplianceWitness {
    let empty;
    let kt: &KindTree = match global_kind_tree() {
        Some(t) => t,
        None => {
            empty = KindTree::empty();
            &empty
        }
    };
    make_witness_with_tree(logic_ref, label_ref, count, kt)
}

/// Build a `KindTree` of exactly `size` entries that always contains
/// `matching` (used by the benchmark resources) at a deterministic position
/// among synthetic filler entries.
///
/// Filler entries use a `[0x00, i_lo, i_hi, 0x00…]` `logic_ref` pattern so
/// they never collide with each other or with `matching`. Their `kind_base`
/// is borrowed from `matching` — it is a valid curve point, satisfying the
/// loader's validation, but the (logic_ref, label_ref) key differs so the
/// circuit will never match against them for the benchmark resources.
///
/// `size` must be ≥ 1.
fn make_kind_tree_of_size(size: usize, matching: &KindTreeEntry) -> KindTree {
    assert!(size >= 1, "size must be at least 1");
    let mut entries = Vec::with_capacity(size);

    // matching entry
    entries.push(matching.clone());

    // filler entries — use index-based logic_ref so they sort deterministically
    for i in 1..size {
        let mut bytes = [0u8; 32];
        bytes[30] = ((i >> 8) & 0xFF) as u8;
        bytes[31] = (i & 0xFF) as u8;
        entries.push(KindTreeEntry {
            logic_ref: Digest::from(bytes),
            label_ref: matching.label_ref,
            kind_base: matching.kind_base.clone(),
        });
    }

    KindTree::from_entries(entries).expect("synthetic kind tree construction failed")
}

/// Empty kind tree: the circuit falls back to `hash_to_curve` for every resource.
fn bench_empty_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("compliance/empty_tree");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    for &count in RESOURCE_COUNTS {
        group.bench_with_input(BenchmarkId::new("prove", count), &count, |b, &count| {
            b.iter_with_setup(
                || make_witness(Digest::default(), Digest::default(), count),
                |witness| do_prove(&witness),
            );
        });
    }

    group.finish();
}

/// Precomputed kind tree from file: the circuit resolves kind bases via a
/// Merkle path, skipping `hash_to_curve`. The witness uses the `logic_ref` and
/// `label_ref` of the first entry in the loaded tree so all resources hit the tree.
fn bench_file_tree(c: &mut Criterion) {
    let kind_tree_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../arm/data/kind_tree.json");
    init_kind_tree_from_file(&kind_tree_path).expect("Failed to load kind_tree.json");

    let entry = &kind_tree()[0];
    let logic_ref = entry.logic_ref;
    let label_ref = entry.label_ref;

    let mut group = c.benchmark_group("compliance/file_tree");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    for &count in RESOURCE_COUNTS {
        group.bench_with_input(BenchmarkId::new("prove", count), &count, |b, &count| {
            b.iter_with_setup(
                || make_witness(logic_ref, label_ref, count),
                |witness| do_prove(&witness),
            );
        });
    }

    group.finish();
}

/// Varying kind-tree sizes × resource counts.
///
/// Measures how prove time scales with both the number of tree entries and the
/// number of resources per compliance witness. Because the kind tree is a
/// Merkle tree, each resource incurs `⌈log₂ N⌉` path-hash steps rather than a
/// linear scan, so tree-size cost is expected to grow slowly (one additional
/// hash per doubling) while resource-count cost scales roughly linearly.
fn bench_tree_size(c: &mut Criterion) {
    let kind_tree_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../arm/data/kind_tree.json");
    init_kind_tree_from_file(&kind_tree_path).expect("Failed to load kind_tree.json");

    let matching = kind_tree()[0].clone();

    let mut group = c.benchmark_group("compliance/tree_size");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(1));

    for &size in TREE_SIZES {
        let kt = make_kind_tree_of_size(size, &matching);
        for &count in RESOURCE_COUNTS {
            group.bench_with_input(
                BenchmarkId::new("prove", format!("{size}x{count}")),
                &count,
                |b, &count| {
                    b.iter_with_setup(
                        || {
                            make_witness_with_tree(
                                matching.logic_ref,
                                matching.label_ref,
                                count,
                                &kt,
                            )
                        },
                        |witness| do_prove(&witness),
                    );
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_empty_tree, bench_file_tree, bench_tree_size);
criterion_main!(benches);
