## Aggregation benchmarks

The ARM protocol supports three proof aggregation strategies. Each takes a
transaction with N actions and produces a single aggregated proof attesting to
the validity of all compliance and resource-logic proofs.

Each action contains 3 step proofs: 1 compliance proof and 2 resource-logic
proofs (one consumed, one created). So a transaction with N actions has 3N
steps in total.

### Strategies

| Strategy   | Circuit invocations | Critical-path depth | Description |
|---|---|---|---|
| Batch      | 1                   | 1                   | Verifies all step proofs in a single circuit; outputs one commitment to all instances |
| Sequential | 3N                  | 3N                  | Hash-chains step proofs one at a time; each step extends the running aggregate |
| BTree      | 3N                  | O(log N)            | Each step can fold in two prior aggregations; enables parallel proving |

### Running the benchmarks

```bash
# Real proofs (succinct STARK)
cargo bench --bench prove -p batch_aggregation
cargo bench --bench prove -p sequential_aggregation
cargo bench --bench prove -p btree_aggregation

# Fast smoke test (dev-mode fake proofs)
RISC0_DEV_MODE=1 cargo bench --bench prove -p batch_aggregation
RISC0_DEV_MODE=1 cargo bench --bench prove -p sequential_aggregation
RISC0_DEV_MODE=1 cargo bench --bench prove -p btree_aggregation
```

### Results (NVIDIA 5090, succinct STARK)

Measured wall time (median of 10 samples). N = number of actions in the
transaction.

| N | Batch       | Sequential  | BTree         |
|---|-------------|-------------|---------------|
| 1 | 1.62 s      | 2.81 s      | 5.54 s        |
| 2 | 3.11 s      | 6.04 s      | 55.1 s †      |
| 4 | 6.46 s      | 13.83 s     | —             |

† The BTree bench uses a **linear schedule**: each step takes the single
previous aggregation as *both* child inputs, so the final succinct step must
recursively verify a proof whose depth doubles at every level. This produces
2^(steps−1) inner-proof verifications and explains the 10× jump from N=1 to
N=2. It does not represent the performance of a properly balanced parallel
btree, where the critical path is O(log N) and independent subtrees can be
proved concurrently.

### Analysis

**Batch** is the fastest strategy for sequential proving: it collapses all 3N
step proofs into a single circuit invocation regardless of N. Proving time
grows sub-linearly (~1.6 s overhead + ~1.6 s per action) because the dominant
cost is the one recursive STARK compression, not the step-proof count.

**Sequential** scales linearly with the number of steps (≈ 0.9 s per step,
2.8 s per action). It has the smallest per-step overhead of the PCD strategies
because each step verifies only one prior aggregation, keeping the recursion
simple.

**BTree** is designed for parallel environments: with log(N) critical-path
depth the wall time under full parallelism would match sequential on small N
and improve significantly at large N. The single-threaded benchmark above does
not capture this advantage.

## Generate proving and verifying keys (ELF and ImageID) reproducibly for releasing
```bash
cd ..
cargo risczero build --manifest-path arm_circuits/compliance/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/trivial_logic/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/logic_test/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/counter/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/kudo_main/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/simple_kudo_denomination/methods/guest/Cargo.toml

cargo risczero build --manifest-path arm_circuits/simple_kudo_receive/methods/guest/Cargo.toml
```

## Generate and print proving and verifying keys (ELF and ImageID) locally for debugging.
```bash
// It covers the previous ELF files, prints their IDs. You need to manually update ids in apps for testing.
cargo test -- --nocapture print_compliance_elf_id
cargo test -- --nocapture print_counter_elf_id
cargo test -- --nocapture print_kudo_main_elf_id
cargo test -- --nocapture print_simple_kudo_denomination_elf_id
cargo test -- --nocapture print_simple_kudo_receive_elf_id
cargo test -- --nocapture print_trivial_logic_elf_id
```