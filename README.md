# Anoma Risc0 Resource Machine

This is a shielded resource machine implementation based on [Risc0-zkvm](https://github.com/risc0/risc0)

## Docs

- [General RM Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)
- Shielded RM Specification(TBD)
- [Anoma SDK](https://github.com/anoma/anoma-sdk)

## ARM-RISC0 Directory Structure

- **`arm/`**: The main Anoma Shielded Resource Machine implementation providing the core functionality for Anoma SDK and Validator.

- **`arm_circuits/`**: Demonstration circuits for arms and applications:

  - **compliance**: Basic compliance checking circuit
  - **trivial_logic**: Minimal logic circuit example, also used in padding resources
  - **proof aggregation (batch)**: Circuit for single-run aggregation

- **`arm_gadgets/`**: It provides a range of commonly used components for resource logic circuits, such as verifiable encryption and ECDSA signature authentication.

- **`arm_tests/`**: It encompasses a basic resource logic instantiation and transaction tests.

## Audits

Our software undergoes regular audits:

1. Informal Systems

   - Company Website: https://informal.systems
   - Commit ID: [61e68468e9c9c292ee0ce2575d5b743e6571a2ff](https://github.com/anoma/arm-risc0/tree/61e68468e9c9c292ee0ce2575d5b743e6571a2ff)
   - Started: 2025-10-13
   - Finished: 2025-10-31
   - Last revised: 2025-11-07

   [📄 Audit Report (pdf)](./audits/2025-11-24_Informal_Systems_RISC_Zero_RM_&_EVM_Protocol_Adapter.pdf)

2. Nethermind

   - Company Website: https://www.nethermind.io/nethermind-security
   - Commit ID: [a0cca9cdc8e87508b97f6afc65a3b7582aa3e59d](https://github.com/anoma/arm-risc0/tree/a0cca9cdc8e87508b97f6afc65a3b7582aa3e59d)
   - Started: 2025-10-07
   - Finished: 2025-11-13

   [📄 Audit Report (pdf)](./audits/2025-11-13_Nethermind_RISC_Zero_RM_&_EVM_Protocol_Adapter.pdf)

## Security

If you believe you've found a security issue, we encourage you to notify us via Email at [security@anoma.foundation](mailto:security@anoma.foundation).

Please do not use the issue tracker for security issues. We welcome working with you to resolve the issue promptly.

## ARM-RISC0 Application Examples

Several application examples are available at [here](https://github.com/anoma/arm-risc0-examples), including the simple counter application, token transfer application, and the kudo application.

## Getting Started

### Dependencies

- Rust: [install rust instructions](https://www.rust-lang.org/tools/install)
- Risc0 toolchain: [install risc0 instructions](https://dev.risczero.com/api/zkvm/install)

Note: The installation of the Risc0 toolchain is required only if you intend to develop resource logics(circuits).

### Build and Test

- Compile `arm` libs

```bash
cargo build
```

- Run `arm` tests

```bash
# run tests in dev-mode: no real proofs are generated
RISC0_DEV_MODE=1 cargo test

# run tests in release mode: default succinct(stark) proofs are generated
cargo test --release
```

### Run tests and examples on Bonsai

[Bonsai](https://risczero.com/bonsai) is a remote and high-performance service provided by RISC0 for generating proofs. To use Bonsai, you can request an API key [here](https://docs.google.com/forms/d/e/1FAIpQLSf9mu18V65862GS4PLYd7tFTEKrl90J5GTyzw_d14ASxrruFQ/viewform), and then set the environment variables. Once set up, your proof generation tasks will be automatically offloaded to Bonsai.

```bash
export BONSAI_API_URL=<BONSAI_URL>
export BONSAI_API_KEY=<YOUR_API_KEY>
```

### Benchmark

- [Compliance circuit benchmark](./arm_circuits/compliance/README.md)

## Feature flags

We have the following feature flags in arm lib:

| Feature                 | Implies                              | Description                                                                                                                                        |
| ----------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `compliance_circuit`    |                                      | A specific feature for compliance circuit                                                                                                          |
| `transaction (default)` | `compliance_circuit`, `client`       | It provides full transaction processing capabilities and supports Succinct(STARK) and Groth16 proof types. Groth16 proofs require x86_64 machines. |
| `prove`                 |                                      | Enables RISC0 proving capabilities (required for actual proof generation)                                                                          |
| `bonsai`                |                                      | Enables RISC0 bonsai sdk                                                                                                                           |
| `client`                |                                      | Enables RISC0 client sdk                                                                                                                           |
| `cuda`                  |                                      | Enables CUDA GPU acceleration for the prover. Requires CUDA toolkit to be installed.                                                               |
| `aggregation_circuit`   |                                      | A specific feature for (pcd-based) aggregation circuits                                                                                            |
| `aggregation`           | `aggregation_circuit`, `transaction` | Enables proof aggregation (only succinct proofs can be aggregated)                                                                                 |

### Usage Examples

```toml
# Default configuration
anoma-rm-risc0 ="1.0.0"

# Proof aggregation (a single succinct proof per transaction)
anoma-rm-risc0 ={ version = "1.0.0", features = ["aggregation"] }

# Logic-circuit-only usage
anoma-rm-risc0 ={ version = "1.0.0", default-features = false }
```

## Reproducibly generate proving and verifying keys (ELF and ImageID)

You may generate different ELFs and ImageIDs on different machines and environments. To reproduce the same output and publicly verify that the ELF and ImageID correspond to the specific circuit source code, use the following tool and command.

For example, build the compliance circuit in RM:

```bash
cargo risczero build --manifest-path arm_circuits/compliance/methods/guest/Cargo.toml
```

will reproduce the output to:

```bash
View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/zbrzf1brqyb5evydjxs9h3gvl

ELFs ready at:
ImageID: 5d3ea0a27561e9e66e6a7c12c7022d1a814a0724d13f7f8e083c4b4f14b5f1c7 -
arm-risc0/arm_circuits/compliance/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/compliance-guest.bin
```

Note: The `unstable` feature of `risc0-zkvm` currently causes issues in circuits. This can be temporarily fixed by manually updating the tool. The problem will be fully resolved in the next release of RISC Zero.

```bash
cargo install --force --git https://github.com/risc0/risc0 --tag v3.0.3 -Fexperimental cargo-risczero
```

## Proof aggregation

If a single transaction bundles too many resources, it is possible to aggregate all compliance and logic proofs into a single aggregation proof, attesting to the validity of them all. This reduces overall verification time and transaction size.

### Before aggregation

Generate the transaction in the normal way in your workflow. But note that succinct proofs will yield faster aggregation.

**Warning:** It does not support in-circuit verification of Groth16 proofs. You would need to generate succinct compliance and logic proofs instead.

### Prove aggregations

You need to enable the `aggregation` feature to be able to prove or verify aggregations.

The aggregation proof type is specified by the ProofType argument. The inner proofs must be Succinct.

We support the batch aggregation strategy. The _batch_ strategy aggregates all proofs in the transaction in a single run.

```rust
use anoma_rm_risc0::transaction;

// Just a dummy tx, for illustration. The inner proofs must be Succinct.
let mut tx = generate_test_transaction(1, 1, ProofType::Succinct);

// Upon succesful aggregation, compliance and resource logic proofs are erased.
// The aggregated proof_type can be ProofType::Succinct or ProofType::Groth16
assert!(tx.aggregate(proof_type).is_ok());
```

**Warning:** Once again, aggregation erases all the individual proofs from `tx` and replaces them with the (single) aggregation proof in a dedicated field. This is why the transaction must be `mut`. This is true independently of the strategy used.

### Verify after aggregation

Use `tx.verify()`, as when there is no aggregated proof. Feature `aggregation` must be enabled. Otherwise, it will result in an error.

### External verification of the aggregation proof

Use `tx.get_raw_aggregation_proof()` to get the RISC0 `InnerReceipt` (the actual proof). The verifier would also need to derive the aggregation instance from `tx` on its own, and wrap both in a RISC0 `Receipt`.

### Comparison

| **Strategy**   | **Prover cost**               | **Public input size**  | **Aggregation scope**          | **Memory efficient**                                                       |
| -------------- | ----------------------------- | ---------------------- | ------------------------------ | -------------------------------------------------------------------------- |
| **batch**      | amortized among all tx proofs | linear in #{tx proofs} | fixed (single prover)          | for RISC0 yes. In general, depends on the zkVM (if supports continuations) |

**[TODO] Parallel proving at the ARM level.** It is possible with tree-like transcripts. Currently not supported, but [planned](https://github.com/anoma/arm-risc0/issues/112).
