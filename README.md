# Anoma Risc0 Resource Machine

This is a shielded resource machine implementation based on [Risc0-zkvm](https://github.com/risc0/risc0)

## Docs

- [Specification of arm-risc0](./docs/README.md)
- [General RM Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)
- Shielded RM Specification(TBD)
- [Anoma SDK](https://github.com/anoma/anoma-sdk)

## ARM-RISC0 Directory Structure

- **`arm/`**: The main Anoma Shielded Resource Machine implementation providing the core functionality for Anoma SDK and Validator.

- **`arm_core/`**: The data types of the Anoma Shielded Resource Machine, shared by `arm/` and `arm_solana/`. It does not depend on RISC0 zkVM or k256.

- **`arm_circuits/`**: Demonstration circuits for arms and applications:

  - **compliance**: Basic compliance checking circuit
  - **trivial_logic**: Minimal logic circuit example, also used in padding resources
  - **proof aggregation (batch)**: Circuit for single-run aggregation

- **`arm_gadgets/`**: It provides a range of commonly used components for resource logic circuits, such as verifiable encryption and ECDSA signature authentication.

- **`arm_solana/`**: Transaction verification for Solana programs, built on `arm_core/` and the syscalls of the Solana runtime.

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
| `transaction (default)` | `compliance_circuit`                 | It provides full transaction processing capabilities and supports Succinct(STARK) and Groth16 proof types. Groth16 proofs require x86_64 machines. |
| `prove (default)`       |                                      | Enables RISC0 proving capabilities (required for actual proof generation)                                                                          |
| `bonsai`                |                                      | Enables RISC0 bonsai sdk                                                                                                                           |
| `cuda`                  |                                      | Enables CUDA GPU acceleration for the prover. Requires CUDA toolkit to be installed.                                                               |
| `aggregation`           | `transaction`                       | Enables batch proof aggregation (the inner proofs must be succinct)                                                                               |

### Usage Examples

```toml
# Default configuration
anoma-rm-risc0 = "2.0.0-rc.9"

# Proof aggregation (a single succinct proof per transaction)
anoma-rm-risc0 = { version = "2.0.0-rc.9", features = ["aggregation"] }

# Logic-circuit-only usage
anoma-rm-risc0 = { version = "2.0.0-rc.9", default-features = false }
```

## Reproducibly generate proving and verifying keys (ELF and ImageID)

You may generate different ELFs and ImageIDs on different machines and environments. To reproduce the same output and publicly verify that the ELF and ImageID correspond to the specific circuit source code, use the following tool and command.

For example, build the compliance circuit in RM:

```bash
cargo risczero build --manifest-path arm_circuits/compliance/methods/guest/Cargo.toml
```

will reproduce the output to:

```bash
ELFs ready at:
ImageID: 23e01dda73611df43ef58e427133f8fdded73a26e0b8b950a616beb2318cdb76 -
arm-risc0/arm_circuits/compliance/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/compliance-guest.bin
```

Use the RISC Zero 3.1.0 tools with the matching crate versions:

```bash
rzup install cargo-risczero 3.1.0
rzup install r0vm 3.1.0
```

RISC Zero 3.1.0 changes the proof circuits and control root. Regenerate receipts
produced by earlier versions and update deployed verifiers before using new proofs.
See the [3.1.0 release notes](https://github.com/risc0/risc0/releases/tag/v3.1.0).

The [circuits README](./arm_circuits/README.md#current-release-artifacts)
lists all five image IDs for `2.0.0-rc.9` and the Docker regeneration commands.

## Starter kind tree

The [starter kind tree](./arm/data/kind_tree.json) contains the rc.9 padding
and test logics under the zero label. Each kind base is the hash to curve of
its logic ref and label ref. Its root is:

```text
44b55c0dcd39680f5dd98c5a15e62661e04cead552d4d76c6e37d3e3abec8b59
```

Initialize it with `constants::init_starter_kind_tree()` and obtain the root
with `constants::kind_tree_root()`. Pass the expected root to
`transaction::verify`. Changing either logic ID requires regenerating its
kind base and the tree root; see the
[kind-tree update steps](./arm_circuits/README.md#updating-the-starter-kind-tree).

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
use anoma_rm_risc0::{
    proving_system::{JournalEncoding, ProofType},
    transaction::{self, Transaction},
};

// Just a dummy tx, for illustration. The inner proofs must be Succinct.
let mut tx: Transaction = /* a transaction with succinct compliance and logic proofs */;

// Upon successful aggregation, compliance and resource logic proofs are erased.
// `proof_type` can be ProofType::Succinct or ProofType::Groth16.
assert!(transaction::aggregate(
    &mut tx,
    ProofType::Succinct,
    JournalEncoding::Risc0Serde,
).is_ok());
```

**Warning:** Once again, aggregation erases all the individual proofs from `tx` and replaces them with the (single) aggregation proof in a dedicated field. This is why the transaction must be `mut`. This is true independently of the strategy used.

### Verify after aggregation

Use `transaction::verify(&tx, expected_kind_tree_root, encoding)`, as when
there is no aggregation proof. The `aggregation` feature must be enabled.
Use the same `JournalEncoding` passed to `transaction::aggregate`:
`Risc0Serde` for native / Solana verification or `Abi` for EVM verification.

### External verification of the aggregation proof

`tx.aggregation` holds the bincode-serialized `InnerReceipt` in `proof` and
the public inputs in `instance`. An external verifier reconstructs the
RISC Zero `Receipt` using the journal encoding selected during aggregation.
The image ID is `BATCH_AGGREGATION_VK` for `Risc0Serde`, or
`BATCH_AGGREGATION_EVM_VK` for `Abi`.

### Comparison

| **Strategy**   | **Prover cost**               | **Public input size**  | **Aggregation scope**          | **Memory efficient**                                                       |
| -------------- | ----------------------------- | ---------------------- | ------------------------------ | -------------------------------------------------------------------------- |
| **batch**      | amortized among all tx proofs | linear in #{tx proofs} | fixed (single prover)          | for RISC0 yes. In general, depends on the zkVM (if supports continuations) |

**[TODO] Parallel proving at the ARM level.** It is possible with tree-like transcripts. Currently not supported, but [planned](https://github.com/anoma/arm-risc0/issues/112).
