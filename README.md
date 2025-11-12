# Anoma Risc0 Resource Machine

This is a shielded resource machine implementation based on [Risc0-zkvm](https://github.com/risc0/risc0)

## Docs

* [General RM Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)
* Shielded RM Specification(TBD)
* [Anoma SDK](https://github.com/anoma/anoma-sdk)

## ARM-RISC0 Directory Structure

- **`arm/`**: The main Anoma Shielded Resource Machine implementation providing the core functionality for Anoma SDK and Validator.

- **`arm_circuits/`**: Demonstration circuits for arms and applications:
  - **compliance**: Basic compliance checking circuit
  - **trivial_logic**: Minimal logic circuit example, also used in padding resources
  - **proof aggregation (batch_aggregation, sequential_aggregation)**: Circuits for single-run aggregation and IVC-based aggregation, respectively
  - **logic_test**: The logic circuit contains hardcoded data to cover all instance fields and is used only in tests
  - **counter**: The simple counter logic circuit
  - **kudo circuits(kudo_main, simple_kudo_denomination, simple_kudo_receive)**: kudo application circuits

- **`examples/`**: Demonstration application examples:
  - **kudo_application**: A simple counter increment example
  - **simple_counter_application**: A relatively complex example; more detailed descriptions can be found [here](https://research.anoma.net/t/shielded-kudos-revised-no-authorisation-abstraction/1522)
  - **simple_transfer_application**: A simplified transfer application for use in the Protocol Adapter; more detailed descriptions can be found [here](https://forum.anoma.net/t/simple-transfer-application-for-ethereum/2193)

## Getting Started

### Dependencies

* Rust: [install rust instructions](https://www.rust-lang.org/tools/install)
* Risc0 toolchain: [install risc0 instructions](https://dev.risczero.com/api/zkvm/install)

Note: The installation of the Risc0 toolchain is required only if you intend to develop resource logics(circuits).

### Build and Test

* Compile `arm` lib

```bash
cargo build
```

* Run `arm` tests

```bash
# run tests in dev-mode: no real proofs are generated
RISC0_DEV_MODE=1 cargo test

# run tests in release mode: default succinct(stark) proofs are generated
cargo test --release
```

* Run examples

For example, test the simple counter example:

```bash
cd simple_counter

# Run the counter initialization test
cargo test test_create_init_counter_tx

# Run the counter increment test
cargo test test_create_increment_tx
```

### Run tests and examples on Bonsai

[Bonsai](https://risczero.com/bonsai) is a remote and high-performance service provided by RISC0 for generating proofs. To use Bonsai, you can request an API key [here](https://docs.google.com/forms/d/e/1FAIpQLSf9mu18V65862GS4PLYd7tFTEKrl90J5GTyzw_d14ASxrruFQ/viewform), and then set the environment variables. Once set up, your proof generation tasks will be automatically offloaded to Bonsai.

```bash
export BONSAI_API_URL=<BONSAI_URL>
export BONSAI_API_KEY=<YOUR_API_KEY>
```

### Benchmark

* [Compliance circuit benchmark](./arm_circuits/compliance/README.md)
* [Kudo example benchmark](./examples/kudo_application/README.md)

## Feature flags

We have the following feature flags in arm lib:


| Feature                  | Implies                   | Description                                                                                                                     |
| ------------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `compliance_circuit`       |                           | A specific feature for compliance circuit                                                                                       |
| `transaction (default)`     | `compliance_circuit`, `client` | It provides full transaction processing capabilities and will be in the Anoma SDK and validator with a selected prover feature. Succinct prover is used by default. |
| `prove`                    |                           | Enables RISC0 proving capabilities (required for actual proof generation)                                                       |
| `bonsai`                    |                           | Enables RISC0 bonsai sdk                                                       |
| `client`                    |                           | Enables RISC0 client sdk                                                       |
| `cuda`                    |                           | Enables CUDA GPU acceleration for the prover. Requires CUDA toolkit to be installed.                                                       |
| `fast_prover`         |                           | Fastest option producing linear-size proofs, and does not support compression via recursion |
| `composite_prover`         |                           | Fastest option producing linear-size proofs, and supports compression via recursion                                                                 |
| `groth16_prover`           |                           | Generates groth16 proofs(requires x86_64 machines)                                                                              |
| `nif`                      |                           | Enables Erlang/Elixir NIF (Native Implemented Function) bindings                                                                |
| `test_circuit`             |                           | A simple circuit implementation for testing |
| `test`                     |                           | Includes tx and action tests; some test APIs are available outside the arm lib(Binding lib and Elixir SDK). |
| `aggregation_circuit`      |                           | A specific feature for (pcd-based) aggregation circuits |
| `aggregation`              | `aggregation_circuit`, `transaction`       | Enables proof aggregation (with constant-sized proofs by default) |
|`fast_aggregation`          | `aggregation`               | Faster aggregation with linear-sized proofs without compression
|`groth16_aggregation`       | `aggregation`               | Generates groth16 aggregation proofs (requires x86_64 machines)


### Usage Examples

```toml
# Default configuration (succinct proofs + transaction support)
arm = "0.11.0"

# Blockchain deployment with Groth16 proofs
arm = { version = "0.11.0", default-features = false, features = ["groth16_prover", "transaction"] }

# Proof aggregation (a single succinct proof per transaction)
arm = { version = "0.11.0", features = ["aggregation"] }

# Blockchain deployment with a Groth16 aggregation proof
arm = { version = "0.11.0", features = ["groth16_aggregation"] }

# Logic-circuit-only usage
arm = { version = "0.11.0", default-features = false }

# Elixir Anoma SDK
arm = { version = "0.11.0", features = ["nif"] }
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

 **Warning:** Bonsai does not support in-circuit verification of Groth16 proofs. You would need to generate succinct compliance and logic proofs instead.


### Prove aggregations
You need to enable the `aggregation` feature to be able to prove or verify aggregations. 

The type of the aggregation proof is selected via a feature. It defaults to succinct stark proofs. For on-chain verification, you probably want to aggregate with the `groth16_aggregation` feature enabled. See the features table above for more information.

We currently support two different aggregation strategies. The _batch_ strategy aggregates all proofs in the transaction in a single run. It is the default aggregation.

```rust
use arm::transaction;

let mut tx = generate_test_transaction(1); // Just a dummy tx, for illustration.

// Upon succesful aggregation, compliance and resource logic proofs are erased.
assert!(tx.aggregate().is_ok());
```

The _sequential_ strategy aggregates sequentially, in an IVC style.

```rust
use arm::aggregation::AggregationStrategy;

assert!(tx.aggregate_with_strategy(AggregationStrategy::Sequential).is_ok());
``` 

**Warning:** Once again, aggregation erases all the individual proofs from `tx` and replaces them with the (single) aggregation proof in a dedicated field. This is why the transaction must be `mut`. This is true independently of the strategy used.

### Verify after aggregation
Use `tx.verify()`, as when there is no aggregated proof. Feature `aggregation` must be enabled. Otherwise, it will result in an error.


### External verification of the aggregation proof
Use `tx.get_raw_aggregation_proof()` to get the RISC0 `InnerReceipt` (the actual proof). The verifier would also need to derive the aggregation instance from `tx` on its own, and wrap both in a RISC0 `Receipt`.

### Comparison

**Strategy** | **Prover cost** | **Public input size** | **Aggregation scope** | **Memory efficient**
-------------|-----------------|-----------------------|-----------------------|----------------------
**batch** | amortized among all tx proofs | linear in #{tx proofs} | fixed (single prover) | for RISC0 yes. In general, depends on the zkVM (if supports continuations) 
**sequential** | linear in #{tx proofs} | constant | composable (different provers) | by design

The sequential (IVC) strategy is an example of proof-carrying data computation. PCD-based aggregation can be distributed across mutually _untrusted_ nodes, and proofs to be aggregated arbitrarily grouped and arranged in different transcripts.

**[TODO] Parallel proving at the ARM level.** It is possible with tree-like transcripts. Currently not supported, but [planned](https://github.com/anoma/arm-risc0/issues/112).