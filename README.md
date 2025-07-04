# Anoma Risc0 Resource Machine

This is a shielded resource machine implementation based on [Risc0-zkvm](https://github.com/risc0/risc0)

## Docs

* [Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)
* [Anoma SDK](https://github.com/anoma/anoma-sdk)

## ARM-RISC0 Directory Structure

- **`arm/`**: The main Anoma Shielded Resource Machine implementation providing the core functionality for Anoma SDK and Validator.

- **`examples/`**: Demonstration applications showcasing different use cases:
  - **Compliance Circuit**: Basic compliance checking circuit
  - **Trivial Logic**: Minimal logic circuit example, also used in padding resources
  - **Simple Counter**: A simple counter increment example
  - **Kudo Application**: A relatively complex example; more detailed descriptions can be found [here](https://research.anoma.net/t/shielded-kudos-revised-no-authorisation-abstraction/1522)

## Getting Started

### Dependencies

* Rust: [intall rust instructions](https://www.rust-lang.org/tools/install)
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

## Feature flags

We hava the following feature flags in arm lib:


| Feature                  | Implies                   | Description                                                                                                                     |
| ------------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| logic_circuit            |                           | It provides logic-related traits and gadgets                                                            |
| compliance_circuit       |                           | A specific feature for compliance circuit                                                                                       |
| transaction(default)     | logic_circuit, compliance_circuit, prove | It provides full transaction processing capabilities and will be in the Anoma SDK and validator with a selected prover feature. |
| prove                    |                           | Enables RISC0 proving capabilities (required for actual proof generation)                                                       |
| succinct_prover(default) |                           | Generates constant-size STARK proofs using recursion                                                                            |
| composite_prover         |                           | Fastest option producing linear-size proofs without compression                                                                 |
| groth16_prover           |                           | Generates groth16 proofs(requires x86_64 machines)                                                                              |
| nif                      |                           | Enables Erlang/Elixir NIF (Native Implemented Function) bindings  
| aggregation              |                           | Enables proof aggregation (with constant-sized proofs by default) |
|fast_aggregation          |                           | Faster aggregation with linear-sized proofs without compression


### Usage Examples

```toml
# Default configuration (succinct proofs + transaction support)
arm = "0.1.0"

# Blockchain deployment with Groth16 proofs
arm = { version = "0.1.0", default-features = false, features = ["groth16_prover", "transaction"] }

# Logic-circuit-only usage
arm = { version = "0.1.0", default-features = false, features = ["logic_circuit"] }

# Elixir Anoma SDK
arm = { version = "0.1.0", features = ["nif"] }

# Proof aggregation
arm = { version = "0.1.0", features = ["aggregation"] }
```


## Reproducibly generate proving and verifying keys (ELF and ImageID)

You may generate different ELFs and ImageIDs on different machines and environments. To reproduce the same output and publicly verify that the ELF and ImageID correspond to the specific circuit source code, use the following tool and command.

For example, build the compliance circuit in RM:

```bash
cargo risczero build --manifest-path examples/compliance_circuit/methods/guest/Cargo.toml
```

will reproduce the output to:

```bash
View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/zbrzf1brqyb5evydjxs9h3gvl

ELFs ready at:
ImageID: e9f77211dc64f622255312cbe02fb883b3cf89d9a0c325f8495636e63e4cbdcb - 
arm-risc0/examples/compliance_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/compliance-guest.bin
```

Note: The `unstable` feature of `risc0-zkvm` currently causes issues in circuits. This can be temporarily fixed by manually updating the tool. The problem will be fully resolved in the next release of RISC Zero.
```bash
cargo install --force --git https://github.com/risc0/risc0 --tag v2.1.0 -Fexperimental cargo-risczero
```

## Benches
Benchmarks are in **`arm/benches`**. For example, to run benchmarks for proof aggregation run:
```bash
  cargo bench --features aggregation
```
or with the extra feature `fast_aggregation` to enable the RISC Zero fast prover option.