# Anoma Resource Machine Test App

A test application for the Anoma Resource Machine implementation using RISC0 zkVM. This crate demonstrates transaction creation, validation, and proof generation with example resource logic.

## Overview

The `anoma-rm-risc0-test-app` crate provides:

- **Test Logic Implementation**: A simple yet complete resource logic circuit for testing
- **Transaction Generation**: Utilities for creating test transactions with multiple actions and compliance units
- **Proof Verification**: Examples of generating and verifying different proof types (Succinct, Groth16)
- **Aggregation Testing**: Demonstration of proof aggregation with batch strategy
- **Integration Tests**: Comprehensive test suite validating ARM functionality

## Key Components

### Test Logic Circuit

The `TestLogic` struct implements a minimal but complete resource logic circuit:

- Validates resource consumption and creation
- Generates zero-knowledge proofs for logic verification
- Includes resource commitments and nullifier key handling
- Supports both succinct and Groth16 proof types

```rust
pub struct TestLogic {
    witness: TestLogicWitness,
}

impl LogicProver for TestLogic {
    // Implements proof generation and verification
}
```

### Transaction Construction Utilities

#### `create_an_action_with_multiple_compliances`
Creates a single action with multiple compliance units:
- Generates consumed and created resources
- Builds Merkle trees for resource inclusion proofs
- Creates logic verification inputs for each resource

#### `create_multiple_actions`
Creates multiple actions for stress testing and validation:
- Combines multiple actions into a single transaction
- Compresses delta witnesses for state transitions

#### `generate_test_transaction`
High-level utility for creating complete test transactions:
- Creates a balanced transaction with delta proofs
- Verifies transaction validity
- Ready for immediate testing or aggregation

## Features

- `cuda`: Enable CUDA acceleration for proof generation
- `prove`: Enable local proof generation (enabled by default)
- `bonsai`: Enable remote proof execution via Bonsai

## Testing

The crate includes a comprehensive test suite:

### Basic Tests

- **`test_logic_prover`**: Validates individual logic proof generation
- **`test_action`**: Tests action creation with multiple compliance units
- **`test_transaction`**: Validates complete transaction flow

### Validation Tests

- **`test_unmatched_logic_verifier_inputs_in_action`**: Ensures logic proof validation catches mismatches
- **`test_nullifier_duplication_check`**: Verifies duplicate nullifier detection

### Aggregation Tests

- **`test_aggregation_works`**: Tests batch proof aggregation strategy
- **`test_aggregation_works_groth16`**: Tests aggregation with Groth16 proofs (ignored by default)
- **`test_verify_aggregation_fails_for_incorrect_instances`**: Validates aggregation integrity checks
- **`test_cannot_aggregate_invalid_proofs`**: Ensures invalid proofs cannot be aggregated

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
anoma-rm-risc0-test-app = "1.0"
```

## Running Tests

```bash
# Run all tests
cargo test

# Run tests in dev mode(This will not generate valid, secure proofs)
RISC0_DEV_MODE=1 cargo test

# Run specific test
cargo test test_aggregation_works
```

## Performance Considerations

- Proof generation is the most time-intensive operation
- Use `bonsai` feature for remote proving on slower machines
- Use `cuda` feature for GPU acceleration
- Aggregation tests are ignored by default due to proving overhead

## License

Licensed under the Apache License 2.0. See [LICENSE](../../LICENSE) for details.
