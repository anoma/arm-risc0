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

The `Tester` struct accumulates consumed witnesses, created resources, and the
delta-commitment randomness across one or more actions, then assembles the
corresponding compliance units, actions, and transactions:

#### `Tester::populate_consumed_resources(num)` / `populate_created_resources(num)`
Fills the tester's per-action buffers with `num` consumed witnesses (each
backed by a fresh nullifier key) or `num` created resources (with nonces
derived from the consumed nullifiers).

#### `Tester::create_compliance_unit(consumed_num, created_num)`
Builds a `ComplianceWitness` from the populated resources and proves it,
returning a `ComplianceUnit`.

#### `Tester::create_an_action(consumed_num, created_num)`
Wraps the compliance unit with the matching logic verifiers (one per
consumed nullifier and one per created commitment), in the order produced
by the compliance instance.

#### `Tester::create_multiple_actions(&[(consumed_num, created_num), ...])`
Convenience wrapper that creates one action per `(consumed, created)` pair.

#### `Tester::generate_test_transaction(&[(consumed_num, created_num), ...])`
High-level entry point: builds the actions, composes a transaction with a
`DeltaWitness`, and returns it after generating the delta proof.

## Features

- `cuda`: Enable CUDA acceleration for proof generation
- `prove`: Enable local proof generation (enabled by default)
- `bonsai`: Enable remote proof execution via Bonsai

## Testing

The crate includes a comprehensive test suite:

### Basic tests

- **`test_logic_prover`**: validates individual logic proof generation.
- **`test_compliance_unit`**: builds and verifies a compliance unit with
  multiple consumed and created resources.
- **`test_compliance_unit_balanced_same_kind`**: exercises per-kind quantity
  aggregation in `constrain_delta` (same-kind resources netting to zero).
- **`test_action`**: tests action creation and per-action verification.
- **`test_action_with_zero_created`**: action with consumed but no created
  resources.
- **`test_transaction`**: validates the complete transaction flow.
- **`test_compose_transactions`**: composes two witness-form transactions and
  verifies the result.

### Validation tests

- **`test_compliance_unit_must_consume_resources`**: a unit with zero consumed
  resources is rejected with `EmptyNullifiers`.
- **`test_invalid_created_nonce_rejected`**: a tampered created-resource nonce
  is rejected with `InvalidResourceNonce` inside `constrain`.
- **`test_unbalanced_tx_fails_to_verify`**: an unbalanced delta makes the
  transaction fail to verify.
- **`test_unmatched_logic_verifier_inputs_in_action`**: action verification
  catches mismatched / missing logic verifier inputs.
- **`test_nullifier_duplication_check`**: detects duplicate nullifiers across
  the actions in a transaction.

### Aggregation tests (require `--features aggregation`)

- **`test_aggregation_works`**: batch-aggregates a multi-action transaction
  and verifies the aggregation proof.
- **`test_verify_aggregation_fails_for_incorrect_instances`**: tampering with
  the public instance after aggregation is detected.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
anoma-rm-risc0-test-app = "1.1.1"
```

## Running Tests

```bash
# Run all tests
cargo test

# Run tests in dev mode (this will not generate valid, secure proofs)
RISC0_DEV_MODE=1 cargo test

# Include aggregation tests (require --features aggregation)
RISC0_DEV_MODE=1 cargo test --features aggregation

# Run a specific test
cargo test test_aggregation_works
```

## Performance Considerations

- Proof generation is the most time-intensive operation
- Use `bonsai` feature for remote proving on slower machines
- Use `cuda` feature for GPU acceleration
- Aggregation tests are gated on `--features aggregation`; outside dev mode,
  proof generation dominates the wall time

## License

Licensed under the Apache License 2.0. See [LICENSE](../../LICENSE) for details.
