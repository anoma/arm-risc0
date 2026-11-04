# Proofs and Verification

This document specifies the delta proof, the aggregation proof and its journal, the transaction, and the out-of-circuit checks of a verifier. The code is in [`arm_core/src/delta_proof.rs`](../arm_core/src/delta_proof.rs), [`arm/src/delta_proof.rs`](../arm/src/delta_proof.rs), [`arm_core/src/aggregation_witness.rs`](../arm_core/src/aggregation_witness.rs), [`arm_core/src/aggregation_instance.rs`](../arm_core/src/aggregation_instance.rs), [`arm/src/aggregation_instance.rs`](../arm/src/aggregation_instance.rs), [`arm/src/transaction.rs`](../arm/src/transaction.rs) and the [aggregation circuit](../arm_circuits/batch_aggregation/methods/guest/src/main.rs). The glossary [`CONTEXT.md`](../CONTEXT.md#language) defines the terms.

## 1. Delta proof

The delta of a compliance unit is the sum of `kind base × (consumed quantity − created quantity)` over its resources, plus `rcv × G`, where `rcv` is a random scalar of the unit and `G` is the generator of the curve.

The **delta message** is the concatenation of the action tree roots of the transaction, 32 bytes for each action. The delta proof is a recoverable ECDSA signature over the Keccak-256 hash of this message, with the sum of the `rcv` values as the signing key. In an out-of-circuit check, the verifier recovers the public key and compares it with the sum of the deltas of all actions. A valid signature shows that the kind base parts of the deltas cancel, if nobody knows a linear relation between `G` and the different kind bases ([`03-kind-tree.md`](./03-kind-tree.md)).

The proof and the witness are fixed-size byte types:

- `DeltaProof` holds 64 signature bytes and a recovery id. Its wire form has 65 bytes, with the recovery id as 27 or 28. `DeltaProof::from_bytes` also accepts 0 or 1, and it requires `r` and `s` in `[1, n−1]`.
- `DeltaProof::check_low_s` requires `s ≤ n/2`, so a second form of the same signature is not valid. `delta_proof::prove` rejects the recovery ids 2 and 3.
- `DeltaWitness` holds one scalar in `[1, n−1]`. `delta_proof::from_scalars` and `delta_proof::compress` reject an empty list. `delta_proof::from_scalars` and `delta_proof::compose` reject a zero sum, and `delta_proof::compress`, which adds the witnesses one by one, fails if a partial sum is zero.

## 2. Aggregation proof and journal

The aggregation proof is one proof for all compliance units and resource logic proofs of a transaction. `transaction::aggregation_witness` builds its input, the `AggregationWitness`. It holds the compliance verifying key, and for each action the compliance instance and the app data of each resource. The proofs themselves go to the circuit as assumptions.

The aggregation circuit does these steps, which include its in-circuit checks:

1. It requires at least one action.
2. It verifies each compliance proof against the compliance verifying key of its input.
3. It requires the same kind tree root for all actions that do not have the root `PADDING_LEAF`.
4. It requires one app data entry for each resource.
5. It calculates the action tree root of each action from its tags.
6. For each resource, it builds the logic instance from the tag, the consumed flag, the action tree root and the app data, and it verifies the logic proof against the logic ref of the resource.
7. It outputs the aggregation instance.

The **journal** is the public output of the aggregation proof. It is the `AggregationInstance`: the compliance verifying key, the kind tree root, and for each action its resources, its delta point and its action tree root. Each resource holds its tag, its logic ref, its app data and, if consumed, its commitment tree root.

`JournalEncoding` selects one of two encodings, each with its own circuit and key:

| Encoding                      | Verifier             | Proving key                | Verifying key              |
| ----------------------------- | -------------------- | -------------------------- | -------------------------- |
| `JournalEncoding::Risc0Serde` | RISC Zero and Solana | `BATCH_AGGREGATION_PK`     | `BATCH_AGGREGATION_VK`     |
| `JournalEncoding::Abi`        | EVM                  | `BATCH_AGGREGATION_EVM_PK` | `BATCH_AGGREGATION_EVM_VK` |

The ABI form, `abi_encode_instance`, uses the types of [`arm/src/aggregation_instance.rs`](../arm/src/aggregation_instance.rs). It encodes the parameters `(bytes32 complianceKey, bytes32 kindTreeRoot, Action[] actions)` with `abi_encode_params`, not the instance as one tuple. The protocol adapter calculates the SHA-256 hash of these bytes itself, with its own copy of the compliance verifying key. A created resource has the commitment tree root `bytes32(0)`, and a blob, a list of 32-bit words, goes into the encoding as its bytes. `AggregationInstance::to_journal` writes the RISC Zero encoding without the zkVM, for verifiers such as `anoma-rm-solana`. A test compares it with the encoding of the zkVM. The verifying keys are constants in [`arm_core/src/constants.rs`](../arm_core/src/constants.rs). They change when the circuits change.

`transaction::aggregate` makes the proof, stores it with the instance in the field `aggregation` of the transaction, and removes the actions. In out-of-circuit checks, `transaction::verify_aggregation` requires that the compliance verifying key in the instance is `COMPLIANCE_VK`, encodes the instance, and verifies the proof against the key of the encoding.

## 3. Transaction

`Transaction` holds the actions, the delta proof, an unused field `expected_balance`, and the aggregation. `Transaction::check_representation` requires either the actions or the aggregation, not both. `transaction::verify` takes the transaction, the expected kind tree root and the encoding. Its out-of-circuit checks verify the delta proof, reject repeated nullifiers, check the kind tree root, and then verify either the aggregation proof or each action.

## 4. Out-of-circuit checks

- **The out-of-circuit checks cover what the in-circuit checks do not.** No in-circuit check rejects repeated nullifiers, compares commitment tree roots or the kind tree root with stored values, or verifies the delta proof, and the aggregation circuit outputs the compliance verifying key of its input. The out-of-circuit checks of `transaction::verify` cover the delta proof, the repeated nullifiers of the transaction, the kind tree root and the compliance verifying key. Only a verifier with state can check that each commitment tree root is a historical root and that no transaction consumed a nullifier before. The protocol adapter on EVM makes both out-of-circuit checks, and it uses its own copy of the compliance verifying key.

## 5. Trust assumptions

- **Nobody knows a linear relation between `G` and the kind bases.** The delta proof shows balance only under this condition, which [`03-kind-tree.md`](./03-kind-tree.md) states in full.
