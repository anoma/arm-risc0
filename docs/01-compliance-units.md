# Compliance Units of Variable Size

This document specifies the compliance unit: one unit for each action, with one or more consumed resources and any number of created resources in one ordered list. It also specifies how the logic proofs pair with the resources. The code is in [`arm_core/src/compliance.rs`](../arm_core/src/compliance.rs), [`arm_core/src/resource.rs`](../arm_core/src/resource.rs), [`arm/src/compliance.rs`](../arm/src/compliance.rs) and [`arm/src/action.rs`](../arm/src/action.rs).

## 1. The unit

Each action has exactly one compliance unit. Consumed and created resources can occur in any order in its list.

The **compliance witness** is the private input of a compliance unit. Its field `resource_witnesses` is the ordered list. Each **resource witness** is the private data of one resource:

- `ResourceWitness::Consumed` holds the resource, the Merkle path of its commitment, and its nullifier key.
- `ResourceWitness::Created` holds the resource.

The witness also holds the ephemeral root, the randomness `rcv` of the delta, and one optional kind path for each resource ([`03-kind-tree.md`](./03-kind-tree.md)). `rcv` must be a 32-byte scalar below the order of the curve (`InvalidRcv`). The ephemeral root is a value of the witness: `compliance::from_resources` sets it to `INITIAL_ROOT`, which is `PADDING_LEAF`, the root of the empty commitment tree.

The **compliance instance** is the public output of a compliance unit. Its field `resource_instances` has one entry for each resource, in the order of the witness:

- `ComplianceResourceInstance::Consumed` holds the nullifier, the logic ref and the commitment tree root.
- `ComplianceResourceInstance::Created` holds the commitment and the logic ref.

The instance also holds the delta point of the unit and the kind tree root.

`compliance::constrain` makes the compliance checks. For each resource, it does these steps in one pass:

1. It calculates the commitment.
2. For a consumed resource, it calculates the nullifier from the nullifier key, which must match the nullifier key commitment of the resource. It calculates the commitment tree root from the Merkle path. A consumed ephemeral resource uses the ephemeral root of the witness instead.
3. It adds the quantity of a consumed resource to the delta, and subtracts the quantity of a created resource, each multiplied by the kind base of the resource.

After the pass, it checks the nonce of each created resource ([`02-nonce-derivation.md`](./02-nonce-derivation.md)). A unit whose delta is the identity point fails (`InvalidDelta`).

The list has no length limit. The time to make the proof and the gas limit of the chain limit an action.

## 2. The order of the list

The order of the witness list is also the order of these items:

- the entries of the compliance instance,
- the leaves of the action tree, from `ComplianceInstance::tags`,
- the logic proofs of the action,
- the resources of the action in the aggregation journal,
- the resources that the protocol adapter processes, and so the order of the external calls.

Each logic proof and the delta proof cover the action tree root, so they cover the order. A resource logic can also require the signature of the owner over the root.

## 3. Pairing of logic proofs

An `Action` holds one `ComplianceUnit` and one `LogicVerifierInput` for each resource, in the order of the list. They pair by position. `action::verify` makes out-of-circuit checks of three conditions:

- The number of inputs is the number of resources (`LogicVerifierInputCountMismatch`).
- The tag of input `i` is the tag of resource `i` (`LogicVerifierTagMismatch`).
- The verifying key of input `i` is the logic ref of resource `i` (`VerifyingKeyMismatch`). So a proof of another circuit cannot replace the proof of the resource logic.

`transaction::aggregation_witness`, which builds the input of the aggregation circuit, checks only the count and the tags. An in-circuit check of the aggregation circuit covers the third condition: the circuit builds each logic instance from the compliance instance and verifies the logic proof against the logic ref of the resource. So a proof of another circuit makes the aggregation fail ([`04-proofs-and-verification.md`](./04-proofs-and-verification.md)). Whether a resource is consumed comes from its variant in the compliance instance, not from its position.

## 4. Out-of-circuit checks

- **The verifier rejects repeated nullifiers.** No in-circuit check compares the nullifiers of the consumed resources of a unit. Two out-of-circuit checks reject a repeated nullifier: `transaction::nf_duplication_check` over the whole transaction, and the nullifier set of the protocol adapter over all transactions.
- **The verifier checks the commitment tree roots.** The compliance circuit calculates the root of each consumed resource, but no in-circuit check compares it with a stored root. An out-of-circuit check of the protocol adapter requires each root to be a historical root.
