# Nonce Derivation

This document specifies how the nonce of each created resource derives from the consumed resources of its compliance unit. The code is in [`arm_core/src/resource.rs`](../arm_core/src/resource.rs) (`Resource::hash_nullifiers`, `Resource::derive_nonce`, `Resource::derive_nonce_from_nullifiers`) and in `compliance::constrain` in [`arm/src/compliance.rs`](../arm/src/compliance.rs). The glossary [`CONTEXT.md`](../CONTEXT.md#language) defines the terms.

## 1. The derivation

Let `nf_0 … nf_{n-1}` be the nullifiers of the consumed resources of a unit, and let `j` be the index of a created resource among the created resources. Both follow the order of the list ([`01-compliance-units.md`](./01-compliance-units.md)).

```
digest  = SHA-256(nf_0 ‖ nf_1 ‖ … ‖ nf_{n-1})
nonce_j = SHA-256("ARM_NONCE_DERIVATION" ‖ j ‖ digest)
```

`j` is a 4-byte big-endian integer. `Resource::hash_nullifiers` calculates the digest, and `Resource::derive_nonce` calculates the nonce. `Resource::derive_nonce_from_nullifiers` does both steps.

The nonce is a field of the resource. So the commitment and the nullifier of a created resource depend on its nonce.

## 2. Why each nonce is unique

Each nonce is unique within one ARM instance: one commitment tree and one nullifier set, for example one protocol adapter. arm-risc0 holds no state, so the uniqueness needs a check of the instance:

- The nullifier set of the instance accepts each nullifier only once. So no two compliance units that one instance accepts consume the same nullifier, and no two of them have the same digest.
- In one unit, each created resource has a different index.

So in one ARM instance, no two created resources get the same nonce, if SHA-256 has no collisions. Without this, two resources with the same other fields would have the same commitment and the same nullifier, and their owner could consume only one of them. Two instances can accept the same transaction, and then both hold the same resources.

## 3. Consequences

- **Each unit consumes at least one resource.** For an empty list, `Resource::hash_nullifiers` fails with `EmptyNullifiers`, so `compliance::constrain` fails. A wrap, for example, consumes an ephemeral resource.
- **Each action has a nullifier that no other action of its ARM instance has.** So two actions of one ARM instance never have the same action tree root. The protocol adapter relies on this: it identifies a transaction by a hash of its action tree roots.
- **The order fixes the commitments.** The nonce of a created resource depends on all consumed resources of its unit and on its position among the created resources. A prover can calculate a commitment only after it fixes the consumed resources and the order of the created resources.
- **The rule applies only to created resources.** A consumed resource keeps the nonce that it got when a transaction created it. A consumed ephemeral resource that no transaction created can have any nonce.

## 4. The in-circuit check

`compliance::constrain` collects the nullifiers of the consumed resources in its pass over the list, calculates the digest, and then requires `nonce_j` for each created resource `j`. A different nonce makes it fail with `InvalidResourceNonce`.

## 5. Out-of-circuit checks

- **The verifier rejects repeated nullifiers.** The uniqueness of the nonces depends on this out-of-circuit check. The protocol adapter keeps a nullifier set for it.

## 6. Parameters

| Name             | Value                             |
| ---------------- | --------------------------------- |
| Domain separator | `ARM_NONCE_DERIVATION` (20 bytes) |
| Index `j`        | `u32`, 4 bytes, big-endian        |
| Hash             | SHA-256                           |
