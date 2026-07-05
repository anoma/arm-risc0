# Private Logic Upgrades in the Anoma Resource Machine

Software changes. A bug is found, a feature is added, a constraint is tightened. In most systems, upgrading is a matter of deploying new code and migrating old state. In a privacy-preserving resource machine, it is considerably harder.

This post describes a mechanism for upgrading resource logic in the Anoma Resource Machine (ARM) without breaking privacy, without introducing mutable registries, and without requiring application-specific migration code. The approach adapts Namada's conversion circuit — originally designed for asset conversions — to the problem of logic upgrades.

---

## The Problem: Logic is Identity

In ARM, every resource carries a **kind** derived from two things: the verifying key of the resource logic and an application-defined label.

```
resource_kind = H(logic_vk || resource_label)
```

This is a deliberately strong commitment. The kind cryptographically identifies the exact logic that governs the resource. No two distinct logic programs can produce the same kind (under collision resistance), and the kind is permanent — it cannot be changed without producing a different resource.

This is good for security. A resource created under `logic_V1` will always be verified against `logic_V1`, regardless of what the application developer does later. Historical resources remain sound forever.

It is bad for upgrades. When a developer modifies the resource logic — even a one-line fix — the verifying key changes. A new verifying key means a new kind. And a new kind means existing resources are incommensurable with resources created by the new logic.

Specifically, ARM's balance equation requires:

```
Inputs − Outputs = 0
```

This is checked homomorphically: each resource contributes a value commitment derived from its kind and quantity. If the input resources are of `KindV1` and the output resources are of `KindV2`, the sum cannot be zero because `G(KindV1) ≠ G(KindV2)`. The transaction fails to balance.

The naive fix — a mutable logic registry where the application can update its verifying key — destroys the security property that made immutable logic valuable. A registry that can be updated by the application means that resource logic is ultimately controlled by whoever controls the registry, not by the resource itself.

---

## The Key Insight: Upgrades as Authorized Equivalences

Instead of making logic mutable, we make the balance relation extensible.

A logic upgrade asserts: *resources governed by `KindV1` and resources governed by `KindV2` are equivalent for balancing purposes.* This is not a statement about the logic code — it is a statement about the resources those two logics produce. The assertion is authorized by some external authority (application governance, protocol governance, multisig, etc.) and recorded in a shared data structure.

This reframing separates two concerns that are easily conflated:

- **What logic governs a resource** — determined forever at creation time, immutable
- **Whether two kinds are equivalent for balancing** — a relation that can be extended over time with proper authorization

With this separation, upgrading does not mean changing any resource's logic. It means declaring, with appropriate authority, that the old and new resource kinds are interchangeable.

---

## The Logic Conversion Tree

The global **Logic Conversion Tree** is a Merkle tree where each leaf commits to an authorized conversion pair:

```
(old_resource_kind, new_resource_kind)
```

The tree plays the role that a conversion table plays in Namada. A few example leaves:

```
(KindV1, KindV2)   ← V1 logic upgraded to V2
(KindV2, KindV3)   ← V2 logic upgraded to V3
(KindA, KindB)     ← an independent application's upgrade
```

All conversions are 1:1. Registering a pair asserts equivalence, not transformation.

The registration mechanism — who may add leaves and under what conditions — is intentionally out of scope for the conversion circuit itself. The circuit only cares that a pair exists in the tree. The authorization could be application governance, a multisig threshold, or protocol-level governance. Once registered, the conversion is usable permissionlessly by anyone.

The tree root is committed on-chain at each block. Every conversion proof must reference a root within the protocol's accepted anchor window; stale proofs are rejected.

---

## The Generic Conversion Circuit

ARM provides a single generic conversion circuit shared by all applications. It takes:

**Public inputs:**
- The Logic Conversion Tree root
- The conversion commitment (defined below)

**Private witness:**
- The old resource kind
- The new resource kind
- The converted quantity
- A Merkle proof for the conversion pair against the declared root
- A random blinding factor

The circuit proves four things:

1. The Merkle proof is valid against the declared tree root.
2. The proven leaf contains the pair `(old_kind, new_kind)`.
3. The conversion ratio is 1:1.
4. The conversion commitment is correctly formed from the witness.

That is all. **The circuit never inspects resource logic, never consumes resources, and never creates resources.** Its sole output is a well-formed commitment that participates in transaction balancing.

---

## The Conversion Commitment

Rather than publishing the conversion pair and quantity in the clear, the circuit produces a hiding, binding commitment:

```
C = Commit(old_kind, new_kind, quantity, randomness)
```

Using a Pedersen-style commitment over the curve used for value commitments in ARM, the concrete form is:

```
ConversionCommitment = q · G(new_kind) − q · G(old_kind) + r · H
```

where:
- `G(kind)` is a generator derived deterministically from the resource kind (e.g., hash-to-curve with domain separation)
- `H` is the blinding generator
- `r` is fresh randomness chosen by the prover

This structure is homomorphic. The commitment can be added to the transaction's balance sum with ordinary group addition, no special handling required.

The published commitment reveals nothing. To an external observer, it is an indistinguishable random group element.

---

## How Balancing Works

Consider a transaction that consumes `q` units of `KindV1` and creates `q` units of `KindV2`. Without a conversion, the balance equation fails:

```
q · G(KindV1) − q · G(KindV2) ≠ 0
```

because `G(KindV1) ≠ G(KindV2)`.

The conversion commitment contributes:

```
q · G(KindV2) − q · G(KindV1) + r · H
```

Adding this to the balance (and accounting for the blinding terms from the resource commitments):

```
q · G(KindV1) − q · G(KindV2) + q · G(KindV2) − q · G(KindV1) + (blinding terms) = 0
```

The kind-dependent terms cancel exactly. The transaction balances.

The full balance equation is:

```
Inputs − Outputs + ConversionCommitments = 0
```

The verifier checks this equation over group elements, seeing only commitments. It learns nothing about which kinds were converted or how much.

---

## Privacy

Publishing the conversion pair directly would leak:
- which application is upgrading
- which logic versions are involved
- how many resources were migrated in each transaction

The commitment scheme hides all of this. A transaction with a conversion commitment is indistinguishable from one without. An observer cannot tell whether the commitment represents `KindV1 → KindV2` or `KindX → KindY` or any other authorized pair, and cannot determine the quantity converted.

This matters in practice. Upgrade activity is metadata. An observer who knows which application is upgrading and when can infer user behavior even without seeing resource contents. Hiding the conversion pair and quantity preserves the same privacy guarantees ARM provides for ordinary resource operations.

---

## Composable Upgrades

Because the conversion only contributes to balancing, it composes freely with arbitrary resource operations. A migration does not require a dedicated transaction:

```
Consume:    OldToken
Create:     NewToken, Payment, Change
Conversion: Commit(OldKind, NewKind, amount, r)
```

The payment and change outputs use the new logic. The conversion commitment bridges the balance gap. The application logic for `NewToken`, `Payment`, and `Change` does not know a conversion occurred.

Users do not need to take any special action beyond including the conversion proof alongside their normal spend. Wallets can handle this transparently.

### Chained Upgrades

When a kind has gone through multiple upgrades — V1 to V2 to V3 — a user holding V1 resources who wants V3 resources includes two conversion proofs in the same transaction. The intermediate kind cancels algebraically:

```
Input:         q · G(V1)
Output:       −q · G(V3)
Conversion 1:  q · G(V2) − q · G(V1)
Conversion 2:  q · G(V3) − q · G(V2)
─────────────────────────────────────
Total:         0  ✓
```

No intermediate resources need to be created. The V2 terms cancel in the balance sum. Each proof is independent; they only interact through the balance equation.

---

## Sunsetting Old Resource Kinds

Registering a conversion pair does not retire the old kind. Resources of `KindV1` remain creatable and spendable under `V1` logic indefinitely. In ordinary circumstances this is harmless — users migrate at their own pace.

When an upgrade is driven by a security fix, however, this is a problem. An attacker who finds the vulnerability in `V1` logic can still exploit it post-upgrade to mint illegitimate `KindV1` resources, then immediately convert them to `KindV2`. The upgrade does not protect against the attack; it only offers legitimate users a path to the new logic.

The fix is to include an optional **sunset block height** in each conversion leaf:

```
(old_kind, new_kind, sunset_height)
```

After `sunset_height`, the protocol refuses to consume or create `KindV1` resources. Users have a bounded window to migrate; after the window closes, the old logic is effectively retired by consensus.

Two enforcement approaches:

**Protocol-enforced sunset.** The balance circuit checks the current block against `sunset_height`. No changes to existing resource logic are required.

**Logic-gated sunset.** `V1` logic itself gates spending on a block height or the presence of a registered conversion. This requires forward-looking design in the old logic — practical only if applications anticipate needing this mechanism.

For security-motivated upgrades, the protocol-enforced approach is preferred because it does not depend on the old logic having been written correctly in the first place.

---

## What Remains Open

**Registration policy.** The conversion circuit is agnostic about who may register pairs. In practice, the right answer depends on the application: a stablecoin might require issuer multisig; a protocol primitive might require governance. The key property is that the circuit enforces whatever policy is encoded in the tree — the tree itself is the trust root.

**Semantic equivalence.** Registering `(KindV1, KindV2)` asserts that the two kinds are equivalent for balancing. It does not prove it. The registration authority is responsible for ensuring that the new logic actually preserves the application semantics users expect. The circuit has no opinion on this; it only checks membership.

**Sunset governance.** If a sunset height is included, it should be immutable once committed to the tree. Extending a sunset means registering a new leaf with a later height — potentially alongside (or replacing) the original. The protocol needs a policy for which leaf takes precedence when multiple leaves exist for the same pair.

**New logic's creation constraints.** The conversion proof authorizes the balance adjustment. It does not automatically satisfy `V2`'s resource creation logic. If `V2` enforces constraints on how new resources may be created (an issuer signature, a proof of legitimacy), those constraints must be satisfied independently. The conversion proof is necessary but not sufficient for a migration transaction.

---

## Summary

The approach adapts Namada's conversion-circuit design from asset conversions to logic upgrades.

The central observation is that a logic upgrade is an authorized equivalence between two resource kinds, not a transformation of resources. Modeling it this way lets a single generic circuit — one shared by all applications — handle every upgrade case. The circuit proves membership in a global Logic Conversion Tree and produces a hiding, binding commitment that participates in transaction balancing via homomorphic addition.

The result has several desirable properties simultaneously:

| Property | How it's achieved |
|---|---|
| Generic | One circuit, shared across all applications |
| Immutable logic | Resource kinds remain bound to fixed verifying keys |
| Permissionless use | Anyone can use a registered conversion |
| Private | Committed kinds and quantities are never revealed |
| Composable | Conversions only touch balancing; resource logic is unaffected |
| Protocol minimal | No registries, no version identifiers, no upgrade hooks in ARM itself |

The only additions to ARM are the Logic Conversion Tree and its associated circuit — both of which are reusable, application-agnostic components.
