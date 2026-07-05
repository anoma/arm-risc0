# Merging the Conversion Mechanism into the Compliance Circuit

The [conversion circuit design](migration_post.md) introduces two new on-chain structures:

- a **Logic Conversion Tree** storing authorized `(old_kind, new_kind)` pairs, and
- a **generic conversion circuit** that proves membership in that tree and produces a balancing commitment.

This is clean as a standalone proposal. But looking at what the compliance circuit already does — computing homomorphic resource commitments keyed on resource kind — these two structures turn out to be the same thing in different clothes. This post works through that observation and explores what a merged design would look like.

---

## What the Compliance Circuit Already Does

ARM's compliance circuit enforces the balance equation. Each resource contributes a **resource commitment**:

```
ResourceCommitment(kind, q, r) = q · G(kind) + r · H
```

where `G(kind)` is a generator derived deterministically from the resource kind, `H` is the blinding generator, and `r` is fresh randomness. The circuit sums these commitments over all consumed and created resources and checks that the total is zero:

```
Σ ResourceCommitment(input_i)  −  Σ ResourceCommitment(output_j)  =  0
```

To do this, the circuit needs a **kind table**: a mapping from resource kind to its generator `G(kind)`. This table is trusted infrastructure — the circuit takes a Merkle proof from it for each resource kind it encounters.

---

## What the Conversion Circuit Adds

A conversion commitment for upgrading `q` units from `old_kind` to `new_kind` is:

```
ConversionCommitment = q · G(new_kind) − q · G(old_kind) + r · H
```

This can be rewritten as:

```
ConversionCommitment = q · ΔG(old_kind, new_kind) + r · H
```

where:

```
ΔG(old_kind, new_kind) = G(new_kind) − G(old_kind)
```

Compare this to a resource commitment:

```
ResourceCommitment(kind, q, r) = q · G(kind) + r · H
```

The structure is identical. A conversion commitment is a resource commitment whose "generator" is the difference of two kind generators. The conversion circuit is the compliance circuit, evaluated on a delta generator instead of a plain generator.

The kind table maps `kind → G(kind)`. The Logic Conversion Tree maps `(old_kind, new_kind) → ΔG`. Both map a key to a generator. The compliance circuit uses the generator to compute a commitment. The balance check sums commitments.

There is no structural reason for these to be separate.

---

## A Unified Generator Table

Merge the two structures into a single **Unified Generator Table** — a Merkle tree whose leaves are one of two types:

```
Kind leaf:
    type:       KIND
    key:        kind
    generator:  G(kind)

Conversion leaf:
    type:       CONVERSION
    old_kind:   old_kind
    new_kind:   new_kind
    generator:  ΔG = G(new_kind) − G(old_kind)
    sunset:     block_height (optional)
```

The leaf hash includes the type tag, so kind leaves and conversion leaves are cryptographically distinguished. The tree has a single root committed on-chain at each block.

Kind leaves are permissionless: `G(kind)` is a deterministic function of `kind`, so anyone can add a correctly-formed kind leaf and anyone can verify it independently. The protocol checks correctness at registration time.

Conversion leaves require external authorization. The protocol enforces whatever authorization policy is in place (governance vote, multisig approval, etc.) before inserting a conversion leaf. The circuit itself does not verify authorization — it trusts that any leaf present in the committed tree has already been authorized.

---

## The Unified Compliance Circuit

With the unified table, the compliance circuit is extended to handle both leaf types.

**Public inputs:**
- The Unified Generator Table root
- One combined balance commitment `C`

**Private witness, per resource:**
- The resource kind and quantity
- A Merkle proof of the kind leaf → `G(kind)`

**Private witness, per conversion:**
- The old and new kind
- The converted quantity
- A Merkle proof of the conversion leaf → `ΔG`
- The sunset height (if present in the leaf)

**Private witness, global:**
- A single randomness `r`

**What the circuit proves:**

For each resource:
1. The Merkle proof is valid against the declared tree root.
2. The leaf is of type KIND.

For each conversion:
1. The Merkle proof is valid against the same tree root.
2. The leaf is of type CONVERSION.
3. If `sunset` is present, the current block is at or before `sunset`.

**Delta commitment:**

The circuit computes the net generator sum over all resources and conversions in this unit:

```
S = Σ_i  sign_i · q_i · G(kind_i)
  + Σ_k  q_k · ΔG_k
```

where `sign_i = +1` for inputs and `−1` for outputs.

`S` is the balance contribution of this compliance unit. It is not required to be zero within a single unit — a transaction may span multiple compliance units, and the zero-sum check is enforced at the transaction level:

```
Σ_units  C_unit = 0
```

The unit publishes one delta commitment with a single randomness `r`:

```
C = S + r · H
```

Since `S` is not fixed to zero, `r` can be chosen freely and `C` is a proper hiding commitment. All intermediate values — the individual resource kinds, quantities, and conversion details — stay private inside the circuit. The ZK proof attests that `C` is correctly formed from the witness and that each Merkle proof is valid.

---

## Worked Example

Suppose a user holds `q` units of `KindV1` and wants `q` units of `KindV2`, where `(KindV1, KindV2)` is a registered conversion pair.

The transaction has:
- One input resource: `(KindV1, q)`
- One output resource: `(KindV2, q)`
- One conversion entry: `(KindV1 → KindV2, q)`

The circuit looks up three generators from the unified tree:

| Component | Leaf type | Generator |
|---|---|---|
| Input `KindV1` | KIND | `G(KindV1)` |
| Output `KindV2` | KIND | `G(KindV2)` |
| Conversion `(KindV1, KindV2)` | CONVERSION | `G(KindV2) − G(KindV1)` |

The net generator sum for this unit:

```
S = +q · G(KindV1)               [input]
  −  q · G(KindV2)               [output]
  +  q · (G(KindV2) − G(KindV1)) [conversion]
  =  0
```

In this single-unit transaction the contributions happen to cancel, so `S = 0`. In general, a transaction with multiple compliance units would have each unit contribute a non-zero `S`, with the deltas summing to zero across all units.

The circuit publishes one delta commitment:

```
C = S + r · H
```

All three Merkle proofs target the same tree root. The unit produces one ZK proof and one public group element `C`. No individual per-resource or per-conversion commitments are exposed.

---

## Comparison: Separate vs. Unified

| | Separate circuits | Unified compliance |
|---|---|---|
| On-chain roots | Kind table root + Conversion tree root | One unified root |
| Public commitments per transaction | One per resource + one per conversion | One combined commitment |
| Randomness values | One per resource + one per conversion | One |
| Proof types | Compliance proof + Conversion proof | One compliance proof |
| Tree updates | Two independent trees to update | One tree update per change |
| Circuit complexity | Two simpler circuits | One slightly more complex circuit |
| Non-migrating transactions | No conversion overhead | Still one tree root in all transactions |
| Authorization enforcement | Separate per-tree policy | Single tree update policy, two leaf types |

The unified approach reduces the number of on-chain commitments from N (one per resource plus one per conversion) to one, and collapses all randomness to a single value. Every transaction already produces a compliance proof; the merge folds conversion authorization into that proof with no additional ZK proof or additional randomness required.

The main trade-off is inclusion overhead: transactions that perform no conversions still reference the unified tree root. In the separate design, a non-migrating transaction has no knowledge of the conversion tree at all.

---

## Authorization Across Leaf Types

The most important design decision in the unified tree is how leaf-type authorization is enforced.

**Kind leaves** are self-authorizing: the generator `G(kind)` is a deterministic function of `kind`, which is itself a deterministic function of `(logic_vk, label)`. Anyone can compute and verify a kind leaf without external approval.

**Conversion leaves** are governance-authorized: the choice of which pairs are equivalent is a trust decision that cannot be derived from the pair alone. It must come from an external authority.

In the unified tree, these two authorization modes coexist. The cleanest way to handle this is to push authorization to the **tree update protocol** rather than the circuit:

- Protocol transactions that add a kind leaf check: `G == hash_to_curve(kind)`. No further approval needed.
- Protocol transactions that add a conversion leaf check: a valid authorization proof (governance signature, multisig threshold, etc.). The circuit then trusts the tree root, which only contains leaves that passed this check.

The circuit remains agnostic to authorization policy. It checks leaf type and verifies the Merkle proof. The tree root is the trust anchor.

---

## Summary

The conversion mechanism and the compliance circuit are doing the same thing: mapping a key (a resource kind or a conversion pair) to a generator, then using that generator to compute a homomorphic commitment. The balance equation is the same group equation in both cases.

Merging them collapses two Merkle trees into one and eliminates the conversion circuit as a separate proof type. Because all terms are computed inside a single circuit, only one combined balance commitment is published and only one randomness is needed — down from one per resource and one per conversion in the separate design. The unified compliance circuit handles both resource kinds and conversion pairs against one tree root, producing one proof and one public group element per transaction regardless of whether a conversion is present.

The key design decision is keeping authorization enforcement in the tree update mechanism rather than the circuit. Kind leaves are self-verifying; conversion leaves are governance-authorized. The circuit trusts the tree root as the sole trust anchor and remains agnostic to how that root was formed.
