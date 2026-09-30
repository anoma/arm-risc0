# Replace flat kind-table array with Merkle tree for O(log N) circuit lookup

## Background

The compliance circuit currently resolves a resource's kind point by linearly scanning a flat `Vec<KindTableEntry>` carried in `ComplianceWitness`. The table is committed to as a flat hash (`hash_kind_table_entries`) stored in `ComplianceInstance`.

A new benchmark (`compliance/table_size`) confirms that circuit cost scales with table size: as entries grow, the guest executes more iterations, eventually crossing a segment boundary and increasing proof time.

## Proposal

Replace the flat array with a Merkle tree whose root is stored as the kind-table commitment in `ComplianceInstance`. Each `ComplianceWitness` carries a per-resource Merkle path (one path per consumed/created resource) instead of the full table.

**Lookup semantics stay unchanged:**
- Path present → verify membership and use the stored kind point directly (skipping `hash_to_curve`)
- Path absent / `None` → fall back to `hash_to_curve` as today

No non-membership proof is needed; an empty path is the existing "not in table" signal.

## Impact

| | Current (flat array) | Proposed (Merkle tree) |
|---|---|---|
| Witness data per resource | O(N) — full table | O(log N) — one path |
| Circuit cost per resource | O(N) — linear scan | O(log N) — path verification |
| Host complexity | flat slice | build tree, compute paths |
| Commitment in `ComplianceInstance` | `hash_kind_table_entries(all)` | Merkle root |

For the current table (2 entries) the difference is negligible. The benefit becomes meaningful beyond ~32 entries.

## Changes required

1. **`arm_core`**: replace `kind_table: Vec<KindTableEntry>` in `ComplianceWitness` with `kind_paths: Vec<Option<MerklePath>>` (one entry per consumed/created resource); replace `kind_table_hash` in `ComplianceInstance` with `kind_table_root: Digest`.
2. **Compliance guest circuit**: replace the linear scan with Merkle path verification.
3. **`arm` host**: add a `KindTable` struct that builds the tree from entries and computes per-resource paths; update `init_kind_table_from_file` / `init_kind_table_from_entries` accordingly.
4. **`ComplianceWitness` construction** in tests and benches: pass paths instead of the flat table.
5. **`kind_table_commitment_check`**: verify against the Merkle root instead of the flat hash.

## Open questions

- Hash function for the Merkle tree: SHA-256 (already used elsewhere in the circuit) or Poseidon for better in-circuit efficiency?
- Leaf encoding: `hash(logic_ref || label_ref || kind_point)` or a structured encoding?
- Tree construction: binary tree over sorted leaves (sorted by `logic_ref`) to keep host-side path computation deterministic.
