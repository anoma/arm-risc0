# Execution Proof Guest — Performance Report

---

## Benchmark Results (wall time, Groth16 prover)

- **with delta** — delta proof verified inside the zkVM via ECDSA recovery
- **without delta** — delta proof bytes passed through to the journal; ECDSA verification is skipped in the circuit and delegated to an external verifier

### tx_count (1 compliance unit per transaction)

| tx_count | with delta (median) | without delta (median) | Δ |
|----------|--------------------|-----------------------|---|
| 1 | 8.520 s | 6.759 s | **−20.7%** |
| 2 | 10.328 s | 7.193 s | **−30.4%** |
| 4 | 15.304 s | 8.442 s | **−44.8%** |
| 8 | 25.526 s | 11.751 s | **−54.0%** |
| 16 | 45.412 s | 18.498 s | **−59.3%** |

### compliance_count (1 transaction, N compliance units)

| compliance_count | with delta (median) | without delta (median) | Δ |
|-----------------|--------------------|-----------------------|---|
| 1 | 8.546 s | 6.811 s | **−20.3%** |
| 2 | 9.062 s | 6.806 s | **−24.9%** |
| 4 | 9.678 s | 7.318 s | **−24.4%** |

---

## Cycle Profile

Two profiles are tracked:

- **`profile.pb`** — baseline: delta proof verified inside the zkVM (ECDSA recovery + point check)
- **`profile_without_delta.pb`** — delta proof passed through to the journal; external verifier checks the signature

| | `profile.pb` | `profile_without_delta.pb` |
|--|-------------|---------------------------|
| **Total cycles** | 1,056,572 | **285,165** (−**73.0%**) |
| **Accounted cycles** | 1,034,990 (97.96%) | 283,672 (99.48%) |

---

## `profile.pb` — Top Functions by Self Cycles

| Rank | Function | Flat cycles | Flat % | Cum % |
|------|----------|------------|--------|-------|
| 1 | `sys_bigint` | 274,647 | 25.99% | 26.12% |
| 2 | `sys_bigint2_3` | 167,444 | 15.85% | 15.91% |
| 3 | `[PageIn]` | 92,650 | 8.77% | 8.77% |
| 4 | `sys_bigint2_4` | 90,447 | 8.56% | 8.59% |
| 5 | `FieldElement::invert` | 59,670 | 5.65% | 25.04% |
| 6 | `sys_read_words` | 48,776 | 4.62% | 4.65% |
| 7 | `AffinePoint::mul` | 45,388 | 4.30% | 30.99% |
| 8 | `memcpy` | 44,915 | 4.25% | 5.58% |
| 9 | `memcmp` | 21,853 | 2.07% | 2.24% |
| 10 | `Vec<u32>::write_words` | 20,249 | 1.92% | 4.04% |
| 11 | `sys_write` | 20,064 | 1.90% | 2.21% |
| 12 | `[PageOut]` | 17,201 | 1.63% | 1.63% |
| 13 | `keccak::keccak_p` | 16,160 | 1.53% | 1.72% |
| 14 | `sys_sha_buffer` | 15,630 | 1.48% | 2.19% |
| 15 | `Scalar::invert` | 14,738 | 1.39% | 6.80% |
| 16 | `FdWriter::write_words` | 14,670 | 1.39% | 5.57% |
| 17 | `FdReader::read_words` | 10,318 | 0.98% | 5.66% |
| 18 | `VecVisitor::visit_seq` | 7,693 | 0.73% | 7.38% |
| 19 | `FieldElement::sqrt` | 6,623 | 0.63% | 3.03% |
| 20 | `ExpirableBlob::serialize` | 5,704 | 0.54% | 5.96% |

## `profile.pb` — Key Call-Chain Hotspots

| Call Chain | Cum Cycles | Cum % |
|------------|-----------|-------|
| `execution_proof_guest::main` | 1,036,034 | 98.06% |
| `DeltaProof::verify` | 655,789 | **62.07%** |
| `ecdsa::recover_from_digest` | 653,539 | 61.85% |
| `k256::mul::lincomb` | 450,931 | 42.68% |
| `AffinePoint::mul` | 327,425 | 30.99% |
| `ecdsa::hazmat::verify_prehashed` | 287,496 | 27.21% |
| `ProjectivePoint::to_affine` | 208,716 | 19.75% |
| `DeltaInstance::from_deltas` | 97,169 | 9.20% |
| `deserialize_struct` (serde) | 87,142 | 8.25% |
| `InsertionWitness::apply` | 28,201 | 2.67% |

## `profile.pb` — Analysis

The circuit is dominated by **ECDSA** (`DeltaProof::verify` at 62.07% cumulative):

| Category | Cycles | Share |
|----------|--------|-------|
| ECDSA / delta proof (`sys_bigint`, `sys_bigint2_3/4`, `FieldElement::invert`, `AffinePoint::mul`) | ~580K | ~55% flat |
| Delta instance (`DeltaInstance::from_deltas`) | ~97K | ~9% cum |
| Memory paging (`[PageIn]`, `[PageOut]`) | ~110K | ~10% |
| Serde I/O (read + write path) | ~100K | ~9% |
| Tree ops (`InsertionWitness::apply`) | ~28K | ~3% |

The ECDSA cost is near-floor for secp256k1 on RISC0 — `sys_bigint` and `sys_bigint2_3/4` are already hardware-accelerated syscalls. The only way to materially reduce this is to eliminate the verification from the circuit entirely (as done in `profile_without_delta.pb`) or to aggregate multiple delta proofs into a single signature.

---

## `profile_without_delta.pb` — Top Functions by Self Cycles

| Rank | Function | Flat cycles | Flat % | Cum % |
|------|----------|------------|--------|-------|
| 1 | `sys_read_words` | 48,776 | 17.10% | 17.10% |
| 2 | `[PageIn]` | 42,860 | 15.03% | 32.13% |
| 3 | `memcpy` | 34,350 | 12.05% | 44.18% |
| 4 | `sys_write` | 24,420 | 8.56% | 52.74% |
| 5 | `Vec<u32>::write_words` | 20,249 | 7.10% | 59.84% |
| 6 | `FdWriter::write_words` | 17,852 | 6.26% | 66.10% |
| 7 | `sys_sha_buffer` | 16,086 | 5.64% | 71.75% |
| 8 | `[PageOut]` | 10,339 | 3.63% | 75.37% |
| 9 | `FdReader::read_words` | 10,318 | 3.62% | 78.99% |
| 10 | `VecVisitor::visit_seq` | 7,693 | 2.70% | 81.69% |
| 11 | `ExpirableBlob::serialize` | 5,704 | 2.00% | 83.69% |
| 12 | `sha::copy_and_update` | 5,264 | 1.85% | 85.53% |
| 13 | `to_vec` (serde) | 4,089 | 1.43% | 88.66% |
| 14 | `deserialize_tuple` | 3,212 | 1.13% | 91.13% |
| 15 | `deserialize_struct` | 3,138 | 1.10% | 93.33% |
| 16 | `InsertionWitness::apply` | 615 | 0.22% | 98.33% |

---

## `profile_without_delta.pb` — Key Call-Chain Hotspots

| Call Chain | Cum Cycles | Cum % |
|------------|-----------|-------|
| `execution_proof_guest::main` | 269,746 | 94.59% |
| `ExecutionProofInstance::serialize` | 63,914 | **22.41%** |
| `TxInfo::serialize` | 55,373 | 19.42% |
| `AppData::serialize` | 55,274 | 19.38% |
| `deserialize_struct` (serde) | 88,394 | 31.00% |
| `VecVisitor::visit_seq` | 78,310 | 27.46% |
| `InsertionWitness::apply` | 28,832 | 10.11% |
| `to_vec` (serde) | 29,675 | 10.41% |
| `env::verify` | 14,235 | 4.99% |

---

## Analysis

Without ECDSA, the circuit is dominated by **serde I/O**:

| Category | Cycles | Share |
|----------|--------|-------|
| Read path (`sys_read_words`, `FdReader`, `VecVisitor`) | ~66,787 | ~23% |
| Write path (`sys_write`, `Vec::write_words`, `FdWriter`, `ExpirableBlob::serialize`, `AppData::serialize`) | ~123,478 | ~43% |
| Memory paging (`[PageIn]`, `[PageOut]`) | ~53,199 | ~19% |
| Tree ops (`InsertionWitness::apply`, `IncrementalMerkleTree::insert`) | ~31,016 | ~11% |

The write path is now the single largest cost at ~43%, driven almost entirely by `AppData` / `ExpirableBlob` serialisation in `env::commit`. The `TxInfo::serialize` cumulative (19.42%) and `AppData::serialize` cumulative (19.38%) confirm these are essentially the same call chain.

---

## Optimization Targets (without-delta baseline)

| Priority | Target | Cycle share | Approach |
|----------|--------|-------------|----------|
| **High** | Write path — `AppData`/`ExpirableBlob` in `env::commit` (43%) | ~123K | Avoid re-serialising `AppData` in the journal; store pre-serialised words on the input side so the guest passes them through without deserialization |
| **High** | Memory paging `[PageIn]`/`[PageOut]` (19%) | ~53K | Reduce working-set size; struct field reordering already applied — further gains require shrinking `AppData` blob payloads |
| **Medium** | Read path — `sys_read_words`, `VecVisitor` (23%) | ~67K | Pre-serialise `AppData` on the host side so the guest reads a flat `Vec<u32>` instead of deserialising nested structs |
| **Low** | `InsertionWitness::apply` (10% cum) | ~29K | Cost is inherent to the indexed Merkle tree depth; no algorithmic improvement available |
