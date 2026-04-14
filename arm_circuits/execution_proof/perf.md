# Execution Proof Guest — Performance Report

**Profile:** `profile.pb`
**Profile type:** cycles
**Total cycles:** 1,056,572
**Accounted cycles:** 1,034,990 (97.96%)

---

## Benchmark Results (wall time, Groth16 prover)

### tx_count (1 compliance unit per transaction)

| tx_count | time (median) | 95% CI |
|----------|--------------|--------|
| 1 | 8.520 s | [8.503 s, 8.536 s] |
| 2 | 10.328 s | [10.302 s, 10.351 s] |
| 4 | 15.304 s | [15.281 s, 15.328 s] |
| 8 | 25.526 s | [25.468 s, 25.591 s] |
| 16 | 45.412 s | [45.056 s, 45.693 s] |

### compliance_count (1 transaction, N compliance units)

| compliance_count | time (median) | 95% CI |
|-----------------|--------------|--------|
| 1 | 8.546 s | [8.529 s, 8.564 s] |
| 2 | 9.062 s | [9.046 s, 9.082 s] |
| 4 | 9.678 s | [9.661 s, 9.695 s] |

---

## Top Functions by Self Cycles

| Rank | Function | Flat % | Cum % |
|------|----------|--------|-------|
| 1 | `sys_bigint` | 25.99% | 26.12% |
| 2 | `sys_bigint2_3` | 15.85% | 15.91% |
| 3 | `[PageIn]` | 8.77% | 8.77% |
| 4 | `sys_bigint2_4` | 8.56% | 8.59% |
| 5 | `FieldElement::invert` | 5.65% | 25.04% |
| 6 | `sys_read_words` | 4.62% | 4.65% |
| 7 | `AffinePoint::mul` | 4.30% | 30.99% |
| 8 | `memcpy` | 4.25% | 5.58% |
| 9 | `memcmp` | 2.07% | 2.24% |
| 10 | `Vec<u32>::write_words` | 1.92% | 4.04% |
| 11 | `sys_write` | 1.90% | 2.21% |
| 12 | `[PageOut]` | 1.63% | 1.63% |
| 13 | `keccak::keccak_p` | 1.53% | 1.72% |
| 14 | `sys_sha_buffer` | 1.48% | 2.19% |
| 15 | `Scalar::invert` | 1.39% | 6.80% |
| 16 | `FdWriter::write_words` | 1.39% | 5.57% |
| 17 | `FdReader::read_words` | 0.98% | 5.66% |
| 18 | `VecVisitor::visit_seq` | 0.73% | 7.38% |
| 19 | `FieldElement::sqrt` | 0.63% | 3.03% |
| 20 | `ExpirableBlob::serialize` | 0.54% | 5.96% |

---

## Key Call-Chain Hotspots (by Cumulative Cycles)

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

---

## Optimization Targets

| Priority | Target | Cycle share | Approach |
|----------|--------|-------------|----------|
| **High** | `DeltaProof::verify` / ECDSA (62%) | ~656K | Aggregate delta proofs across all transactions into a single signature; reduces ECDSA verifications from N to 1 |
| **High** | `sys_bigint` + bigint2 syscalls (50% flat) | ~533K | Already using RISC0 accelerator — near floor for secp256k1 ECDSA |
| **Medium** | `DeltaInstance::from_deltas` (9.2% cum) | ~97K | Accumulate delta directly during the CU loop instead of collecting into a `Vec` first |
| **Low** | `FieldElement::invert` (5.6%) | ~60K | Batch-invert independent field elements using Montgomery's trick |
