# mneme-core Interface Contract (§20.3)

**Status:** FROZEN at Wave 0/1  
**Contract version:** `mneme-core-v1.0.0` (`interface::CONTRACT_VERSION`)

## Change policy

Types listed below are normative seams between parallel implementation agents.
**No agent may modify** field layouts, enum variants, domain tags, hashing rules,
or CBOR key assignments without an explicit **interface-change request** approved
by the integration owner.

Implementation details may evolve only inside non-contract modules (`dcbor`,
`domain`, `embedding`, `hlc`, `object` internals).

## Frozen types (`src/interface.rs`)

| Type | Seam | Blueprint |
|------|------|-----------|
| `ObjectId` | Content addressing | §5.5, INV-1 |
| `ObjectRecord`, `MemoryKind`, `PayloadEnc`, `TrustTier`, `HlcWire` | Object model | §5.5 |
| `LogicalKey` | Key index | §5.6 |
| `Hlc`, `NodeId` | Hybrid logical clock | §5.4 |
| `MnemeError` | Typed fail-closed errors | §16, INV-9 |
| `MerkleProof`, `NonMembershipProof` | SMT ↔ dag/root/verify | §5.6 |
| `Receipt`, `Procedure`, `VerificationObject` | index ↔ verify | §9.2, §6.1 |
| `Root`, `RootPreimage`, `ConsistencyProof` | root ↔ verify/crdt/store | §5.7 |
| `Capability`, `Caveat` | cap ↔ store/verify | §12 |
| `SyncMessage` | crdt ↔ mnemed | §11 |
| `Query`, `Draft`, `Entry`, `ObjectRef`, `ForgetTarget`, `ForgetMode` | Store kernel API | §7 |

## Wave 0/1 proof obligations (mneme-core)

| Invariant | Enforcement |
|-----------|-------------|
| INV-1 | `ObjectRecord::compute_id` = `BLAKE3(OBJ ‖ dCBOR(record))` |
| INV-2 | MNEME-dCBOR encoder; `assert_canonical` gate |
| INV-7 | Strict parse; `UnknownField`; float/indefinite rejection |
| INV-9 | Closed `MnemeError` enum (no `Other(String)`) |
| INV-10 | `FixedPointEmbedding` integer distance + commit |
| §3 | `ProcedureMismatch` / `BelowTierPolicy` / `ZkProofInvalid` error text: authenticated `≠` true; procedure-faithfulness `≠` exact-NN / not exact nearest-neighbor / not true nearest neighbors; Phase I `ExactDominance` is top-k over prover-asserted distances, not top-k by true query-to-embedding distance; binding `≠` SNARK |

## Test vectors (Appendix B items 1–2)

Frozen fixtures under `proof/vectors/`:

- `object_id_manifest.json` + `objects/*.cbor` — object→id across all `MemoryKind` values
- `dcbor_manifest.json` + `dcbor/*.cbor` — map key ordering, float rejection, indefinite-length rejection

Integration tests: `crates/mneme-core/tests/appendix_b_vectors.rs`

## Hash domain tags (§5.2)

All tags are ASCII NUL-terminated, frozen at v1. See `domain::DomainTag`.

## MNEME-dCBOR rules (§5.1)

- Definite-length encoding only
- Map keys sorted by bytewise lexicographic order of encoded key bytes
- No floating-point in identity-bearing structures
- Unknown fields rejected at parse time
- Object map keys are unsigned integers `0..=10` (v1 schema)
