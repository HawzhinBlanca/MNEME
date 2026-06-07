# MNEME Trusted Computing Base — Manifest

The §17.6 line budget (`TCB_LINE_BUDGET = 500`) governs the **orchestration TCB**:
the `mneme-verify` crate, which is the fail-closed gate every agent read passes
through. But "trust by reading every line" honestly spans more than that crate:
`verify_recall` / `verify_store` call into a handful of trusted functions in
sibling crates that parse untrusted on-disk/wire bytes or perform the underlying
cryptographic checks. This manifest enumerates that **full trusted surface** so a
reviewer knows exactly what must be read to trust a recall, and so the surface
cannot silently grow without being noticed.

## Tier 1 — budgeted orchestration TCB (`mneme-verify/src`, ≤ 500 lines)

| File | Role |
|---|---|
| `lib.rs` | exports + `TCB_LINE_BUDGET` |
| `recall.rs` | `verify_recall`: root → receipt↔root binding → membership → object re-hash → provenance → writer/tier → tombstone |
| `semantic.rs` | `verify_semantic_recall` / `verify_semantic_receipt` |
| `root.rs` | `verify_root`: preimage recompute, operator-sig, chain, replay |
| `proof.rs` | `verify_membership_proof`: every auth-path sibling |
| `store.rs` | `verify_store` standalone on-disk gate; `verify_signed_head_only` (NOT a tamper gate, `#[doc(hidden)]`, CLI-forbidden by `adoption_lint`) |

Enforced by: `cargo test -p mneme-verify tcb_budget` (line count) and
`scripts/ci/verify-tcb-guard.sh` (no `unwrap`/`expect`/`panic!`/`unreachable!`/
`todo!`/`unimplemented!`/`anyhow`/numeric `as`-cast/slice-index).

## Tier 2 — trusted functions called from Tier 1 (outside the budget)

These are part of the trusted surface; a recall's integrity depends on them. Each
is fail-closed (returns a typed `MnemeError`, never panics on attacker input).

| Crate · function | Trusted because |
|---|---|
| `mneme-crypto`: Ed25519 verify, AEAD open, vault | root/cap signature verification; payload AEAD |
| `mneme-root`: `verify_root_chain`, `check_replay`, `max_signed_checkpoint`, `verify_checkpoint_chain` | succession + A-REPLAY floor + per-checkpoint signature re-verify |
| `mneme-dag`: `DagIndex::new`, `rebuild_from`, `root` | `verify_store` rebuilds the DAG from on-disk objects and compares its root to `root.dag_head_root` (store.rs) |
| `mneme-smt`: `verify_membership`, `verify_non_membership`, `hash_up`, `membership_leaf_hash` | Merkle path recomputation |
| `mneme-index`: `key_index_load::{load_object_keys, load_key_index_tree}` | parses untrusted on-disk sidecars for `verify_store`; **linted by `verify-tcb-guard.sh`** |
| `mneme-index`: `verify_semantic_receipt_tcb_gate` (→ `verify.rs`, `procedure.rs`, `provenance.rs`, `commit.rs`, `semantic_zk.rs`, `zkann.rs`; calls `verify_ads_vo_membership` / `verify_ads_vo` internally) | semantic receipt TCB gate: ADS VO membership + provenance + procedure replay |
| `mneme-core`: dCBOR `decode_strict`/`from_bytes_strict`, `decode_hex32`, `hash_obj`, domain hashes | canonical decode (bounded alloc) + content addressing |

## Honesty boundary
- The budget bounds the **orchestration** TCB, not the cryptographic primitives or
  the canonical codec, which are audited libraries / Tier-2 trusted functions.
- A change that adds a new Tier-2 dependency from `mneme-verify` must update this
  manifest and, if it parses untrusted bytes, be added to the guard's lint set.
