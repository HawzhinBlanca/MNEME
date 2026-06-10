# Trick #1 — Beacon Spot-Check Retrieval (research prototype)

**Status:** Prototype / research memo. Wire extension + `verify-cert --audit` in flight;
this document is the honest design contract. **Not** a per-call zero-knowledge proof.

**Date:** 2026-06-11.

**Related:** [`VISION_PROOF_CARRYING_COGNITION.md`](../VISION_PROOF_CARRYING_COGNITION.md)
(Cognition Transparency Log north star), [`PHASE_IV_A_PIOP_SPIKE.md`](PHASE_IV_A_PIOP_SPIKE.md)
(global exact-NN PIOP deferral), [`SEMANTIC_VO_DISTANCE_RECOMPUTE_VNEXT.md`](SEMANTIC_VO_DISTANCE_RECOMPUTE_VNEXT.md)
(distance-recompute v-next).

---

## 1. Problem (the weakness we already admit)

Phase I semantic verification proves **procedure-faithful** retrieval over an
authenticated candidate set — not true global nearest neighbors. The standing
honesty boundary (`mneme_verify::HONESTY_PROCEDURE`, blueprint §3) says so
explicitly; see also `docs/redteam/PHASE_I_ZKANN_DISTANCE_UNBOUND.md`.

Phase IV-A PIOP research targets **succinct global exact-NN** — expensive,
unshipped, TCB-budget constrained. Trick #1 is the **cheap complement**: do not
prove every recall; make cheating **detectable with public randomness** on a
lottery-selected subset.

---

## 2. Trick #1 — probabilistically-checkable retrieval

**Idea (interactive-proof / casino-audit pattern):**

1. At recall time, the operator commits the usual semantic receipt (candidate set,
   Merkle paths, dominance proof) **before** the audit randomness is known.
2. An optional **`audit_beacon`** extension binds a **public, unpredictable**
   randomness value into the Cognition Certificate (published *after* the prover
   could have chosen candidates — drand round or NIST beacon pulse).
3. Any verifier derives a deterministic **audit selector** from the beacon +
   recall identifiers. On **selected** calls, the verifier recomputes true top-k
   over the committed embedding set (full scan or exact dominance replay with
   carried embeddings). On **non-selected** calls, ordinary certificate
   verification suffices.

**Detection economics:** if each audited call has independent detection
probability `p` when the operator lied about top-k, then over `N` independent
recalls the probability of never being caught is `(1 − p)^N`. This is
**statistical deterrence**, not a SNARK — cheap, honest, and aligned with CT /
double-entry / Certificate Transparency (detectable lying, not oracle truth).

**Honest upgrade string (additive, does not replace §3):**

> Beacon spot-check upgrades **audited calls only** to lottery-enforced exact-NN
> over the committed embedding set. Non-audited calls remain procedure-faithful
> only. This is not per-call zero-knowledge and does not prove semantic truth.

---

## 3. Public randomness sources

### drand (default prototype)

- **API:** drand v2 public endpoints (`https://api.drand.sh/v2/beacons/...`).
- **Output:** threshold BLS signature per round; unpredictable to the prover at
  commit time if round is chosen **after** receipt assembly (round `R` fixed only
  once drand has published round `R`).
- **Offline path:** ship `(chain_hash, round, signature_bytes)` in the cert;
  verifier checks BLS against drand chain info fetched out-of-band or embedded
  in a transparency bundle. Hash the signature into 32 bytes for selector input:
  `randomness = BLAKE3("MNEME-AUDIT-BEACON/v1" ‖ sig_bytes)`.

### NIST Randomness Beacon (alternate)

- **Source:** NIST Beacon Program pulses (512-bit output + signature).
- **Offline path:** same pattern — carry pulse index + signed output; hash into
  `randomness` with domain tag `MNEME-AUDIT-BEACON/v1`.

Neither source proves memory **true**; both anchor **unpredictable audit selection**
that the operator cannot grind before committing the receipt.

---

## 4. Wire extension (`audit_beacon`)

Additive Cognition Certificate field — **does not mutate** frozen
`mneme-core` interface types. Extension map on the cert outer body:

| Cert version | Field key | Name |
|---|---:|---|
| v1 | `6` | `audit_beacon` |
| v2 draft | `7` | `audit_beacon` (field `6` remains context attestation) |

`audit_beacon` value: dCBOR map:

| Key | Type | Semantics |
|---:|---|---|
| `0` | text | `source`: `"drand"` or `"nist"` |
| `1` | unsigned | `round`: drand round or NIST pulse index |
| `2` | bytes (32) | `randomness`: BLAKE3 digest of beacon output (domain-separated) |

Binding: the beacon tuple is included in the certificate commitment domain
(`MNEME-COGNITION-CERT/v1` extension tag) so tampering after publication fails
closed.

Fixture pin: `proof/vectors/certs/manifest.json` entry `beacon_spot_check`.

---

## 5. Audit selector algorithm

Deterministic, documented for `mneme verify-cert --audit` and crossref:

```
input = BLAKE3(
  "MNEME-AUDIT-SELECT/v1"
  ‖ randomness (32)
  ‖ query_commit (32)
  ‖ semantic_commit (32)
)
selected := (LE_u64(input[0..8]) mod AUDIT_RATE_DENOM) == 0
```

Default `AUDIT_RATE_DENOM = 256` (~1/256 recalls fully audited). Tunable policy,
not consensus-critical in v0 prototype.

**If selected:** verifier loads embeddings for the committed candidate universe
(store sidecar or v-next VO rows), recomputes integer distances, checks returned
`result_ids` are true top-k. Fail closed on mismatch.

**If not selected:** run standard `verify_cognition_certificate_v1` (signature,
root binding, ADS / zkANN dominance) without full NN recompute.

---

## 6. Honest limits (binding)

| Claim | Status |
|---|---|
| Per-call exact-NN proof | **No** — only on beacon-selected audits |
| Zero-knowledge | **No** — public beacon + statistical sampling |
| Semantic truth | **No** — authenticated ≠ true (§3.1 unchanged) |
| Grinds beacon before commit | **Mitigated** by round-after-commit discipline |
| Operator skips beacon | Allowed — falls back to Phase I honesty only |

This is a **soundness amplifier**, not a replacement for PIOP/FRI or
distance-recompute v-next.

---

## 7. Path to Cognition Transparency Log

Trick #1 is the **retrieval-audit seed** for the transparency-log composition
described in the founder memo:

```
append-only signed checkpoint log  (mneme-root — shipped)
  + beacon-spot-checkable retrieval  (Trick #1 — prototype)
  + homomorphic context-set lock     (Trick #2 — Pedersen/Schnorr shipped)
  + forget-absence across log        (Trick #3 — research)
  + Byzantine inference consistency  (Trick #4 — research)
```

Each certificate entry becomes a **CT-style log element**: publicly gossipable,
offline-verifiable against the `<500`-line TCB, retroactively falsifiable if the
operator lied on an audited draw. See
[`VISION_PROOF_CARRYING_COGNITION.md`](../VISION_PROOF_CARRYING_COGNITION.md) §0–§2
for the PCC / EU AI Act / NIST framing.

---

## 8. Implementation map (this repo)

| Component | Owner | Status |
|---|---|---|
| `audit_beacon` wire + domain bind | `mneme-index` `cognition_cert.rs` | prototype branch |
| `verify-cert --audit` | `mneme-cli` `cert.rs` | prototype branch |
| Appendix B fixture | `proof/vectors/certs/` | manifest pinned |
| Independent decode sketch | `mneme-crossref` `wire_beacon.rs` | stub / doc |
| TCB `verify_recall` | unchanged | no beacon in TCB v0 |

---

## 9. References

- drand documentation: <https://drand.love/docs/>
- NIST Randomness Beacon: <https://beacon.nist.gov/home>
- Certificate Transparency model: RFC 9162 (detectability, not truth)
- Phase I task spec P1-4: Cognition Certificate v1
- Crossref notes: `docs/phase-program/PHASE_IV_CROSSREF_NOTES.md` §6
