# The Price of Verifiable Cognition (Pillar B)

**Status:** theory artifact B1.
**Honesty boundary:** Authenticated ≠ true.

## 3. Imported floors (corrected attribution)

**Theorem (Dwork–Naor–Rothblum–Vaikuntanathan, TCC 2009).** Deterministic non-adaptive online memory checking requires **Ω(log n / log log n)** query overhead.

A fully general computational floor matching Merkle's `O(log n)` upper bound is **OPEN**.

MNEME SMT recall uses **256** probes (`O(log n)`). Position vs floor: **up to an `O(log log n)` factor**. Claiming an exact floor match is an overclaim.

**ExactDominance** verification is **Θ(n)** in committed candidate count under the **transparent non-succinct** model.

In the **non-aggregating epoch model**, non-use costs **Ω(N)**.

## 5. CI floor audit

`scripts/ci/validation-lane.sh bounds` runs `cognition_floor_audit`, `recall_floor`, `exact_dominance_floor`.

## 6. Honesty strings

- Ω(log n / log log n) — Dwork–Naor–Rothblum–Vaikuntanathan TCC'09, deterministic non-adaptive
- MNEME matches floor up to O(log log n); exact match OPEN
- Authenticated ≠ true
