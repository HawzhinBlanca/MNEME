# Finding (Phase II core invariant) — Context Gate does NOT enforce "nothing injected"

**Severity: HIGH for the Phase II claim (currently scaffold — `PHASE_II_GATE_OPEN = false`, gate
closed, so not a live production exploit).** Date 2026-06-04.

## The claim (VISION / ROADMAP Phase II)

> The enclave emits a Context-Consumption Attestation binding `H(assembled_context)` to the
> certified memory set, so *a verifier, offline, can check the model was fed **precisely** the
> certified context (and nothing injected out-of-band)*.

## What the software slice actually enforces

`mneme_gate::verify_consumption_attestation(attestation, assembled_context, certified_memory_set_payload, profile)`:

1. `attestation.assembly_profile == profile`
2. `attestation.context_hash == hash_context_assembled(assembled_context)`
3. `attestation.certified_memory_set_hash == hash_certified_memory_set(certified_memory_set_payload)`

With:
- `certified_memory_set_payload = count ‖ (object_id ‖ object_id)*` — **ids only** (content_commit == id).
- `assembled_context = "MNEME-CTX-ASM-v1\n" ‖ (object_id ‖ plaintext)*` — ids **and plaintexts**.

**Nothing cross-binds the two.** The gate recomputes each digest from its *own* input bytes and
compares to the CCA. It never checks that the plaintexts in `assembled_context` are the contents of
the certified ids, nor even that the id lists match.

## The injection (passes the gate today)

- `certified_memory_set_payload` = legit (from the verified recall ids).
- `assembled_context` = `magic ‖ (legit_id ‖ INJECTED_PLAINTEXT)*` — attacker-chosen prompt body.
- `attestation.context_hash` = `hash(assembled_context_with_injection)`; `certified_memory_set_hash`
  = `hash(legit certified payload)`.
- Gate: digest (2) matches the injected bytes ✓, digest (3) matches the legit payload ✓ → **Ok**.

So an offline verifier given `(CCA, assembled_context, certified_payload)` **cannot detect that the
prompt body was swapped** — exactly the "nothing injected" property the gate is supposed to prove.
The only test (`consumption_attestation_accepts_matching_hashes`, `phase_ii_*_roundtrip`) is
happy-path; there is **no injection-rejection test**.

Why it's not a live exploit *yet*: `PHASE_II_GATE_OPEN = false`, the enclave-report verifier always
returns `Err`, and the honest store assembles inside `assemble_verified_context` (which DOES
re-hash entries). The gap is that the **gate itself — the offline trust boundary — does not enforce
the binding**, so the moment it's relied on standalone (the whole Phase II promise), it fails open.

## Root cause

`assemble_verified_context` authenticates entries (`record.compute_id() == id`) and derives both
digests from the same set — sound on the *prover* side. But the *verifier* (`verify_consumption_attestation`)
receives raw bytes and only checks digest self-consistency. The certified-set preimage commits to
ids, not to the assembled prompt, so the verifier has nothing to cross-check the prompt body against.

## Correct fix (software-only, makes the offline check real)

The gate must prove `assembled_context` is the **deterministic assembly of the certified set** —
re-derive and compare, not trust the bytes:

- Carry the certified `(object_id, plaintext)` pairs (or the full verified `Entry` set) to the gate,
  re-run `encode_assembled_prompt_v1` over them, and require `hash == attestation.context_hash`.
  Plaintext↔id is itself authenticated because `object_id == hash_obj(record)` and the record body
  *is* the plaintext — so the gate (or its caller, inside the TCB boundary) must also check each
  `hash_obj(record) == id`. Equivalent to: the certified-set preimage must commit to the assembled
  prompt, so the two digests are *derivable from one source*, not independent.
- Then `H(assembled) ` is provably a function of the certified set → injection changes the
  re-derived hash → fail closed.

## Required tests (before Phase II can claim the invariant)

- **Adversarial:** `assembled_context` with an injected/swapped plaintext but a legit
  `certified_memory_set_payload` must be **rejected** (today: accepted). This is the missing
  regression test that proves "nothing injected."
- Wrong-order / extra-entry / dropped-entry assembled contexts must be rejected.
- Keep the happy-path roundtrip green.

## Honest status / recommendation

Phase II is **scaffold** (gate closed) and labeled as such — so this is not a production
fail-open today. But it **is** the core Phase II invariant, and it is currently *unenforced and
untested*. Phase II must not be called "software-complete with the no-injection guarantee" until the
gate re-derives the assembled context from the certified set and the adversarial injection test
fails closed. (The remaining Phase II item — real GPU-TEE remote attestation — is separately
external-gated.)
