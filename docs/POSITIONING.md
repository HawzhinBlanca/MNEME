# MNEME Positioning & Taxonomy

This document outlines where MNEME fits in the taxonomy of database engines, AI RAG systems, and cryptographic verification frameworks, defining its core boundaries.

---

## 1. Verifiable Memory vs. Semantic Truth Oracle

MNEME is a **verifiable memory substrate**, not a truth oracle.

```
       [ Client Query ] 
              │
              ▼
   ┌──────────────────────┐
   │ Verifier TCB Gate    │ ◄─── Proves: Authorization, Provenance, Integrity
   └──────────────────────┘
              │
              ▼
    (Recall Verified Entry)  ◄─── Does NOT prove: Semantic Truth (Factuality)
```

* **What MNEME Proves:**
  * **Integrity:** The recalled memory byte-for-byte matches what was written.
  * **Provenance:** The memory was authored by a specific public key (writer).
  * **Authorization:** The writer possessed a valid capability token at the time of writing.
  * **Temporal Validity:** The memory was valid at the specified bi-temporal coordinates.
  * **Absence (Forgetting):** If an entry was shredded (forgotten), the prover cannot selectively resurrect it.
* **What MNEME Does NOT Prove:**
  * **Semantic Truth:** If an authorized writer signs a false statement (e.g., "The sky is green"), MNEME will verify it. The signature proves *who* said it and that it was *unaltered*, not that the statement is factually correct.

---

## 2. Procedure-Faithfulness vs. Nearest-Neighbor Optimality

In vector search and Retrieval-Augmented Generation (RAG), verifying the correctness of nearest-neighbor (k-NN) queries is computationally intensive. MNEME divides this problem into distinct scopes:

* **Procedure-Faithfulness (Phase I):**
  * The verifier checks that the prover followed the HNSW traversal sequence or flat-file scan correctly.
  * It checks that the distance scores returned match the prover-asserted distance metrics for the returned candidate set.
* **Nearest-Neighbor Optimality (Phase IV):**
  * Proving that the returned top-k are the *absolute closest* items in the entire database (with no closer items missed) requires a global succinct non-membership/optimality proof (e.g. ZK-SNARK over the HNSW graph).
  * In Phase I, true nearest-neighbor optimality is **not** proven. An adversarial operator could hide a closer entry, which verifies successfully as long as the returned subset itself is internally consistent. This is a load-bearing limit documented in our §3 Honesty Boundary.

---

## 3. Software Verifier vs. Hardware TEE

The verification pipeline has two distinct isolation boundaries:

* **Software Verifier (In-Repo):**
  * Runs as a lightweight library (`mneme-verify`) inside the agent client process.
  * Relies on standard cryptographic signatures (Ed25519) and hash paths (BLAKE3).
  * Governed by a strict `TCB_LINE_BUDGET = 500` lines so it remains completely auditable.
* **Hardware TEE Enclave (Phase II):**
  * Executes the verifier and prompt-assembly logic inside a hardware-isolated environment (such as NVIDIA Confidential Computing or AMD SEV/Intel SGX).
  * Binds the model's output to the attested context.
  * The software verifier is a prerequisite: it establishes the mathematical correctness of the receipt before hardware enclaves seal the execution context.
