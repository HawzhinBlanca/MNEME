# MNEME Threat Model

This document outlines the security threats to the MNEME verifiable memory substrate and details how the system's design and invariants mitigate them.

## Scope

The threat model covers the following core components:
1. **Memory Store & Key-Index:** The physical database layout containing the Sparse Merkle Tree (SMT) and content-addressed blobs.
2. **Verifier TCB (`mneme-verify`):** The fail-closed gate that parses receipts, check signatures, and validates retrieval procedures.
3. **Daemon (`mnemed`) & Sync Protocols:** The Unix socket / WebSocket listener that handles store queries and peer synchronization.
4. **Key Vault:** Active key zeroization, sealed operator seeds, and KMS/HSM adapters.

---

## Asset Identification

| Asset | Security Goal | Impact of Compromise |
|---|---|---|
| **Memory Integrity** | Ensure memory entries cannot be altered or fabricated without detection. | High: Agent reasons over false, fabricated memories. |
| **Recall Provenance** | Ensure recalled entries were written by authorized writers and are bound to the requested key. | High: Agent consumes unauthorized or poisoned context. |
| **Cryptographic Keys** | Keep operator seed and KMS decryption keys secret and protected from memory scraping. | Critical: Attacker can sign arbitrary roots or decrypt raw payload blobs. |
| **Forgotten State (GDPR)** | Ensure tombstoned keys are permanently unrecoverable and cannot be resurrected. | High: Privacy violation; resurrection of deleted history. |

---

## Adversary Model

MNEME is designed under the assumption of an **adversarial host operator** (e.g., a cloud provider, database admin, or compromised host daemon).

### 1. The Untrusted Operator (Database Host)
* **Capabilities:** Has read/write access to the host filesystem. Can reorder database writes, truncate files, roll back the directory state to an older checkpoint, or flip bits in raw blobs.
* **Goal:** Feed the verifier old, modified, or out-of-order memory states to manipulate agent behavior.

### 2. The Malicious Peer (Network Sync)
* **Capabilities:** Synchronizes state over WebSockets or Unix sockets. Can send clock-regressed signed checkpoints, tampered MST trees, or unauthorized objects.
* **Goal:** Poison the database or desynchronize replicas.

### 3. The Compromised Client (Leaked Capabilities)
* **Capabilities:** Possesses scoped write capabilities.
* **Goal:** Exceed capability scopes (e.g., promote quarantine tier, write to foreign namespaces, or overwrite historical entries).

---

## Threat Matrix & Mitigations

### 1. Replay & State Rollback (A-REPLAY)
* **Threat:** The operator rolls back the root file `meta/HEAD` to an older sequence number, resurrecting a previously deleted (forgotten) entry or reverting a memory update.
* **Mitigation:** 
  * **INV-6:** During cold open, the store reads all checkpoints in `roots/` and rejects if any signed checkpoint on disk carries a sequence number higher than the current `HEAD`.
  * **HLC High-Water Mark:** The signed root carries a monotonic HLC timestamp (`hlc_max`). The verifier rejects any root whose sequence increases but whose HLC regresses (`RootReplayed`).

### 2. Retrieval Poisoning & Namespace Collision
* **Threat:** An attacker inserts a fake entry for `logical_key = ("sales", "forecast")` by placing it in the database and returning it during recall, hoping the agent will read it.
* **Mitigation:**
  * **Receipt-Root Binding:** The verifier recomputes the hash of the requested `logical_key` and asserts that it matches `receipt.logical_key`. It then verifies that `receipt.key_index_root` is identical to `root.key_index_root`.
  * **SMT Membership Verification:** The verifier re-calculates the Merkle membership path from the returned entry's object ID to the signed root. If any bit of the key, value, or auth path is altered, membership verification fails and the read fails closed.

### 3. Durability & Mid-Write Corruption (Orphan Blobs)
* **Threat:** The operator crashes the system mid-transaction, leaving the SMT in an inconsistent state or leaving partially written object blobs.
* **Mitigation:**
  * **`.incomplete` Sentinel:** Before modifying any database metadata, the store writes an `.incomplete` sentinel file to disk and `fsync`s the parent directory. During boot, if `.incomplete` is found, the store rolls back or fails open checks, preventing corrupt states from being exposed.

### 4. Cryptographic Key Scraping & Core Dumps
* **Threat:**decryption keys (DEKs) or KMS master keys linger in RAM and are extracted via a core dump or memory scraping.
* **Mitigation:**
  * **Zeroization on Drop:** `FileKeyVault` and `EnvelopeKeyVault` implement custom `Drop` traits that explicitly overwrite active keys in memory with zeros (`zeroize()`) when the store is dropped or closed.

### 5. Silent TCB Fail-Open (Orchestration Bypass)
* **Threat:** A bug in the verifier's error handling results in a `Result::Ok` when verification encounters a malformed signature or missing proof.
* **Mitigation:**
  * **Budgeted Orchestration:** The verifier TCB is restricted to `TCB_LINE_BUDGET = 500` lines, ensuring it can be completely audited by a human.
  * **Strict Linting:** Automated pre-flight checks (`verify-tcb-guard.sh`) reject compilation if the TCB contains unsafe code, unwraps, expects, panics, or unhandled numeric casts.
