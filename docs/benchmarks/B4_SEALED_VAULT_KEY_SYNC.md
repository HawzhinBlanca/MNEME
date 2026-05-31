# B4 — AEAD-sealed vault-key transfer over §11 sync

**Status: IMPLEMENTED.** Closes the one functional gap left by the keyless wire sync (F-G):
same-trust-domain peers now recall each other's entries as **plaintext** after a §11
WebSocket sync, not merely converge over ciphertext.

## Problem

Before B4, `SyncSnapshot` carried the authenticated structure + **ciphertext** object
blobs but deliberately **no vault keys**. Two daemons converged their signed content
roots, but a peer could not *decrypt* the entries it received over the wire — only the
on-disk `merge_from_path` copied vault keys (from the peer's on-disk vault). So
distributed recall returned ciphertext-only; plaintext required out-of-band key custody.

## Design

A snapshot may now carry an **optional, AEAD-sealed** key bundle (`SyncSnapshot.encrypted_keys`,
`#[serde(default)]` — empty = keyless, fully backward-compatible).

- **Channel key** (`KeyPair::vault_channel_key`): `BLAKE3("mneme-vault-sync-channel-v1" ‖ operator_seed)`.
  Peers that share the operator key (same trust domain — e.g. a user's two devices) derive
  the **identical** key. The Ed25519 signing key is never used directly as an encryption
  key; the channel key is a one-way domain-separated derivation.
- **Bundle**: concat of fixed-width `key_id(16) ‖ object_key(32)` records for every payload
  key the sender holds (shredded keys are absent — `vault.get` fails and they are skipped,
  so a forgotten entry's key is never transferred).
- **Seal**: `nonce24 ‖ XChaCha20-Poly1305(channel_key, bundle, aad="mneme-vault-sync-v1")`.
- **Import** (`Store::import_sealed_vault_keys`): on merge, derive the channel key, `open`,
  and `import_key` each record not already held. Runs **after** the merge transaction.

The daemon (`mnemed`) serves `export_sync_snapshot_sealed()` for `MSG_SNAPSHOT`; decode +
merge already round-trip the new field, so no new wire opcode was needed.

## Security properties (verified by tests)

| Property | Mechanism | Test |
|---|---|---|
| Same-operator plaintext recall | shared channel key opens the bundle | `e2e_b4_sealed_snapshot_enables_same_operator_plaintext_recall`, `plaintext_recall_after_websocket_sync` (real WS) |
| A-NET cannot read keys | no operator key ⇒ cannot derive channel key | `e2e_b4_foreign_operator_cannot_open_sealed_keys` |
| Tampered bundle ⇒ no leak | AEAD tag fails `open` ⇒ nothing imported ⇒ recall fails closed; ciphertext still converges | `e2e_b4_tampered_sealed_keys_fail_closed_but_still_converge` |
| Different operator ⇒ no cross-domain leak | different seed ⇒ different channel key ⇒ `open` fails | `e2e_b4_foreign_operator_cannot_open_sealed_keys` |
| No key reuse; derivation is one-way | channel key ≠ signing seed | `vault_channel_key_is_deterministic_domain_separated_and_not_the_seed` |

**Fail-closed everywhere:** short frame, AEAD failure, or a missing key all yield *no
plaintext* (recall returns a typed `MnemeError`); convergence over ciphertext is committed
independently and is never blocked by a bad key bundle.

## Invariants

- **TCB untouched** — all logic lives in `mneme-store` / `mneme-crypto`, not `mneme-verify`.
- **Determinism unaffected** — sealed keys are wire-only; the signed root / receipt /
  semantic digests do not include sync snapshots or channel keys (foundation-gate
  byte-identical ×2).
- **Crypto-shred preserved** — keys remain per-object; shredded keys are not exported.

## Known boundaries (honest scope)

1. **Trust domain = shared operator key.** B4 enables plaintext sync *within* one trust
   domain. Cross-operator (federation) sync still converges ciphertext only — sharing
   decryption keys across distinct operators is intentionally out of scope and would
   require an authenticated key-agreement handshake.
2. **Incremental (manifest+delta) path is keyless.** B4 seals the full-snapshot path; the
   delta path still converges ciphertext. Sealing the delta is a mechanical follow-up.
3. **Distributed forget.** A peer that received a key keeps it after the sender shreds —
   the same property the on-disk `merge_from_path` already had. Forget propagation across
   peers is a separate concern (not a regression).
4. **Key-import durability.** Keys are imported after the merge transaction; a crash in
   between loses only un-imported keys, which the next sync re-supplies (recall fails
   closed until then — no incorrect plaintext).
