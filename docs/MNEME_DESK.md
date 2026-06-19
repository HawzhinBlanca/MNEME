# MNEME Desk — Phase Y0 runbook

The smallest **real, runnable** verifiable-memory app on the shipped substrate. It is
the local-first console (`ui/`) talking to the `mnemed` daemon through a same-origin dev
host that holds the operator capability server-side. No new trusted code: the daemon
remains the sole authority and re-verifies every capability and receipt.

> Honest scope: this is Phase Y0 of [PROVENANCE_BLUEPRINT.md](PROVENANCE_BLUEPRINT.md).
> It proves **verifiable recall + provable, reversible forgetting** end to end. It is
> **not** the self-improving cognition program (L1–L6) — that is a multi-year frontier.
> `authenticated ≠ true`.

## Trust boundary

```
browser (untrusted)
   │  same-origin http, NO capability in the page
   ▼
ui/serve.mjs  (untrusted glue — holds the cap, injects Authorization: Bearer)
   │  127.0.0.1 only
   ▼
mnemed daemon (authority) ── recall_verified · forget_with_proof · signed root
   │
   ▼
Store kernel + 464-line verifier TCB
```

The proxy carries bytes; it proves nothing. A compromised page can only drive the
actions the cap already allows — it cannot read the cap, and the daemon re-verifies
everything. Bind everything to loopback.

## Launch

```bash
# 0. one-time: operator custody (a 32-byte hex master key in your shell/keychain)
export MNEME_KMS_MASTER_KEY_HEX=<64 hex chars>

# 1. create a store (persists the operator under the master key)
mneme init ./my-store

# 2. mint a least-privilege capability for the app (browser never sees this file)
mneme cap mint ./my-store --read --write --namespace '*' --tier-max trusted --out ./cap.txt
mneme cap inspect ./cap.txt          # confirm the scope before trusting it

# 3. start the daemon (loopback only)
mnemed --store ./my-store --http 127.0.0.1:7845 &

# 4. start the same-origin host (injects the cap server-side)
MNEME_CAP_FILE=./cap.txt MNEME_DAEMON=http://127.0.0.1:7845 node ui/serve.mjs

# 5. open http://127.0.0.1:8765
```

Override ports with `MNEME_UI_PORT` / `--http`. Pass the cap inline with `MNEME_CAP=…`
instead of a file if you prefer.

## What you can verify yourself

```bash
# fail-closed: the daemon rejects an unauthenticated read
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7845/v1/head        # => 401

# through the proxy the cap is injected, so the same call succeeds
curl http://127.0.0.1:8765/v1/head                                          # => 200 + signed root

# forget with a receipt you can hold, then verify it offline
curl -X DELETE 'http://127.0.0.1:8765/v1/forget-proof/notes/hello'          # => ForgetProof (CBOR b64)
```

The forget proof is an SMT non-membership proof bound to a fresh signed Ed25519 root: a
third party checks, offline, that the key is absent from the committed index after the
deletion — the one thing no RAG/vector-DB stack can show.

## Verify the whole stack

```bash
scripts/ci/desk-live-e2e.sh    # boots cap-mint -> mnemed -> ui/serve.mjs and asserts the chain
```

It proves, against the real binaries, every load-bearing claim: same-origin serve,
fail-closed auth (401), cap-injected recall, remember → verified recall, a root-bound
ForgetProof, **fail-closed deletion** (recall returns 410 Gone, `prove-absent` confirms
absence under the signed root), and **least-privilege** (a read-only cap is denied
forget, 403). Any mismatch aborts non-zero.

## Security checklist (do not skip)

- The cap file is a bearer credential. Treat it like an SSH key; never commit it, never
  paste it into a web page. Prefer a short `--tier-max` and a narrow `--namespace`.
- Keep `mnemed` and `ui/serve.mjs` on `127.0.0.1`. The daemon refuses a non-loopback
  HTTP bind without TLS; do not work around that.
- `mneme cap mint` defaults to least privilege (each permission must be granted
  explicitly; namespace defaults to `tools`). Grant `--promote`/`--forget` only when
  the app needs them.
