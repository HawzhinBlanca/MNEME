# Agent Task — Cross-Host CRDT Convergence Proof (MNEME, Windows/x86_64 peer)

You are an autonomous agent on a **Windows x86_64 machine** (use WSL2/Ubuntu). Cross-host
*determinism* is already proven (`docs/benchmarks/XHOST_DETERMINISM_PROOF.md`). This task proves
the harder, still-open property: **cross-host CRDT convergence** — two independent machines that
ingest object deltas in different orders reconcile, via anti-entropy, to the *same* committed
object set. Unlike the determinism proof, convergence is a genuine **two-peer network exchange**,
so it needs an SSH path between the hosts. RustDesk's relay does not provide one; **Tailscale does**
(a free WireGuard mesh, no router config). Work autonomously; stop only for an interactive
login/credential.

## Prerequisites you must establish
1. **Tailscale on both hosts.** Windows: `winget install tailscale.tailscale` then `tailscale up`
   (a browser login — if interactive, complete it and report the machine's Tailscale IP). Inside
   WSL, Tailscale on the Windows host is reachable; confirm the **Mac peer's Tailscale IP/hostname**
   from the human (e.g. `100.x.y.z` or `macbook.tailnet-name.ts.net`).
2. **SSH from this host → the Mac peer.** Generate a key if needed
   (`ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519`), have the human add the public key to the
   Mac's `~/.ssh/authorized_keys`, and confirm `ssh -o BatchMode=yes <macuser>@<mac-tailscale> true`
   succeeds. (The convergence script SSHes *from* the initiating host *to* `MNEME_SECOND_HOST`; you
   can run it from either side — pick whichever host you can SSH *from*.)
3. **Same commit on both.** Both hosts must have the MNEME repo at the **same git HEAD** (use
   `v0.7.0` / `3fedc80f`, or the current `master` — but identical on both). The script enforces this.

## Run the proof
From the initiating host's repo root, with the peer set:
```
MNEME_SECOND_HOST=<peeruser>@<peer-tailscale-ip> scripts/ci/convergence-two-host.sh
```
This runs the CRDT convergence tests locally, then SSHes to the peer (verifying it is on the same
git HEAD) and runs them there, comparing converged object-set digests across the two machines.
The relevant tests are `mneme-crdt merge_convergence` and `mnemed v11_object_sync two_peers_converge`.

If you cannot establish SSH at all, fall back to the **local-smoke** mode and say so explicitly —
it only proves *same-host* convergence and does **not** satisfy the cross-host claim:
```
scripts/ci/convergence-two-host.sh --local-smoke
```

## Report back (fail-closed, honest)
- Connectivity established: Tailscale IPs of both hosts; the exact `ssh … true` command that
  succeeded (or the precise failure).
- `git rev-parse HEAD` on both hosts (must match).
- The script's output: which tests ran on which host, and whether the cross-host converged
  object-set digests **matched**.
- Verdict: **`CROSS-HOST CONVERGENCE: PROVEN`** only if the real two-host (non-`--local-smoke`)
  run compared converged digests across both machines and they matched; otherwise **`LOCAL-SMOKE
  ONLY`** or **`MISMATCH`**, stated plainly. Do not label a same-host smoke run as a cross-host
  proof.
- Honesty boundary unchanged: convergence proves replicas reconcile to the same authenticated
  object set — not semantic truth of any entry.
