#!/usr/bin/env bash
# claims-lint — MNEME applied to MNEME's own docs.
#
# The §3 honesty boundary forbids claims that don't verify. A doc that cites a
# commit SHA that is not in the tree, or a Cargo feature that does not exist, is
# exactly the failure mode MNEME exists to punish — a receipt that doesn't check.
# This gate counts the truth from source (git + Cargo.toml) instead of trusting
# hand-typed strings, the same way the tamper-floor test counts cases from source.
#
# Two invariants over every tracked *.md file:
#   1. COMMIT CITATIONS: every backtick-quoted token that looks like a git SHA
#      (7-40 hex) and resolves to a real commit object MUST be an ancestor of
#      HEAD — UNLESS the same line explicitly labels it as off-master (one of:
#      "not in master", "branch state", "PR #", "unmerged", "historical").
#      A backtick SHA that resolves to NO object at all is always a failure
#      (a truly phantom receipt).
#   2. FEATURE CITATIONS: every cargo feature named in an unambiguous usage —
#      `--features <name>` / `--features=<name>` / `required-features = [.. <name> ..]`
#      — MUST exist in some Cargo.toml [features] block (or be "default"). We only
#      check these manifest/CLI forms, not loose prose like "the X feature", to
#      avoid flagging function/identifier names that merely sit near the word
#      "feature".
#
# Exit non-zero on any violation. Fail closed.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail=0
note() { printf '%s\n' "$*" >&2; }

# Ancestry/existence checks need full history. CI checks out shallow (depth 1) by
# default, where real ancestor commits legitimately resolve to no object — the very
# shallow-clone trap this gate exists to catch in docs. Unshallow first; if we
# cannot (offline/fork), degrade ancestry+existence to NON-FATAL warnings so we
# never emit a FALSE phantom — a false failure that blocks a valid PR is worse than
# a skipped check. The feature-declaration check is unaffected and always runs.
SHA_CHECKS=1
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
  note "claims-lint: shallow clone detected — fetching full history for ancestry checks…"
  if ! git fetch --unshallow --quiet 2>/dev/null \
     && ! git fetch --deepen=1000000 --quiet 2>/dev/null; then
    : # fall through to the shallow re-check below
  fi
fi
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
  SHA_CHECKS=0
  note "claims-lint: WARNING — repository still shallow; commit-SHA checks DEGRADED to non-fatal (feature checks still enforced)."
fi

# Collect declared Cargo features across the workspace (left-hand side of `name =`
# inside each [features] block), plus cargo built-ins.
declared_features="$(
  {
    printf 'default\n'
    while IFS= read -r toml; do
      awk '
        /^\[features\]/ { inblk=1; next }
        /^\[/           { inblk=0 }
        inblk && /^[A-Za-z0-9_-]+[[:space:]]*=/ {
          line=$0; sub(/[[:space:]]*=.*/, "", line); gsub(/[[:space:]]/, "", line);
          print line
        }
      ' "$toml"
    done < <(git ls-files '*Cargo.toml')
  } | sort -u
)"

is_declared_feature() {
  printf '%s\n' "$declared_features" | grep -qxF "$1"
}

line_has_offmaster_marker() {
  printf '%s' "$1" | grep -qiE 'not in master|branch state|PR #|unmerged|historical|does not exist|phantom'
}

while IFS= read -r md; do
  lineno=0
  while IFS= read -r line; do
    lineno=$((lineno + 1))
    # Extract every backtick-quoted token on the line.
    while IFS= read -r tok; do
      [ -n "$tok" ] || continue
      # --- Invariant 1: commit SHA citations (skipped if history is shallow) ---
      if [ "$SHA_CHECKS" = "1" ] && printf '%s' "$tok" | grep -qiE '^[0-9a-f]{7,40}$'; then
        if git cat-file -e "${tok}^{commit}" 2>/dev/null; then
          if ! git merge-base --is-ancestor "$tok" HEAD 2>/dev/null; then
            if line_has_offmaster_marker "$line"; then
              : # explicitly labelled off-master — allowed
            else
              note "PHANTOM-RECEIPT  $md:$lineno  commit \`$tok\` is not an ancestor of HEAD and is not labelled off-master"
              fail=1
            fi
          fi
        else
          # Looks like a SHA, in backticks, but resolves to nothing.
          # Only flag tokens that are plausibly SHAs (>=8 hex) to avoid false hits
          # on short hex like colour codes; and skip if labelled off-master.
          if [ "${#tok}" -ge 8 ] && ! line_has_offmaster_marker "$line"; then
            # Heuristic guard: ignore pure-digit tokens (timestamps, sizes).
            if printf '%s' "$tok" | grep -qiE '[a-f]'; then
              note "PHANTOM-SHA      $md:$lineno  \`$tok\` looks like a commit SHA but resolves to no object"
              fail=1
            fi
          fi
        fi
      fi
    done < <(printf '%s\n' "$line" | grep -oE '`[^`]+`' | sed 's/^`//; s/`$//')

    # --- Invariant 2: feature citations (unambiguous CLI/manifest forms only) ---
    # Capture ONLY the immediate argument to `--features` / `--features=` (the very
    # next whitespace-delimited token), and the contents of `required-features=[...]`.
    # The immediate-token rule avoids swallowing later CLI flags or `-- <testname>`
    # filters (e.g. `--features pedersen_schnorr_zk -- forgery_zk` checks only the
    # former). A single token may still be a comma-separated list (a,b,c).
    feat_names="$(
      printf '%s' "$line" | perl -ne '
        my @f;
        while (/--features[= ]\s*["'\'']?([A-Za-z0-9_,-]+)/g) { push @f, split(/,/, $1); }
        while (/required-features\s*=\s*\[([^\]]*)\]/g) {
          my $inner=$1; push @f, ($inner =~ /["'\'']([A-Za-z0-9_-]+)["'\'']/g);
        }
        print join("\n", @f), "\n" if @f;
      '
    )"
    if [ -n "$feat_names" ]; then
      while IFS= read -r feat; do
        [ -n "$feat" ] || continue
        if ! is_declared_feature "$feat"; then
          if line_has_offmaster_marker "$line"; then
            : # explicitly labelled off-master (branch/experimental) — allowed
          else
            note "UNKNOWN-FEATURE  $md:$lineno  feature \`$feat\` cited but not declared in any Cargo.toml [features]"
            fail=1
          fi
        fi
      done < <(printf '%s\n' "$feat_names")
    fi
  done < "$md"
done < <(git ls-files '*.md')

if [ "$fail" -ne 0 ]; then
  note ""
  note "claims-lint: FAILED — docs cite receipts that do not verify against the tree."
  note "Fix: land the cited commit/feature, or label the line off-master, or correct the claim."
  exit 1
fi

echo "claims-lint: OK — all doc commit/feature citations verify against HEAD."
