//! `mneme-evolve` — **EXPERIMENTAL**: a verifiable self-play episode harness.
//! Step 1 of the PROVENANCE L1 layer (see `docs/PROVENANCE_BLUEPRINT.md`). It is
//! **outside** the verifier TCB and proves nothing on its own; the store remains
//! the authority.
//!
//! This is the buildable, GPU-free kernel of a self-improving loop: run
//! `propose -> verify-with-a-REAL-reward -> commit`, where every ACCEPTED
//! improvement is written to the signed store as a memory carrying `parent_ids`
//! lineage. The result is a signed, attributable, **reversible** record of the
//! episode — the "proof-carrying autobiography" no current self-evolving agent
//! (Darwin Gödel Machine, Absolute Zero) keeps.
//!
//! ## Honesty boundary (load-bearing — never weaken)
//! - It updates **no** model weights and does **not** make any agent "smarter".
//!   The proposer is a deterministic stand-in for an LLM; swapping in a real LLM
//!   does not change what is proven.
//! - It proves only that the loop **ran faithfully** over a real verifiable
//!   reward, that the accepted skill set is **signed + attributable** (lineage)
//!   and **reversible** with a ForgetProof. It does **not** prove the improvement
//!   is meaningful — that needs a held-out eval and a judge, which live OUTSIDE
//!   the TCB and are unattested.
//! - `authenticated != true`.

use mneme_cap::Capability;
use mneme_core::{Draft, LogicalKey, MemoryKind, MnemeError, ObjectId};
use mneme_store::Store;

const EVOLVE_SESSION: [u8; 16] = *b"mneme-evolve\x00\x00\x00\x00";

/// A task with a **deterministic, verifiable reward** (Absolute-Zero shaped:
/// the loop both proposes and checks, with no external labels).
pub trait VerifiableTask {
    /// Short domain tag; learned skills are namespaced under `skills/<domain>`.
    fn domain(&self) -> &str;
    /// Propose a candidate from a seed. **Deterministic** — reproducible episodes.
    fn propose(&self, seed: u64) -> Vec<u8>;
    /// The verifiable reward: does the candidate satisfy the objective check?
    fn reward(&self, candidate: &[u8]) -> bool;
}

/// One accepted improvement, committed to the signed store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skill {
    pub key: LogicalKey,
    pub object_id: ObjectId,
    pub candidate: Vec<u8>,
    /// The skill this one descends from (the previously accepted skill), if any.
    pub parent: Option<ObjectId>,
}

/// The signed, attributable record of a self-play episode.
#[derive(Clone, Debug)]
pub struct EpisodeRecord {
    pub domain: String,
    pub attempts: u64,
    pub accepted: Vec<Skill>,
    /// Final signed root sequence after the episode (monotone; advances per commit).
    pub final_root_seq: u64,
}

/// Run a verifiable self-play episode against a real store.
///
/// For `rounds` seeds, propose a candidate, check the **real** reward, and on
/// success commit it as a `Procedural` skill whose `parent_ids` chains to the
/// previously accepted skill (the lineage DAG). Duplicate accepted candidates are
/// skipped. Deterministic in `(task, seed, rounds)`: identical inputs accept the
/// same candidates in the same order — the basis for a replayable episode.
pub fn run_episode(
    store: &mut Store,
    cap: &Capability,
    task: &dyn VerifiableTask,
    rounds: u64,
    seed: u64,
) -> Result<EpisodeRecord, MnemeError> {
    let namespace = format!("skills/{}", task.domain());
    let mut accepted: Vec<Skill> = Vec::new();
    let mut seen: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    let mut prev: Option<ObjectId> = None;
    let mut attempts = 0u64;

    for i in 0..rounds {
        attempts += 1;
        let candidate = task.propose(seed.wrapping_add(i));
        // Only a candidate that PASSES the verifiable reward and is novel is committed.
        if !task.reward(&candidate) || !seen.insert(candidate.clone()) {
            continue;
        }
        let key = LogicalKey {
            namespace: namespace.clone(),
            name: format!("skill-{:04}", accepted.len()),
        };
        let draft = Draft {
            namespace: key.namespace.clone(),
            logical_name: key.name.clone(),
            kind: MemoryKind::Procedural,
            body: candidate.clone(),
            parent_ids: prev.into_iter().collect(),
            session: EVOLVE_SESSION,
            trust_tier: None,
            embedding: None,
            valid_time_ms: None,
        };
        let (object_id, _root) = store.remember(draft, cap)?;
        accepted.push(Skill {
            key,
            object_id,
            candidate,
            parent: prev,
        });
        prev = Some(object_id);
    }

    let final_root_seq = store.current_root()?.sequence;
    Ok(EpisodeRecord {
        domain: task.domain().to_string(),
        attempts,
        accepted,
        final_root_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_cap::agent_cap;
    use mneme_core::{ForgetMode, ForgetTarget};
    use mneme_crypto::KeyPair;
    use tempfile::tempdir;

    /// A genuinely verifiable task: discover `n` in `[0, 1000)` with `n² ≡ 1 (mod 1000)`.
    /// The reward is an objective, deterministic check — no judge, no labels.
    struct ModularRoots;
    impl VerifiableTask for ModularRoots {
        fn domain(&self) -> &str {
            "modroots"
        }
        fn propose(&self, seed: u64) -> Vec<u8> {
            let n = (seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407)
                >> 33)
                % 1000;
            (n as u32).to_le_bytes().to_vec()
        }
        fn reward(&self, c: &[u8]) -> bool {
            let Ok(b) = <[u8; 4]>::try_from(c) else {
                return false;
            };
            let n = u32::from_le_bytes(b) as u64;
            (n * n) % 1000 == 1
        }
    }

    fn store_with_cap(dir: &std::path::Path) -> (Store, Capability) {
        let operator = KeyPair::from_seed([0x33; 32]);
        let cap = agent_cap(&operator, operator.public_key_bytes()).unwrap();
        let mut store = Store::create(&dir.join("store"), operator).unwrap();
        store.trust_mut().authorized_writers.push(cap.subject);
        (store, cap)
    }

    #[test]
    fn episode_commits_only_rewarded_candidates_with_lineage() {
        let dir = tempdir().unwrap();
        let (mut store, cap) = store_with_cap(dir.path());
        let rec = run_episode(&mut store, &cap, &ModularRoots, 500, 1).unwrap();

        assert!(!rec.accepted.is_empty(), "episode should learn some skills");
        // Every committed skill genuinely passes the verifiable reward.
        for sk in &rec.accepted {
            assert!(
                ModularRoots.reward(&sk.candidate),
                "only rewarded candidates are committed"
            );
        }
        // Lineage: each skill after the first descends from the previous one.
        assert!(
            rec.accepted[0].parent.is_none(),
            "first skill has no parent"
        );
        for w in rec.accepted.windows(2) {
            assert_eq!(w[1].parent, Some(w[0].object_id), "lineage chains forward");
        }
        // One signed root per accepted commit (monotone).
        assert!(rec.final_root_seq >= rec.accepted.len() as u64);
    }

    #[test]
    fn episode_is_deterministic() {
        let d1 = tempdir().unwrap();
        let (mut s1, c1) = store_with_cap(d1.path());
        let d2 = tempdir().unwrap();
        let (mut s2, c2) = store_with_cap(d2.path());
        let r1 = run_episode(&mut s1, &c1, &ModularRoots, 300, 7).unwrap();
        let r2 = run_episode(&mut s2, &c2, &ModularRoots, 300, 7).unwrap();
        let cands1: Vec<_> = r1.accepted.iter().map(|s| s.candidate.clone()).collect();
        let cands2: Vec<_> = r2.accepted.iter().map(|s| s.candidate.clone()).collect();
        assert_eq!(
            cands1, cands2,
            "same (task, seed, rounds) accepts the same skills in the same order"
        );
    }

    #[test]
    fn a_learned_skill_is_reversible_with_an_absence_proof() {
        let dir = tempdir().unwrap();
        let (mut store, cap) = store_with_cap(dir.path());
        let rec = run_episode(&mut store, &cap, &ModularRoots, 500, 1).unwrap();
        let sk = rec.accepted[0].clone();

        // A committed skill is present: prove_absent must REFUSE (the key is live).
        assert!(
            store.prove_absent(&sk.key).is_err(),
            "a committed skill is present, so it cannot be proven absent"
        );

        // Forget it (crypto-shred) — the improvement is rolled back …
        store
            .forget(
                ForgetTarget::LogicalKey(sk.key.clone()),
                &cap,
                ForgetMode::Shred,
            )
            .unwrap();

        // … and now its absence is provable against the new signed root.
        assert!(
            store.prove_absent(&sk.key).is_ok(),
            "after forget, the skill is provably absent (reversible self-improvement)"
        );
    }
}
