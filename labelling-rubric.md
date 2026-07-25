# Commit-Role Labelling Rubric

**Purpose.** Define what each `role` means so every commit is judged by the same
rule — commit #5 and commit #95 get the same call. Label noise (20–71% of labels
were found wrong in real-world vulnerability datasets by Croft et al., ICSE'23)
comes almost entirely from undefined boundaries. This is the standard that closes
them.

Roles are written by `label.py` into `labels.jsonl` and merged into
`commits.jsonl` as the `role` field by `main.py`. They are the ground truth the
eval scores against (`eval.py` label-aware mode).

---

## The core question

Re-ask this on **every** commit:

> **"What is this commit's relationship to a real, pre-existing, exploitable
> security vulnerability?"**

Ground truth is the **reality** of the commit (was it a vuln fix?), not only what
is obvious from the diff. When the diff alone is insufficient, you **may** use
the commit message and (for GHSA rows) the advisory to decide. Change the role
only when that context makes the answer clear.

- **Undecidable** even with message/advisory (e.g. a "security" dependency bump
  with no visible in-repo exploit path) → `other`, with a short note. Do not
  guess `fix` to tidy metrics.
- **Stage-1 models still see the diff only.** Richer labels measure whether the
  classifier can recover reality from a weaker view; that is intentional for the
  cascade (triage → adjudicate).

Earlier phase-1 labelling was often diff-only; contested rows have been / may be
revisited under this rule. New labels should follow reality-with-context.

---

## Roles

### `fix`
The diff contains the **substantive code change that closes the vulnerability**.

- Partial fix — one of several commits that together close it? → still `fix`
  (it fixes something real; advisory-level recall handles the "whole fix?"
  question separately).
- Hardening with no named CVE? → `fix` **if** it removes a genuinely exploitable
  path; otherwise `other`.
- Test-only change? → **not** `fix` → `context` (the fixing code is elsewhere).
- **"Merge commit from fork" (fork-squash)?** → almost always `fix`. GitHub's
  private-fork security workflow squashes the whole fix into a *single-parent*
  commit with this subject (it is not a real 2-parent merge). The diff carries
  the complete fix — often the cleanest positive you'll see. Note its
  `msg_class` comes out `quiet`, which is correct (no security language in the
  subject); do **not** expect `merge_noise`. See the fork-squash TODO below.

### `context`
Related to the advisory but **not the fixing code**.

- CHANGELOG / release notes / docs that merely *describe* the fix or announce the
  CVE → `context`.
- A test that encodes or verifies the fix → `context` (the fix is a different
  commit).
- A discussion-referenced commit, or a revert → `context`.

### `backport`
The **same logical fix** as another commit, ported to a different branch or
release line (a different SHA carrying an equivalent change).

- Can't tell whether this is the original or the port? → label `fix`. Use
  `backport` **only** when you can see it duplicates a fix you've already
  identified. It is a real fix but a *duplicate* one, so the eval counts it in
  neither recall nor false positives — it is reported on its own.

### `introduce`
The commit that **caused** the flaw (vulnerability-contributing commit).

- Rare from GHSA (advisories almost never reference introducing commits). Assign
  only when there is explicit evidence — e.g. the advisory says "introduced in…".
- This is a **negative** for fix-detection: the classifier should say "no."

### `other`
None of the above: a version/dependency bump, an unrelated change, a random
non-security commit, or **genuinely undecidable**.

- **"Security" dependency / lockfile bumps** with no visible first-party exploit
  path in this repo → `other` (note it). Do not promote to `fix` on message
  wording alone.

- Truly cannot decide? → `other` **plus a note** explaining why. Never force a
  `fix`/`context` guess to avoid `other`; an honest "undecidable" is data, a
  coin-flip is noise.

---

## Tie-breakers

The recurring ambiguities, resolved once so you don't re-litigate them:

1. **The revert test (use this first).** *"If I reverted this commit, would the
   vulnerability come back?"*
   **Yes → `fix`. No → `context`.** This resolves most `fix`-vs-`context` calls
   and maps directly to what the classifier is meant to detect. The patch passes;
   tests, changelogs, and docs fail (reverting them doesn't reopen the hole).

2. **Diff touches both fixing code AND a changelog/docs hunk.** → `fix`. The code
   change wins; the changelog is incidental. (This is the filebrowser case — a
   real fix whose diff also happens to announce the CVE.)

3. **Multi-commit advisory — which one is "the" fix?** Don't pick a single winner.
   Each substantive fixing commit is `fix` independently. Supporting commits
   (tests, backports, changelog) take their own role.

4. **Security-relevant but no evidence it was ever exploitable.** → lean `other`,
   note why. Phase 1 targets *exploitable* vulnerabilities, not general hardening.

5. **Still torn between `fix` and `context`?** Apply tie-breaker 1 again and
   commit to the answer. If it's genuinely 50/50, it's `other` with a note.

---

## Conventions

- **Write a one-line note** on every non-obvious call (`label.py` prompts for it).
  Future-you and any second annotator need the *why*, not just the verdict.
- **Reality over diff-only purity.** Prefer message + advisory when needed to
  decide `role`; leave `other` when still unclear (including security-flavoured
  dep bumps with no in-repo path). Stage-1 eval remains diff-only *input*.
- **Be consistent over correct-in-isolation.** A slightly-wrong rule applied
  uniformly is recoverable (shift the whole set); an inconsistent standard is not.
- **One sitting ≤ ~100 commits.** Fatigue degrades label quality; split larger
  batches across sessions and re-read this file at the start of each.

---

## TODO / open items

- **Fork-squash stratification.** "Merge commit from fork" squashes are a
  recurring, identifiable population (GitHub's coordinated-disclosure workflow
  rendered in git) and worth measuring recall on separately. They are currently
  single-parent commits classified `quiet`, which is correct — but there is no
  flag to slice by them. If enough accumulate to matter, add a `fork_squash`
  boolean to the commit row (subject matches "Merge commit from fork",
  regardless of parent count) rather than forcing them into `merge_noise`, which
  is a data-quality bucket for empty-diff merges and would mis-file these
  full-diff fixes. Deferred until there is data to justify the axis.

---

## Before a labelling round (holdout discipline)

Decide the **test/holdout split before labelling**, not after — so you never
inspect commits you later want as an untouched test set. Once a holdout is
locked, don't look at it during development; rotate a fresh one each round.
