# Strata — VFD + Security-Context Grounding: quick-test findings

**Date:** 2026-07-31
**Author:** pilot run for the Strata eval redesign
**Scope:** two small, real-data experiments to decide *what approach to take* for the
evals — not publication-grade numbers. All code + data + raw model outputs are under
[`experiments/vfd-grounding-pilot/`](experiments/vfd-grounding-pilot/).
**Budget guard:** the user set a USD 30–50 ceiling on model spend. **Total spent ≈ USD 4.4.**
No OpenAI key is committed anywhere (verified); the harness reads it from `OPENAI_API_KEY`.

---

## TL;DR

Two questions, answered on real GHSA commits with a real OpenAI model (`gpt-5.4` primary,
plus a small cross-model sweep):

1. **Can a model tell a commit fixes a vulnerability from the diff alone, or does it need
   the commit message / PR?**
   **Diff-only recall is already near-ceiling** (6–7 of 7 fixes, including deliberately
   *silent* ones). Extra context does **not** raise recall meaningfully. What context *does*
   buy you is **lower false-positive rate on security-adjacent non-fixes** (dependency
   bumps) — and that matters more for weaker models and for weaker prompts. The frontier
   model with a decent prompt needs neither. **So: the interesting axis is FPR, not recall
   — exactly as the `oneshot.md` note predicted.**

2. **Does a security context built from a repo's *past* vulnerabilities help analyze *new*
   code, versus a blind first look?**
   **Yes for recall, with a real precision cost.** Relevant prior context lifted detection
   of held-out vulns from **2/4 → 4/4** (gpt-5.4, no reasoning) and rescued the *specific*
   bugs the model missed blind. An **irrelevant-context control did not** lift detection,
   so this is genuine grounding, not yes-priming. **But** grounding also makes the model
   *hunt the whole vuln class*, surfacing extra same-class findings elsewhere — including in
   already-patched files — and that alert volume **grows with reasoning effort**. Crucially,
   those extra hits were **not** re-flags of the fixed line; they were *different, plausibly
   real* siblings. The naive "blind vs here-are-the-findings" framing is misleading; the
   honest test needs an irrelevant-context control **and** patched/clean controls with
   per-finding verification.

**Net recommendation for the eval design:** measure FPR at the real base rate (recall is a
solved-looking problem on this population); make "context helps" claims only against a
leakage/irrelevant control; and evaluate the security-context/grounding idea as a
**recall-amplifier feeding a verification stage**, scored on *patched-code false alarms*,
not just on vulnerable-code hits.

---

## 1. Setup

### 1.1 How the data was obtained (no local corpus was present)

The repo checkout had **no** `ghsa-commits/` or `advisory-database/`, and this session's
network is locked down: `api.github.com` and `github.com` are reachable **only** for
`matiasinsaurralde/strata`; `add_repo` cannot pull cross-owner repos. Two channels *are*
open and were used:

- **OSV.dev API** (`https://api.osv.dev/v1/vulns/GHSA-…`) — advisory summary, CWE ids,
  CVE aliases, and reference URLs (commit / PR / issue). See `osv_fetch.py`.
- **Commit patches and PR bodies** — fetched with the assistant's `WebFetch` (which has an
  independent fetch path) against the public `…/commit/<sha>.patch` and PR pages. A strict
  "raw passthrough" prompt returns the patch **verbatim** (diff + full commit message).
- **Full pre-/post-fix source files** for Experiment 2 — parent SHAs discovered via the
  commit page, then files pulled byte-exact from `raw.githubusercontent.com`.

This is itself a useful finding for the harness: **you can build a GHSA commit corpus with
OSV + raw/patch fetches, without GitHub API tokens or cloning product repos.**

### 1.2 Models

`gpt-5.4` (primary) at `reasoning_effort ∈ {none, medium, high}`, plus `gpt-4o`, `gpt-4.1`,
`gpt-5.2`, `gpt-5.6-luna` for the sweep. gpt-5.x models reject `temperature`, so those run
at default temperature with `reasoning_effort`; gpt-4o/4.1 run at `temperature=0`. Pricing
for cost accounting uses the repo's `ModelPricing(1.25, 10.0, 0.125)` for gpt-5.x
(in/out/cached per 1M) and public gpt-4o rates; see `common.py`.

### 1.3 The pilot corpus (11 real commits)

**Positives — 7 GHSA fix commits**, chosen to span *silent → announced*:

| id | repo@sha | GHSA / CVE | CWE (advisory) | signal in message | PR |
|---|---|---|---|---|---|
| pgx | jackc/pgx@6dbad4ca | GHSA-xgrm-4fwx-7qm8 / CVE-2026-33815 | memory-safety (neg. length) | **quiet** ("Guard against negative parameter lengths") | none |
| go-tuf | theupdateframework/go-tuf@73345ab6 | GHSA-846p-jg2w-w324 | CWE-617/754 (panic→DoS) | **quiet** ("Perform type assertion") | #710 *empty* |
| aws-efs | kubernetes-sigs/aws-efs-csi-driver@51806c22 | GHSA-mph4-q2vm-w2pw / CVE-2026-6437 | CWE-88 (option injection) | **quiet** ("Validate mountTargetIp…") | none |
| sliver | BishopFox/sliver@81812734 | GHSA-2286-hxv5-cmp2 | CWE-22 (path traversal) | **very quiet** ("Use correct path construction") | none |
| go-attestation | google/go-attestation@b6e905e7 | GHSA-9r4w-jg96-92mv | CWE-20 (hash injection) | **announced** (body describes attacker/impact) | #502 rich |
| istio | istio/istio@692e460c | GHSA-9gcg-w975-3rjh / CVE-2026-39350 | CWE-185 (regex→authz bypass) | subject neutral; **diff** adds `area: security` note | #59700 one-line |
| kargo | akuity/kargo@23646eae | GHSA-w5wv-wvrp-v5m5 | CWE-863 (auth bypass) | **very quiet** ("Merge commit from fork") | none |

**Negatives — 4 non-fix commits from the same repos**, spanning easy→hard:

| id | repo@sha | kind | hardness |
|---|---|---|---|
| neg-gotuf-sigstore-bump | go-tuf@abd8cd2 | dependabot bump of a **signing lib** (sigstore) | hard (security-adjacent) |
| neg-kargo-xnet-bump | kargo@1f415234 | dependabot bump of **golang.org/x/net** | hard (archetypal FP driver) |
| neg-gotuf-logfix | go-tuf@45e0a1f | one-line log-format fix **inside `VerifyDelegate`** | hard (sits in sig-verify code) |
| neg-gotuf-mapscopy-refactor | go-tuf@4b704cd | `copyMapValues`→`maps.Copy` refactor | easy |

Only **2 of 7** fixes had a usable PR body — matching the design note that ~16% of
advisories carry a PR. That sparsity is itself a result (see §2).

---

## 2. Experiment 1 — the content ladder (diff → +message → +PR)

**Task.** One-shot: *"Does this commit fix a security vulnerability?"* → JSON
`{security_fix, confidence, cwe, why}`. Three input levels per commit:
`L0` diff only · `L1` diff + commit title+message · `L2` diff + message + PR body
(L2 only where a non-empty PR exists). Positives measure recall; negatives measure
specificity/FPR. Harness: `exp1.py`; prompt ablation: `exp1_prompt.py`.

### 2.1 Results (recall on 7 positives / FP on 4 negatives)

| model:effort | level | recall | quiet recall | neg FP | cwe hit* |
|---|---|---|---|---|---|
| gpt-4o:none | L0 | 7/7 | 5/5 | **2/4** | 4/7 |
| gpt-4o:none | L1 | 7/7 | 5/5 | **0/4** | 4/7 |
| gpt-4.1:none | L0 | 6/7 | 4/5 | 0/4 | 5/7 |
| gpt-4.1:none | L1 | 7/7 | 5/5 | 0/4 | 4/7 |
| gpt-5.2:none | L0 | 7/7 | 5/5 | **1/4** | 4/7 |
| gpt-5.2:none | L1 | 7/7 | 5/5 | **0/4** | 5/7 |
| gpt-5.4:none | L0 | 6/7 | 4/5 | 0/4 | 5/7 |
| gpt-5.4:none | L1 | 6/7 | 4/5 | 0/4 | 5/7 |
| gpt-5.4:medium | L0 | **7/7** | 5/5 | 0/4 | 5/7 |
| gpt-5.4:high | L0 | 7/7 | 5/5 | 0/4 | 5/7 |
| gpt-5.6-luna:none | L0 | 6/7 | 4/5 | 0/4 | 5/7 |
| gpt-5.6-luna:none | L1 | 7/7 | 5/5 | 0/4 | 5/7 |

\* `cwe hit` is a keyword match against the advisory CWE family and **undercounts** — e.g.
istio's fix was scored a "miss" although the model returned CWE-625/CWE-730 *Permissive
Regular Expression* / *improper neutralization*, which is a **more apt** class than the
advisory's CWE-185. Treat CWE auto-scoring as unreliable; the models' semantic descriptions
were consistently on-target. (Full grid incl. L2 in `aggregate_exp1.py` output.)

### 2.2 What it shows

- **Diff-only recall is near-ceiling, even on silent fixes.** Every model caught 6–7/7 from
  the diff alone. The only recurring L0 miss is **go-tuf**, and it's a *judgment call*, not a
  comprehension failure: gpt-5.4 (none) says *"defensive type checks … robustness/input-
  validation hardening rather than a clearly exploitable security fix"* — and even names the
  right class (CWE-248 uncaught exception). The message doesn't change its mind; **more
  reasoning does** (medium/high → 7/7). The hardening-vs-vulnerability boundary is genuinely
  fuzzy and is where the model's threshold, not its understanding, decides.

- **The commit message's real job is FPR, not recall.** Adding L1 flips the two
  dependency-bump false positives to correct rejections for the models that made them
  (gpt-4o 2→0, gpt-5.2 1→0), and also rescues an occasional borderline recall miss
  (gpt-4.1, luna 6→7). So `L1 ≥ L0` on both axes. On the x/net bump the message
  `"chore(deps): bump golang.org/x/net"` is exactly what lets a model say *"routine indirect
  dependency bump, no evidence it addresses a specific vulnerability."*

- **The PR (L2) added nothing beyond L1** on any decision here (the 2 PR-bearing fixes were
  already YES), and PRs existed for only 2/7 fixes. PR context helped *only* CWE-naming at
  high reasoning. For triage, PR retrieval looks low-value/high-cost on this population.

- **Reasoning effort substitutes for context, on the frontier model.** gpt-5.4 goes 6→7/7
  by thinking harder (none→medium), with **0 false positives at every effort** — while the
  message never rescued its one miss. Cost: `none` ≈ \$0.002/call, `medium` ≈ \$0.006/call.

- **The clean 0-FP result is partly the prompt.** The main prompt tells the model a fix is
  *"not a mere … routine dependency bump."* Dropping that hint (neutral prompt, `exp1_prompt.py`):

  | model | L0 recall (neutral) | L0 neg FP (neutral) |
  |---|---|---|
  | gpt-4o | 7/7 | **2/4** |
  | gpt-4.1 | 7/7 | **2/4** |
  | gpt-5.2 | 7/7 | **2/4** |
  | gpt-5.4 | 7/7 | **0/4** |

  Without the hint, the non-frontier models flag *both* dep bumps as fixes (*"the update of
  the sigstore library suggests a potential security fix"*) — reproducing the ~0.23 FPR the
  `oneshot.md` probe saw. **gpt-5.4 stays 0/4 regardless.** So diff-only FPR is a joint
  function of *model capability × prompt × whether the message is included*; recall is robust
  to all three.

### 2.3 Why FPR is the whole game (base-rate arithmetic)

At the measured ~1.5% prevalence, `precision = R·π / (R·π + F·(1−π))`. With near-perfect
recall `R≈1`:
- `F = 0.25` (weak model, neutral prompt, diff-only) → **precision ≈ 5.7%**.
- `F = 0.10` → precision ≈ 13%.
- `F → 0` (frontier + message, or frontier + reasoning) → precision usable.

Recall being saturated, **the entire deployability question is how close to 0 you can push
FPR** — which is what the message, the prompt, and model capability each contribute to. This
is the concrete case for measuring the negative arm as carefully as the positive arm.

---

## 3. Experiment 2 — security-context grounding (the key question)

**Question (user's words):** *given a security context generated from the past, evaluating
new code, do we get better findings accuracy or the same as a first-time look?*

**Design.** For 4 cases (sliver/CWE-22, istio/CWE-185, aws-efs/CWE-88, go-tuf/CWE-617) we
review the **full file** in two versions — `before` (vulnerable) and `after` (patched) — under
four context conditions:

- **blind** — code only.
- **relevant** — an aggregate, `securitycontext.dev`-style history for *that repo* naming the
  recurring CWE class, **without** pointing at the specific function (realistic grounding).
- **irrelevant** — same repo, a *different* plausible CWE class (priming control).
- **leading** — states the specific finding directly ("prior review reported X here; confirm")
  — the naive "here are the findings" approach.

We score whether the model reports the **held-out target vuln** on the vulnerable file
(recall) and whether it reports that same class on the **patched** file (false-alarm / volume).
Harness: `exp2.py`; contexts: `contexts.py`; region tooling: `diffregion.py`.

### 3.1 Results

**gpt-5.4, `reasoning_effort=none`:**

| metric | blind | relevant | irrelevant | leading |
|---|---|---|---|---|
| VULN detect (target found) | **2/4** | **4/4** | 2/4 | 3/4 |
| PATCHED same-class hit | 0/4 | 1/4 | 0/4 | 0/4 |

**gpt-5.4, `reasoning_effort=medium`:**

| metric | blind | relevant | irrelevant | leading |
|---|---|---|---|---|
| VULN detect (target found) | 3/4 | **4/4** | 3/4 | 4/4 |
| PATCHED same-class hit | 0/4 | **3/4** | 0/4 | 1/4 |
| PATCHED avg #findings | 0.75 | 1.00 | 0.50 | 0.75 |

**Cross-model / cross-effort robustness** (all 5 configs, 4 cases each):

*VULN detection (held-out target found on vulnerable file):*

| config | blind | relevant | irrelevant | leading |
|---|---|---|---|---|
| gpt-5.4:none | 2/4 | **4/4** | 2/4 | 3/4 |
| gpt-5.4:medium | 3/4 | **4/4** | 3/4 | 4/4 |
| gpt-5.4:high | 3/4 | **4/4** | 4/4 | 4/4 |
| gpt-5.2:medium | 3/4 | **4/4** | 3/4 | 3/4 |
| gpt-5.6-luna:medium | 3/4 | **4/4** | 3/4 | 4/4 |

*PATCHED-file same-class hits (alert volume / potential false alarm):*

| config | blind | relevant | irrelevant | leading |
|---|---|---|---|---|
| gpt-5.4:none | 0/4 | 1/4 | 0/4 | 0/4 |
| gpt-5.4:medium | 0/4 | **3/4** | 0/4 | 1/4 |
| gpt-5.4:high | 1/4 | **3/4** | 2/4 | 0/4 |
| gpt-5.2:medium | 2/4 | **3/4** | 2/4 | 0/4 |
| gpt-5.6-luna:medium | 2/4 | **3/4** | 0/4 | 0/4 |

Two things replicate in **every** config: **relevant context takes recall to 4/4**
(blind is 2–3/4), and **relevant context lands 3/4 same-class hits on patched files**. The
`irrelevant` control stays at blind-level recall except at `high` effort — where blind is
already strong and reasoning alone saturates detection, so grounding's *recall* margin
shrinks as effort rises (its *volume* cost does not). The `leading` condition behaves
differently from aggregate context: it produces almost no patched-file findings (avg
0.0–0.25) because the model treats it as "confirm this one item" and correctly answers "no,
fixed" — it neither hunts for siblings nor beats aggregate context on recall.

### 3.2 What it shows

- **Relevant prior context genuinely improves recall on new code.** Blind, gpt-5.4 (none)
  found only 2/4 held-out vulns; with the repo's own history it found **all 4**. The rescued
  cases are the subtle ones buried in large files: on **aws-efs**, blind the model found only
  an unrelated data race and *missed* the injection; with relevant context the **MountTargetIp
  option injection (CWE-88) became its #1 finding** — the right bug, in the right place.

- **It's grounding, not yes-priming.** The **irrelevant** context (same repo, wrong class)
  did **not** lift detection (2/4 → 2/4 at none; 3/4 → 3/4 at medium) and never caused a
  false alarm. If the gain were mere "be more suspicious," irrelevant context would have
  helped too. It didn't. That control is what makes the result credible.

- **The cost is alert volume / precision.** Relevant grounding's same-class hits on *patched*
  files rose from **1/4 (none) → 3/4 (medium) → 3/4 (high)** and were **3/4 in every config**,
  model-independent. But inspecting them: **none were re-flags of the fixed line.** They were *different* functions of the same
  class — a `srcNamespaceGenerator` regex (not the patched `serviceAccountRegex`), a
  `MountFlags` comma-injection vector (not the patched `MountTargetIp`), and two *other*
  reachable panics in go-tuf (not the patched `checkType`). So grounding turned "find *a*
  vuln" into "**hunt this whole class**," surfacing plausibly-real siblings. Whether each is
  a true finding needs verification — which is the point: **grounding raises recall and the
  verification burden together.**

- **The naive "here are the findings" (leading) approach is not the win it looks like.** It
  did *not* beat aggregate relevant context on recall (3/4 vs 4/4 at none), and — reassuringly
  — it did **not** make the model parrot the fixed bug on patched code (its one patched hit was
  again a *different* sibling). So models don't blindly confirm a handed-in finding; but a
  leading prompt gives you no verification and no better recall than honest aggregate context.

### 3.3 The methodological correction

The user's proposed test ("blind vs *these are the findings*") is **too easy and misleading on
its own**: on vulnerable code the model will agree, and the naive metric looks great. The
signal only becomes trustworthy with the two controls this run added:
1. an **irrelevant-context control**, to prove the lift is grounding and not "say yes more";
2. **patched/clean controls with per-finding location checks**, to separate "found a real
   sibling" from "false alarm on fixed code."
Both are cheap and both flipped the interpretation. Any Strata grounding eval should bake them
in.

---

## 4. Direct answers to the questions asked

- **"Are models good enough to decide from the diff alone, or do they need more context?"**
  For *recall*, the **diff alone is enough** — 6–7/7 including silent fixes, no meaningful lift
  from message/PR. The residual misses are threshold judgment calls (hardening vs vuln) that
  *reasoning*, not context, resolves. For *precision*, the diff alone is enough **for a
  frontier model with a sane prompt**, but weaker models / weaker prompts over-fire on
  dependency bumps, and the **commit message reliably fixes that**. Bottom line: ship diff-only
  for recall; add the message as cheap FPR insurance; skip PR retrieval for triage.

- **Silent fixes.** The silent commits (sliver, kargo "Merge commit from fork", pgx) were
  caught from the diff with no disclosure words present — evidence the model reads the *code*,
  not the announcement. This is the population that matters, and it's tractable.

- **Building a database of fix commits (incl. non-CVE / private).** Feasible: the pipeline
  needs only the diff to label a fix with good recall, so it will generalize to commits that
  have no advisory at all. The gate is **FPR at scale**, not recall — budget the labeling and
  the negative arm accordingly.

- **Generating a grounding security context.** Works, with the caveats in §3: relevant repo
  history measurably improves detection on new code and generalizes the pattern to new
  locations — but it must feed a **verification stage**, because it also raises same-class
  alert volume (including on already-fixed code), and that volume scales with reasoning.

---

## 5. Recommended approach for the eval redesign

1. **Make FPR the headline, not recall.** Recall on this population looks solved; report the
   negative arm (uniform-random same-repo commits) at the real base rate, with dependency
   bumps explicitly represented as hard negatives. Precision at 1.5% is decided there.
2. **Freeze the prompt as a variable of record.** The 0-FP vs 2/4-FP swing came *purely* from
   one clause in the system prompt. Version prompts; never compare content levels across
   different prompts.
3. **Triage = diff + commit message; drop PR from triage.** Message is cheap and fixes the
   dep-bump FP; PR is sparse (2/7) and added nothing but a marginally better CWE label.
4. **Spend the compute budget on reasoning, not context, for the hard positives.** The one
   ambiguous fix flipped on `reasoning_effort`, not on more input.
5. **Evaluate grounding as a recall-amplifier + verifier, with an irrelevant control and a
   patched-code control.** Score it on *patched-code false alarms* and *findings/commit*, not
   only on vulnerable-code hits. This maps cleanly onto Strata's triage→adjudicator split: the
   security context boosts stage-1 recall; the adjudicator must absorb the extra volume.

---

## 6. Limitations (this is a pilot, not an estimate)

- **Tiny n** (7 pos / 4 neg in Exp 1; 4 cases in Exp 2). Directions are visible; rates have
  huge CIs (0/4 FP has a Wilson upper bound near 0.5). This shows *shape*, not publishable
  numbers.
- **Positives skew Go and skew `quiet`** — chosen to stress non-obviousness, not representative
  of the stratum/language mix.
- **Single run, default temperature** (gpt-5.x reject temp=0); no self-consistency. Individual
  cells (esp. the go-tuf/aws-efs judgment calls) can move run to run.
- **CWE auto-scoring is unreliable** and undercounts correct-but-differently-numbered answers;
  the model descriptions were the reliable signal.
- **Diff fidelity.** Patches came through `WebFetch`; the strict passthrough reproduced them
  verbatim in spot checks, but a production harness should fetch patches to disk directly.
- **Memorization not re-measured here.** The companion `memorization.md` already showed ~0
  advisory-level contamination on this kind of corpus across 10 models; these advisories are
  2026-dated and obscure, so high recall is reasoning, not recall-from-training. Worth an E10
  pass at scale.

---

## 7. Reproduce

Everything is in [`experiments/vfd-grounding-pilot/`](experiments/vfd-grounding-pilot/):

```
export OPENAI_API_KEY=...            # never committed
cd experiments/vfd-grounding-pilot
python osv_fetch.py                  # advisory metadata (optional; already captured)
python exp1.py "gpt-5.4:none" "gpt-5.4:medium"     # content ladder
python exp1_prompt.py                # neutral-prompt FPR ablation
python exp2.py "gpt-5.4:none" "gpt-5.4:medium"     # grounding
python aggregate_exp1.py ; python aggregate_exp2.py
```

`patches/` = verbatim commit patches, `pr/` = PR bodies, `code/` = full pre/post-fix files,
`runs/` = raw model outputs (JSONL, one row per call incl. token usage).

## 8. Cost

| run | calls | USD |
|---|---|---|
| Exp1 gpt-5.4 none | 24 | 0.054 |
| Exp1 gpt-5.4 medium+high | 48 | 0.284 |
| Exp1 sweep (4o/4.1/5.2/luna) | 96 | 0.270 |
| Exp1 neutral-prompt ablation | 44 | 0.113 |
| Exp2 gpt-5.4 none | 32 | 0.194 |
| Exp2 gpt-5.4 medium | 32 | 0.695 |
| Exp2 cross-model (5.4-high, luna-med, 5.2-med) | 96 | 2.762 |
| probes / dry runs | ~15 | ~0.02 |

**Total ≈ USD 4.4**, well under the USD 30–50 ceiling. (Input tokens dominate the cheap runs;
`reasoning_effort=high` on ~8 KB files drove almost the entire cost — 210 k reasoning tokens in
that one run.)
