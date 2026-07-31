# Strata — Evaluation Design v2

**Status:** design proposal, ready to build against
**Date:** 2026-07-31
**Companions:** `research.md` (roadmap & literature), `evals.md` (v1 eval design, GHSA measurements), `prd.md` (implementation inventory & roadmap).
**Scope:** the **one-shot commit‑filtering (triage) task** as the primary object of study, with the **adjudicator cascade** as the secondary object. This document specifies *what we validate, how we report it, what to refactor, and how to de‑risk with a small run before the full one.*

---

## TL;DR — what we are validating

1. **Grounding decision (primary).** Which triage input profile should Strata ship — diff‑only (`D0/D1`), diff+message (`D2/D3`), or diff+message+issue/PR (`C3`) — decided at the **real ~1.5% base rate**, on the **silent‑fix population**, not on a balanced or CVE‑linked set.
2. **The reasoning‑vs‑leakage question.** When added context helps, is the model *reading the code better* or *reading the disclosure words*? The redaction axis (`M0/M1/M2`) answers this and is what makes the grounding decision defensible rather than an artifact of label leakage.
3. **The base‑rate collapse and the cascade's recovery.** That a single‑stage classifier's precision collapses to single digits at 1.5% prevalence (a known but rarely‑measured result), and that the two‑stage cascade with hard gates recovers it.
4. **Adjudicator strategy.** Which stage‑2 configuration (chat vs codex; A0 vs A1; single vs consensus) earns its latency, measured by gate behaviour on hard cases.

Everything below is in service of producing those four numbers with confidence intervals, contamination controls, and a reproducible provenance trail — first on a cheap pilot, then at full scale.

---

## 0. Why a v2

`evals.md` is a strong design but predates the implementation and is written as a plan. Since then the harness has been *substantially built* (`src/strata_eval/ablation.py`, `metrics.py`, `corpus/`, `splits.py`, `redaction.py`) — the statistics engine, per‑stratum recall/FPR, the precision curve at π∈{0.2%, 1.5%, 5%}, repository‑block bootstrap CIs, and even an **automatic profile selector** (lowest expected cascade cost among gate‑passers, `ablation.py:565`) all exist. What is missing is **data, three harness axes, validity controls, and a reproducible run protocol.** This document is the executable bridge from "coded as parts" to "runs and reports a defensible number."

It also folds in four decisions we've since settled:
- the **factorial** (content ladder × redaction × stratum) rather than a single ladder;
- **batch mode** for the one‑shot arm (50% off, and it fits triage perfectly);
- a **pilot‑then‑full** execution shape;
- explicit **retrospective (Profile A) vs prospective (Profile B)** separation so a retrospective number is never quoted as a deployable one.

---

## 1. Grounding in the literature (`research.md`) — what's known, what's new

### 1.1 The task is not new; the evaluation is

Vulnerability‑Fix Detection (VFD) — *"does this commit fix a security vulnerability?"* — is a mature line: VulFixMiner → VulCurator/PatchRNN → GraphSPD/RepoSPD → **CommitShield, LLM4VFD, Han et al., CleanVul** (`research.md` §2.1). We are **not proposing a new detector.** Our contribution is methodological and architectural:

| Our contribution | The gap in the literature it addresses |
|---|---|
| **Prevalence‑honest evaluation** — recall and FPR estimated *independently*, precision derived analytically at real π (`metrics.precision_at_prevalence`) | The field evaluates on **balanced** sets (CommitVulFix ≈38% prevalence, PatchDB oversampled), which makes precision ~10× optimistic (`evals.md` §5.1). |
| **Silent‑fix stratification as the headline** — `quiet` recall at matched FPR, using GHSA's retroactively‑disclosed commits as the silent proxy | No public dataset isolates the silent population; "silent fixing is *policy*" (`evals.md` §2.1), i.e. the mandated output of coordinated disclosure. |
| **Reasoning‑vs‑leakage separation** — redaction (`M0/M1/M2`) removes disclosure vocabulary while keeping prose | Enrichment studies (CommitShield) inject the CVE/CWE into the input and then report the gain — a leakage result dressed as capability (`research.md` §3.1 caveat 3). |
| **Cascade + hard gates + byte‑verified anchoring** — `reachability_delta=narrows`, containment gate, `cite`‑only evidence | The literature reports single‑stage F1 on balanced sets; the deployment‑honest cascade and the enforced direction/containment tests are ours. |
| **Deployment metrics** — alerts/1000, reviewer‑hours/TP, expected cascade $/commit | "The most useful and most under‑reported number in the entire VFD literature" (`research.md` E2). |

So the honest framing for a paper: *a rigorous, deployment‑honest evaluation of a known task on the population everyone else avoids, plus an engineered cascade that survives that population.* That is a legitimate contribution, and it is falsifiable.

### 1.2 Is our dataset similar?

Similar in *kind* (commit‑level security‑fix labels), different in *composition* — deliberately:

| Dataset | Prevalence | Population | Negatives |
|---|---|---|---|
| CommitVulFix (CommitShield) | ~38% | C/C++, post‑2023, CVE‑linked | balanced non‑fixes |
| PatchDB | oversampled | multi‑language | synthetic + real |
| MoreFixes / CVEfixes | n/a (positives only) | **CVE‑linked ⇒ announced** | — |
| **`ghsa-vfd` (ours)** | **~1.5% (measured, `evals.md` §3.7)** | **substantially silent** (~67% no security language, huge commit→advisory lag, `evals.md` §3.6), multi‑ecosystem | **random commits from the same repos** |

The critical difference is the negative side and the prevalence. We do **not** build a balanced window (`evals.md` §5.1) and we do **not** sample negatives adjacent to fixes (systematically unusual). We sample negatives *uniformly at random from the same repositories* and evaluate at the measured base rate. This is the concrete instantiation of the field's own warning that models tuned on NVD/announced patches lose up to 90% F1 in the wild (`research.md` §2.6) — we are testing *on* the in‑the‑wild distribution instead of tuning away from it.

### 1.3 Findings from the literature we expect to reproduce (and where we may diverge)

| Literature finding | Our prediction on the silent population | Divergence risk / interest |
|---|---|---|
| **Context enrichment lifts precision** (CommitShield: +19pp from issue/PR context, same model) | Lifts `announced` recall/precision; **gain shrinks or vanishes on `quiet` after M1 redaction** | If the lift survives redaction, context genuinely helps reasoning — a stronger result than CommitShield's (which leaks). If it collapses, we've quantified how much of the field's "context helps" is leakage. |
| **Augmentation raises FPR** (Han et al.: Data‑Aug FPR worse for every model but one) | Adding message/issue raises FPR; the precision‑at‑prevalence tradeoff may go *negative* | This is why we report FPR per cell, not just recall. |
| **Few‑shot hurts** (−4.9 to −7.2pp precision); **CoT helps non‑agentic** (Han et al.) | Secondary ablation; expect few‑shot to hurt triage | Cheap, possibly free precision; confirm on our data. |
| **Base‑rate collapse** (`research.md` §3.2: single‑stage precision ≈9.6% at 1.5%) | We will *observe this directly* and show the cascade recovers precision to ~0.5–0.7 | This is the load‑bearing argument for the whole architecture; measuring it is the point. |
| **Zero‑context recall ~94% ⇒ leakage** (CommitShield's own caveat) | Our E10 probe + temporal holdout will show a non‑trivial memorised fraction | Table stakes for credibility. |
| **Our own in‑code hint**: D0 caught 6/10 vs D3 4/10 on gin — a *routine subject suppressed a YES* | Message may **hurt** recall on some strata | This is *counter* to "context always helps." If it replicates, it's a genuinely interesting finding: a conventional‑commit subject can mislead a diff‑only reader. |

### 1.4 Are we validating a new idea?

Two ideas are genuinely under test that the literature has not isolated:

- **H‑silent:** *A diff‑only classifier's advantage over a message‑augmented one is a function of how silent the fix is.* Concretely, we predict `R(D3) − R(D0)` is large and positive on `announced`, ≈0 on `quiet`, and that `R(D3, M1) − R(D0, M1)` (redacted) is small on both — i.e. the message's value is mostly its disclosure vocabulary. Nobody has measured this because nobody stratifies GHSA by silence.
- **H‑cascade:** *A recall‑first one‑shot filter followed by a precision‑first gated adjudicator achieves usable precision at 1.5% prevalence where a single stage cannot.* We predict end‑to‑end precision@1.5% ≥ 0.5 with `quiet` recall ≥ 0.9·(stage‑1 recall), versus <0.15 single‑stage.

Both are falsifiable, both are grounded in the shipped code, and both are novel *as measured claims on the silent population*.

---

## 2. Experimental design

### 2.1 Task separation (what we do and don't measure here)

We measure **VFD** (fix detection) only. We do **not** measure VCC/introducing‑commit attribution (GHSA has no ground truth for it, `evals.md` §3.2c) or downstream artifact utility (E6/E7 in `research.md` — a later phase). Keeping the tasks apart is what makes the numbers interpretable.

### 2.2 The two independent arms (why precision is derived, not measured)

Precision at any prevalence follows analytically from recall and FPR: `P(π) = R·π / (R·π + F·(1−π))`. So we estimate the two separately (`evals.md` §5.2), which is already how `ablation.py` reports:

- **Recall arm** — run triage over `ghsa-vfd` **positives**. Every one is a true positive by construction ⇒ **zero labelling.** Report recall per `msg_class` stratum with Wilson CIs (`metrics.wilson_interval`).
- **FPR arm** — sample commits **uniformly at random** from the same repositories, excluding known fix commits. Ground truth is the human `labels.jsonl` role (`fix/context/backport/introduce/other`); only the disputed/flagged subset needs human eyes. Report **coverage‑corrected** FPR (`metrics.summarize_binary` — uncovered negatives never silently deflate it).

Then report the **precision curve** over π and mark the operating points {0.2%, 1.5%, 5%} (`DEFAULT_PREVALENCES`), plus **alerts/1000** and **reviewer‑hours/TP**.

### 2.3 The factorial (triage)

Three crossed axes, every cell reported:

- **Axis A — content ladder** (input profile, normalization held fixed at D1‑normalized so it isn't confounded):
  - `C0` = diff only (≈ `D0/D1`)
  - `C1` = + commit subject (≈ `D2`)
  - `C2` = + full commit message (≈ `D3`)
  - `C3` = + linked issue/PR *when available* (**new build**, §4)
  - `C4` = + advisory join — **not a condition, a leakage ceiling** (upper bound on how far pure label‑lookup gets)
- **Axis B — message condition** (`redaction.py`): `M0` full · `M1` disclosure‑redacted · `M2` neutral stub. Applies only to message‑bearing profiles (C1–C3).
- **Axis C — stratum** (`corpus/keywords.py`): `announced / quiet / empty / merge_noise`.

Plus a small **secondary prompt ablation** (zero‑shot vs few‑shot vs CoT) on one cell, to confirm Han et al. on our data.

**Normalization** (raw `D0` vs normalized `D1`) is its own one‑off side ablation, *not* baked into C0 — otherwise a C0 loss confounds "missing message" with "vendored‑file noise."

### 2.4 Selection bias for the "if available" tier (C3)

Only ~16% of reviewed advisories carry a PR URL (`evals.md` §3.1). So C3 is scored on the **intersection subset** where issue/PR exists, and **C0–C3 are compared head‑to‑head on that same subset** — never C3‑on‑its‑favorable‑subset vs C0‑on‑everything. Report the subset size and its skew separately.

### 2.5 The adjudicator arm (secondary)

Over a curated hard‑case set (and later a holdout), A/B the stage‑2 strategies (already in `scripts/ab_adjudicator.py`):
- **Backend:** chat (9 read‑only tools) vs codex (sandboxed shell).
- **Profile:** A0 blind vs A1 enriched (`linked_artifact`).
- **Consensus:** single vs N‑round majority.
- **Cascade rule:** strict (confirmer must YES) vs veto (confirmer must not NO).

Report precision/recall/**abstain**, per‑gate behaviour (`reachability_delta`, `failure_containment`), tool/command count, latency, cost. This is a *capability probe on hard cases*, not a population estimate — and the natural place to later A/B **tree‑sitter structure on vs off** (`prd.md` §7).

### 2.6 Contamination controls (non‑optional)

- **Temporal holdout** (`splits.temporal_holdout_assignments`, grouped by advisory/patch/backport so a backport can't leak its sibling): build/tune on ≤T, report the honest number on >T (rolling last‑6‑months).
- **E10 memorisation probe** (**new build**): ask the model to describe the advisory with *no code and no message*; report all metrics with and without the memorised fraction.
- **Locked test half** never inspected during any prompt/threshold tuning.

### 2.7 Hypotheses & pre‑registered predictions

| ID | Hypothesis | Predicted direction | Decision rule |
|---|---|---|---|
| H1 | Message helps `announced`, not `quiet` | `R(C2)−R(C0)` ≫ 0 on announced; ≈0 on quiet | If true, ship diff‑only for the silent regime. |
| H2 | The help is mostly leakage | redaction M1 shrinks `R(C2)−R(C0)` toward 0 on announced | If true, C2's "capability" is keyword‑reading. |
| H3 | Context raises FPR | `F(C2) > F(C0)`, `F(C3) > F(C2)` | Weigh recall gain against precision loss at π=1.5%. |
| H4 | Single‑stage precision collapses | precision@1.5% < 0.15 for all triage cells | Motivates the cascade. |
| H5 | Cascade recovers precision | end‑to‑end precision@1.5% ≥ 0.5 at `quiet` recall ≥ 0.9·stage‑1 | The go/no‑go for the architecture. |
| H6 | Message can *hurt* recall | ∃ stratum where `R(C2) < R(C0)` (the gin hint) | Report as a finding if it replicates. |
| H7 | codex ≥ chat on reachability/direction | codex flips introducing‑commit / library‑reachability cases the chat backend misjudges | Decides whether the sandbox's 6× latency is justified. |

---

## 3. Metrics & reporting

### 3.1 Per‑cell metric block (already computed by `metrics.py`)

For every `(profile × condition × stratum)` cell:
- **recall** and **coverage‑corrected FPR**, each with a **Wilson 95% CI**;
- **precision@{0.2%, 1.5%, 5%}** via `precision_interval_at_prevalence` (report the *interval*, not three false‑precision digits);
- **alerts/1000** and **reviewer‑hours/TP**;
- **expected cascade $/commit** (`expected_cascade_cost`), and raw tokens/USD/wall‑clock;
- **repository‑block bootstrap 95%** (`repository_block_bootstrap`, 2000 resamples) so a single dominant repo can't carry the number.

### 3.2 The headline number

> **`quiet`‑stratum recall, at the FPR‑matched operating point, reported alongside precision@1.5%.** (`evals.md` §6.3)

Everything else is diagnostic. If one number goes in the abstract, it is this one — because `quiet` is the silent‑fix proxy and pooled recall is gameable by keying on announcements.

### 3.3 The decision procedure is already coded

the ablation's profile‑selection logic picks the **lowest expected‑cascade‑cost profile among those passing the gate** (overall recall ≥0.95 **and** `quiet` recall ≥0.90; gate at `ablation.py:475`, selection rationale at `:565`). So once the axes and data exist, *the D0/D3 grounding decision is produced mechanically and reproducibly*, not argued. We should keep that selector and extend it to rank over the full `(profile × condition)` grid, subject to the same gate.

### 3.4 Reporting template (per run)

Emit the `evals.md` §11.1 JSON, extended with the axes and always carrying the grounding triple:

```json
{
  "corpus":   {"name":"ghsa-vfd","version":"…","advisory_db_sha":"…",
               "positives":{"quiet":…,"announced":…,"empty":…,"merge_noise":…},
               "negatives":{"n":…,"source":"random_same_repo"},
               "split":"holdout","cutoff":"…"},
  "grounding":{"triage_prompt_id":"current-diff-only-v1","prompt_hash":"sha256:…",
               "input_profile":"D1","message_condition":"M0"},
  "config":   {"model":"gpt-5.4","reasoning_effort":"none","temperature":0.0,
               "batch":true,"keyword_table":"2026-07-26.3","cwe_catalog":"4.20"},
  "cells":    [ /* per (profile × condition × stratum): recall, fpr, precision_curve, ci, cost */ ],
  "headline": {"quiet_recall":{"point":…,"ci95":[…,…]},"precision_at_1.5pct":[…,…]},
  "workload": {"alerts_per_1000":…,"reviewer_hours_per_tp":…},
  "contamination": {"probe_positive_rate":…,"post_cutoff_recall":…},
  "gate":     {"overall_recall_at_least_0_95":…,"quiet_recall_at_least_0_90":…,"winner":"…"}
}
```

Freeze the winner's block as `results/baseline/…`; `ScoreReport.diff_against` / `ab_adjudicator --compare` then render deltas for every subsequent change — so "did this help?" stays a one‑liner.

---

## 4. What we need to refactor / build

Mapped to files, with an honest have/build split. The statistics are ~80% done; the work is data + three axes + controls + a batch path.

### 4.1 Data (the gating dependency)
- **Corpus builder** — *build.* `corpus/bundle.py` is a loader only; nothing writes `commits.jsonl`. Add `strata-eval corpus build`: shallow‑clone `github/advisory-database`, regex commit URLs (can't use ref types, `evals.md` §3.2a), resolve SHAs through the **existing bare‑repo cache** (no GitHub API), compute `msg_class`/`lag_days`/`resolved`/`n_in_advisory`. Diff merges against **first parent** (already correct in `git_repo.py`).
- **`labels.jsonl`** — *produce.* Human roles for the FPR negatives + the `quiet` guardrail: ~150–250 items, 2 raters, Cohen's κ (`evals.md` §5.3). `labeling/worklist.py` builds the blind worklists already.
- **Frozen splits** — *apply.* `splits.py` exists; freeze a temporal + grouped holdout and version it.

### 4.2 Harness axes (code)
- **Redaction axis into the runner** — *small.* `redaction.apply_condition` exists but `ablation.py` has no `--conditions`; cross M0/M1/M2 into the profile loop and the cache key.
- **C3 = issue/PR at triage** — *the one real build.* Linked‑artifact retrieval is an *adjudicator* A1 tool only; add a triage input level (`diffing.build_input_profile` L3) + fetch/cache, Profile‑B‑safe.
- **Random‑negative FPR loop** — *medium.* `ablation`'s FPR currently comes from labelled dev rows; wire `labeling.build_negative_audit_worklist` → (human/adjudicator) → join for the *uniform‑random* FPR of `evals.md` §5.2.
- **E10 contamination probe** — *small.* One no‑code call per positive; report the memorised fraction.
- **Same‑subset intersection harness** for C3 — *small.*
- **Promote `strata_eval.ablation` under `strata-eval`** and emit the §3.4 JSON with the grounding triple.

### 4.3 Batch path (for the one‑shot arm)
- *Modest, ~1–2 days.* Triage is stateless one‑shot ⇒ ideal for the Batch API (50% off in+out). Build submit‑JSONL → poll → download → join‑to‑commit; `TriageDecisionV1` already separates request from result and `DecisionCache` keys map cleanly. Per‑line batch errors slot into the `parser_status`/null‑verdict design. **The adjudicator cannot batch** (multi‑turn tool loop) — keep it synchronous.

### 4.4 Grounding & repro
- **Resolve the D0‑vs‑D3 "production" contradiction** in `scan.py`; assert in a test that the eval runs the *same* `(prompt_id, prompt_hash, input_profile)` `scan` ships.
- **`data/pricing.json`** keyed by model (replace the hardcoded `ModelPricing(1.25,10.0,0.125)` at three sites) + a `--dry-run` cost estimator that prints projected sync *and* batch spend from the real corpus size.
- **Fix the Python‑3.14 import break** (`pydantic … prefer_fwd_module`) that currently errors collection on 7 modules and blocks any live‑model run; add a clean‑interpreter CI job.

---

## 5. Execution plan — small first, then full

### 5.1 Pilot (smoke + directional signal) — do this first

**Goal:** prove the plumbing and see whether the *scientifically interesting effects show up directionally*, for the price of a lunch.

- **Corpus:** the existing ~306‑commit dev corpus (or a 300‑commit slice), positives + a small labelled negative set.
- **Grid:** `C0` vs `C2` × `M0` vs `M1` only (skip C3, skip M2), single model gpt‑5.4, **batch**, `reasoning_effort=none`.
- **Cost:** **~$20–50** (batch), minutes of wall‑clock once submitted.
- **What it validates (go/no‑go before spending on the full run):**
  1. Harness runs end‑to‑end and emits the §3.4 JSON with provenance;
  2. `msg_class` counts are sane and the keyword table doesn't mis‑stratify;
  3. **Directional H1/H2:** does `R(C2)−R(C0)` look large on `announced` and small on `quiet`, and does M1 shrink it? n≈300 gives ±~14pp per stratum — useless for publication, **ample to see a catastrophic gap** (`evals.md` §8.3);
  4. FPR arm plumbing produces a coverage‑corrected number with a CI;
  5. Re‑run is a cache hit (reproducibility);
  6. `--dry-run` batch vs sync estimate matches actual.
- **Gate to proceed:** non‑degenerate numbers, CIs computed, provenance recorded, cache reproduces, and the announced‑vs‑quiet gap is visible (or convincingly absent). If H2 already shows M1 collapsing the announced advantage at n=300, that's the headline finding validated in miniature.

### 5.2 Full run — once the pilot is green

- **Corpus:** paper‑scale (~3,000 positives + ~3,000 random negatives), temporal holdout frozen.
- **Grid:** full factorial (C0–C3 × M0/M1/M2 × strata) + secondary few‑shot/CoT cell + E10 probe; adjudicator A/B on the hard‑case set.
- **Cost (gpt‑5.4, repo pricing):** triage factorial **~$125 batched** (~$250 sync); adjudicator/cascade **~$600–800** (not batchable); **~$825 total** for a thorough single run, **re‑runs near‑free** (content‑addressed caches). Heavy consensus/codex cascade → ~$2–2.5k. Human labelling (~2–3 person‑days) and ~1–1.5 eng‑weeks are the real line items, not tokens.
- **Model sweep:** because the one‑shot arm is ~$125/model batched, comparing 3–4 models is ~$500 — do it, and report cost/time alongside quality (`prd.md` §6).

### 5.3 Ordering (critical path)

```
3.14 fix ─► corpus build ─► label negatives (parallel, human) ─► pilot (C0/C2 × M0/M1)
        │                                                             │ green?
        └─► redaction axis + E10 + batch path ──────────────────────►┴─► full factorial ─► freeze baseline ─► model sweep
                                                 C3 build ───────────►
```

---

## 6. What we expect to observe (and how we'll read it)

- **Recall:** `announced` high and profile‑insensitive; `quiet` lower; `empty` worst; `merge_noise` a diagnostic for the diff‑extraction path (should be ~0 if first‑parent diffing is correct — it is).
- **The message effect:** `R(C2)−R(C0)` large on `announced`, small on `quiet`; **M1 redaction collapses the announced lift** (⇒ H2, the leakage story). If instead the lift survives M1, context genuinely helps reasoning — a stronger, publishable positive.
- **The FPR cost:** `F` rises monotonically C0→C2→C3; the precision‑at‑1.5% tradeoff may be *net negative* for C3.
- **Base‑rate collapse:** every single‑stage cell sits at precision@1.5% in the single digits to low‑teens (⇒ H4).
- **Cascade recovery:** end‑to‑end precision@1.5% jumps to ~0.5–0.7 with the gates doing the work (⇒ H5) — the money slide.
- **A surprise worth watching:** a stratum where `R(C2) < R(C0)` (message *hurts* — the gin hint, H6). If it replicates, it's a clean, quotable finding.

Read against the **coded gate** (overall recall ≥0.95 AND `quiet` ≥0.90): the winner is the lowest‑cost profile that clears it. If *no* profile clears the gate on `quiet`, that itself is the result — the diff‑only checker is not sufficient for the silent population and the value has to come from the cascade, which is exactly what H5 tests.

---

## 7. Threats to validity (carried from `evals.md` §8, still binding)

- **GHSA positives aren't a random sample of security fixes** — they skew severe/library/packaged. Stratification controls the *message* confound, not the *diff‑shape* confound; state it wherever recall is reported.
- **Label noise** — untyped `WEB` refs that are context not fixes, single‑of‑multi‑commit refs, PR‑merge stand‑ins. Hand‑check ~50 positives; publish the noise rate as a recall ceiling.
- **The unmeasured population** — silent means unlabelled; retroactive disclosure is a proxy, not a solution. The 50‑item hand guardrail is the honesty check, not a substitute.
- **Contamination** — public, indexed, years‑old advisories. E10 + rolling post‑cutoff holdout are the only defence.
- **Optimisation drift** — recall‑only tuning has a degenerate optimum ("say yes more"); the recall and FPR arms must run in the *same* loop, every change producing both. `ablation.py` already reports both — keep it that way.
- **Language confounding** — Go‑deep, others shallow; report analyzer coverage per language beside every metric until non‑Go has a gold set.

---

## 8. Summary — what we will validate

1. **The grounding decision, defensibly:** which triage input profile Strata ships, chosen mechanically (lowest expected cascade cost among gate‑passers) at the **real 1.5% base rate**, on the **silent‑fix population**, using the **exact prompt `scan` runs.**
2. **Reasoning vs leakage:** whether added context (message/issue/PR) helps because the model reads code better or because it reads disclosure words — via the redaction axis. This is what turns "context helps" (the literature's leaky claim) into a defensible one.
3. **The base‑rate collapse and the cascade's recovery:** that single‑stage precision is unusable at 1.5% and that the gated two‑stage cascade recovers it — the architectural go/no‑go (H4/H5).
4. **Adjudicator strategy:** which stage‑2 configuration (chat/codex, A0/A1, single/consensus) earns its cost on hard reachability/direction/containment cases (H7), and the seam where tree‑sitter structure gets A/B'd.
5. **Two novel measured claims** the literature hasn't isolated: **H‑silent** (the diff‑only advantage is a function of how silent the fix is) and **H‑cascade** (recall‑first filter + precision‑first gated adjudicator is usable at real prevalence).

We validate all of this cheaply in a **~$20–50 pilot** that shows the effects directionally, then commit to a **~$825 full run** (batched where it counts) that produces publication‑grade numbers with CIs, contamination controls, and a reproducible provenance trail. The task is old; the honesty of the evaluation, the silent‑fix framing, and the gated cascade are what's new.
