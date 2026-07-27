# Strata — Product Requirements & Roadmap

**Status:** working PRD / strategy document
**Date:** 2026-07-27
**Companion documents:** `research.md` (roadmap & design rationale), `evals.md` (evaluation design). This PRD reconciles those two research documents with **what is actually in the tree today** and proposes the next increments.

> **Note on provenance.** `research.md` and `evals.md` were written *before* the implementation existed and reason from a description (they assume a Go codebase, `internal/git/cache.go`, etc.). The real implementation is **Python** (`src/strata`, `src/strata_eval`), targets any **OpenAI‑compatible** endpoint, and already ships a Codex‑sandbox adjudicator and tree‑sitter scaffolding. Wherever this PRD and those documents disagree on *what exists*, this PRD is authoritative; wherever they disagree on *what to build*, this PRD says so explicitly.

---

## 0. One‑paragraph framing

Strata turns a repository's commit history into a **compiled, evidence‑anchored security context**: a cheap recall‑first triage pass finds candidate security‑fix commits, a precision‑first tool‑using adjudicator confirms or rejects each with citations re‑read from git, and a deterministic compiler aggregates the survivors into an artifact a human *or an agent* can act on. The thesis is unchanged from `research.md`: *the history is a labelled corpus of a project's own failure modes, and a compiled summary of it makes the next review measurably better.* The pipeline that thesis requires is now largely built. What is thin is **measurement** — we can run the pipeline but we cannot yet say, with a number, how good triage recall or adjudicator precision is at the real ~1.5% base rate, grounded in the prompts we actually ship. Closing that gap is the spine of this roadmap.

---

## 1. What we've built (implementation inventory)

The pipeline, as it exists in code:

```
                    prefilter            triage              adjudicate            attribute            compile
  git history  ──►  (free, local)  ──►  (1 cheap call)  ──►  (tool-using)   ──►   (re-point +   ──►    (no LLM)   ──►  security-context.json
                    prefilter.py         triage.py            adjudicator.py       dedup)               context/          + agent_brief
                                         + D0..D3 profiles    or codex_adjudicator attribution.py       compiler.py
                                                              + consensus.py
```

### 1.1 Orchestration & storage
- **CLI `strata`** (`src/strata/__main__.py`): `import`, `resume`, `status`, `export`, `scan`. `scan` is the end‑to‑end "compile a security context" command (`--profile A0|A1`, `--adjudicator chat|codex`, `--sandbox`, `--max-cost`, `--max-candidates`, `--include-leads`).
- **CLI `strata-eval`** (`src/strata_eval/__main__.py`): `score` only (scores compiled artifacts against the frozen fixture).
- **Importer** (`importer.py`, `store.py`): local Git import with **resumable SQLite** checkpointing, run status, and stable JSONL exports (`triage`, `findings`, `manifests`). Cache/reuse identity includes the **prompt hash**, so editing a prompt correctly invalidates replayed verdicts (`_DefaultAdjudicatorStage` in `__main__.py`).
- **Git layer** (`git_repo.py`): bare‑mirror cache, **first‑parent diff extraction** (`git diff <parent> <sha>`), stable **`git patch-id --stable`**, `is_merge`/`parent_sha`, and the read‑only primitives the adjudicator drives (`read_range`, `blame`, `search`, `list_paths`, `history`, `resolve_revision`, `enumerate_shas`).

### 1.2 Stage 0 — deterministic prefilter (`prefilter.py`, `diffing.py`)
Free, local rejection before any inference, with per‑reason accounting (`empty_diff`, `no_first_party_source`, `docs_only`, `test_only`, `dependency_only`, `generated_vendor_only`, `binary_only`, `submodule_only`, `oversize`). Test‑only changes are **kept as a weak positive signal**, dependency bumps are **routed not dropped**. This is described in‑code as the largest single cost lever.

### 1.3 Stage 1 — triage (`triage.py`, `prompts/triage/current-diff-only-v1.*`)
One cheap chat call per admitted commit. The shipped prompt is **diff‑only, one‑word YES/NO**, frozen byte‑for‑byte (`current-diff-only-v1`, `immutable: true`). Input profiles `D0..D3` let the *same* prompt see raw diff (D0), normalised first‑party diff (D1), subject+diff (D2), or full message+diff (D3). Output is a provenance‑bearing `triage-decision-v1` where a backend failure yields a **null verdict** that can never masquerade as `NO`. Reasoning models (gpt‑5+/o‑series) are handled (`max_completion_tokens`, temperature gating in `llm.py`).

### 1.4 Stage 2 — adjudication (two interchangeable backends)
Both emit the same `finding-v1` and pass through the **same validator and gates**.
- **Chat backend** (`adjudicator.py`): a bounded tool loop over nine read‑only tools (`show_commit`, `show_diff`, `read_blob`, `read_range`, `cite`, `search`, `list_paths`, `history`, `blame`; plus `linked_artifact` for profile A1). Evidence is produced **only** through `cite`, which re‑reads the bytes from git and returns a ready‑made anchor — hand‑written anchors are rejected, which killed the largest source of lost findings (right text, wrong line offsets).
- **Codex backend** (`codex_adjudicator.py`): the same contract inside a **read‑only sandboxed worktree** with a real shell (`rg`, `sed`, `git log -S`, and — in write mode — `semgrep`, `go vet`, `gopls`). It answers *containment* and *reachability* by looking rather than inferring. Every command is recorded in the audit trail; `approval_mode=deny_all`; hard wall‑clock deadline.
- **Consensus** (`consensus.py`): N‑round majority voting over either backend (temperature 0 is not determinism at the ~1.5% base rate). The winning decision is the **best‑anchored real answer** among the majority, not a synthetic merge.

The gates are the interesting part and are enforced, not requested: **`reachability_delta` must be `narrows`** (a commit that widens the attacker surface is the commit that *created* it), **`failure_containment: contained` cannot be a fix** (a panic the runtime absorbs is hardening), a **closed 14‑value L0 class enum**, a **pinned CWE‑4.20 catalog** (`data/cwe-catalog-4.20.json`, 969 weaknesses), and **no chain‑of‑thought fields**. Language‑specific answers to those gates live in `prompts/adjudicator/lang/{go,python,javascript}.md` (`recover()` can't catch a Go fatal abort; a C‑extension segfault in Python; an unhandled rejection kills a Node process) and are appended by `language.py` — today to the **sandbox/codex** prompt.

### 1.5 Attribution & de‑duplication (`attribution.py`)
Before compiling, findings are re‑pointed off merge commits onto the authoring child (first‑parent walk + content disambiguation by cited span), collapsed by patch‑id (cherry‑picks/backports/merge pairs), and merge‑ancestry duplicates folded — with anchors **re‑verified at the destination** and the move declined if a span no longer matches. In the four‑repo matrix, 3 of 5 false positives came from merges; this is the fix.

### 1.6 The artifact (`context/models.py`, `compiler.py`, `narrative.py`)
`SecurityContext` (`security-context-v1`) is **compiled deterministically** from validated findings — every count, ranking, hotspot and coverage number is computed by code, no LLM in the aggregation. Contents:
- **`fingerprints`** — adjudicated fixes anchored to code (class, CWE, components, sink symbols, invariant, `still_applies`, reachability/containment provenance, attribution provenance).
- **`shared_surfaces`** — invariants stated as *guard + entry points + violation hint*.
- **`top_risks`** — recency‑weighted (class, component) pairs.
- **`remediation`** — a coverage number that ships its **own formula and definition** (a direct answer to the "under‑defined headline metric" credibility gap in `research.md` §2.5).
- **`leads`** — unfixed sink matches; **dual‑use, withheld unless `--include-leads`.**
- **`agent_brief`** — a deterministic, agent‑ready hunt protocol (see §8); the only model‑written field is a one‑paragraph `summary`, with a deterministic fallback.

### 1.7 Evaluation machinery (`src/strata_eval/`, `scripts/`)
- **Frozen fixture** (`truth.py`, `tests/fixtures/matrix-truth.json`): commit‑level roles for four Go repos (`gin-gonic/gin`, `grpc/grpc-go`, `buger/jsonparser`, `getkin/kin-openapi`), adjudicated by LLM panels. Scoring is free and takes milliseconds; `strata-eval score` reports per‑repo/total precision, recall, and an `unscored` bucket for findings outside the fixture.
- **Low‑prevalence metrics** (`metrics.py`): Wilson intervals, exact zero‑event upper bound, **precision‑at‑prevalence** and **alerts‑per‑1000**, expected cascade cost, per‑stratum summaries, and a **coverage‑corrected FPR** (uncovered negatives don't get to silently deflate FPR).
- **GHSA corpus tooling** (`corpus/bundle.py`, `corpus/keywords.py`): loader + stratifier for a GHSA bundle, `msg_class ∈ {announced, quiet, empty, merge_noise}`, a **versioned, boundary‑safe** keyword table (the `rce`‑inside‑`enforce` bug is fixed and documented), plus an `announcement_strength` axis and a `diff_leaks_disclosure` check.
- **Contamination control** (`splits.py`): grouped **and** temporal holdout assignment with union‑find over advisory/patch/backport links, stable hashing, and a temporal cutoff.
- **Announcement‑dependence** (`redaction.py`): M0/M1/M2 message conditions sharing the *same* keyword table as stratification.
- **A/B harness** (`scripts/ab_adjudicator.py`): runs either stage‑2 backend over the fixture and reports precision/recall/abstain/cost/latency/tool‑calls, with `--consensus`, `--compare`, and `--cascade` (proposer→confirmer) modes.

### 1.8 LLM plumbing (`llm.py`, `env.py`)
OpenAI‑compatible client with **domain‑aware retry classification** (oversize/quota are terminal, transient 429s back off), a pre‑emptive token‑window rate limiter, cache‑aware `TokenUsage`, `ModelPricing`, and correct handling of the reasoning‑model families.

---

## 2. What works, what doesn't, what to improve

| Area | State | Note |
|---|---|---|
| Prefilter → triage → adjudicate → compile cascade | **Works** | End‑to‑end via `strata scan`; funnel is reconcilable (every dropped commit has a reason). |
| Evidence anchoring (`cite`) + gate enforcement | **Works, and is the moat** | Anchors re‑read from git; `narrows`/containment gates measurably separate real fixes from hardening (in‑code: 4/4 unrecoverable real, 0/19 contained real). |
| Merge handling / attribution / dedup | **Works** | First‑parent diffs + patch‑id dedup + merge re‑pointing. Resolves `evals.md` §4.4's biggest trap. |
| Closed taxonomy + pinned CWE catalog | **Works** | 14‑value L0 enum, CWE‑4.20 pinned & validated, OOV rejected not coerced. |
| Two adjudicator backends + consensus | **Works** | Chat and Codex share one validator; consensus wraps either. |
| Compiled artifact + `agent_brief` | **Works** | Deterministic aggregation; agent‑consumable brief already exists. |
| **Tree‑sitter / real static analysis** | **Scaffolded, not wired** | `tree-sitter-language-pack` is a dependency and `TreeSitterAnalyzer` exists, but it is an availability probe with **no runner** — symbol anchoring today is regex `text_fallback` (`SymbolAnchor.confidence="heuristic"`). This is the single biggest "declared but unbuilt" item. → §7. |
| **Eval surface vs. the real pipeline** | **Built but scattered / ungrounded** | Three disjoint entry points: `strata-eval score` (end‑to‑end, 4‑repo fixture), `python -m strata_eval.ablation` (the real **triage recall/FPR/precision‑curve** arm over D0–D3, with the `quiet`‑recall gate), and `scripts/ab_adjudicator.py` (stage‑2 A/B). They aren't consolidated under one CLI, aren't pinned to a single "production" triage profile, and the ablation needs a GHSA bundle that **isn't in the repo**. → §3. |
| Triage prompt grounding | **Inconsistent** | `scan.py` contradicts itself: the `ScanConfig` docstring says *"D0 … is production"* (and defaults to D0) while the stage‑1 comment says *"Production uses D3."* We do not currently measure the exact profile+prompt `scan` runs. → §3.2. |
| Language coverage | **Go‑deep, others shallow** | Real gold set + appendix depth is Go‑only; `python`/`javascript` appendices exist but have no gold set; non‑Go repos in `research.md` ran at L0 while reporting higher grounding. |
| Cost/latency accounting | **Present, not persisted** | `TokenUsage`/`ModelPricing`/scan funnel expose cost, and `ab_adjudicator` reports it, but there is no persisted `scan_runs` cost table or eval cost report. → §6. |
| Reproducibility on a fresh sync | **Currently broken on 3.14** | `uv run pytest` errors at collection on 7 modules: `pydantic … _eval_type() got an unexpected keyword argument 'prefer_fwd_module'` — a Python‑3.14 × pinned‑pydantic/openai typing incompatibility. Pure‑Python tests (corpus, metrics, static analysis, prefilter) collect fine. Not a logic bug, but it means the "hermetic suite" doesn't run clean on a clean checkout. → §9. |
| VCC / introducing‑commit attribution | **Not started** | `attribution.py` re‑points *fix* commits; there is no introducing‑commit layer yet (correctly deferred per `research.md` §3.4). |

**Improvement themes that recur below:** (a) make the eval *runnable end‑to‑end and grounded in the shipped prompts*, (b) *wire* tree‑sitter rather than scaffold it, (c) *persist* cost/latency so model comparisons are one command, (d) pin a dependency set that imports under 3.14.

---

## 3. Evals — match the scenarios of our real pipeline

This is the request that reorders everything else: *adjust evals so they match the different scenarios of our pipeline, grounded to the actual prompt we use for commit filtering.*

### 3.1 Where we are
More is built than is obvious, but it's scattered across three entry points that don't share a CLI, a "production" definition, or a corpus:
1. `strata-eval score` — scores a **compiled artifact** end‑to‑end against the 4‑repo fixture. Conflates prefilter+triage+adjudicate+compile into one number; can't attribute a regression to a stage.
2. **`python -m strata_eval.ablation`** — the *real* triage arm. It runs the shipped diff‑only prompt over input profiles **D0–D3**, computes recall, **coverage‑corrected FPR**, and the **precision curve at π∈{0.2%, 1.5%, 5%}** (`metrics.precision_interval_at_prevalence`), stratifies by `msg_class`, and even enforces the `evals.md` gate (overall recall ≥0.95 **and** `quiet` recall ≥0.90). This is E1+E2 in code, grounded in the actual prompt — but it lives outside the `strata-eval` console script and reads a **GHSA bundle that isn't checked in** (`--bundle ghsa-commits`, gitignored).
3. `scripts/ab_adjudicator.py` — measures **stage 2 in isolation** (chat vs codex) over the fixture, with `--consensus`/`--compare`/`--cascade`. Good and stage‑isolated, but a standalone script.

So the evaluation design of `evals.md` (E1 recall‑by‑stratum, E2 FPR + precision curve, E3 announcement‑dependence via `redaction.py`, E4 context‑level, E9 cost) is **substantially implemented** — the missing pieces are *consolidation*, *grounding to one production profile*, and *shipping the corpus data*, not building the statistics from scratch.

### 3.2 The grounding gap (the specific ask)
The commit‑filtering prompt we ship is `current-diff-only-v1` (diff‑only YES/NO), driven at a chosen input profile. But:
- The eval never runs that prompt over a labelled set and reports **stratified recall + FPR at real prevalence** — it only sees triage's effect indirectly through the compiled artifact.
- `scan.py` itself disagrees about which profile is production (D0 vs D3). **We cannot claim a grounded triage number while the code disagrees with itself about what production is.**

**Action T‑0 (half a day, unblocks everything):** resolve D0‑vs‑D3, make `ScanConfig.triage_profile` the single source of truth, and assert in a test that the eval's triage arm uses the *same* `(prompt_id, prompt_hash, input_profile)` that `scan` uses. Emit that triple in every eval report (the reporting template in `evals.md` §11.1 already has the slot).

### 3.3 A scenario‑matched eval matrix
Map every runnable stage to an experiment that uses the **exact artifact** that stage runs, and expose each as a `strata-eval` subcommand:

| Pipeline stage (real code) | Eval that grounds it | Ground truth | New CLI |
|---|---|---|---|
| Prefilter (`prefilter.py`) | Reduction rate + **positive‑leakage** (did we drop a real fix?) | GHSA positives + fixture | `strata-eval prefilter` |
| Triage `current-diff-only-v1` @ Dx | **Recall by `msg_class` stratum** + **FPR** + precision curve at π∈{0.2%,1.5%,5%} | GHSA `ghsa-vfd` positives (recall arm) + random repo commits (FPR arm) | `strata-eval triage` |
| Triage message dependence | `R(M0) − R(M1)` on `announced` (`redaction.py`) | GHSA `announced` stratum | `strata-eval triage --ablate message` |
| Adjudicator chat/codex @ A0/A1 | Precision/recall/**abstain**, per‑gate behaviour | fixture (now) → GHSA holdout (later) | fold `ab_adjudicator` into `strata-eval adjudicate` |
| End‑to‑end cascade | Cascade precision/recall + **alerts/1000** + **reviewer‑hours/TP** | fixture + FPR arm | `strata-eval cascade` |
| Compile | Coverage formula reproducibility; two runs byte‑identical mod `build` block | self | `strata-eval compile-check` |

The two arms that matter most (from `evals.md` §5.2) are **recall over GHSA positives** (every positive is a TP by construction — zero labelling) and **FPR over random repo commits** (only the flagged subset needs adjudication — ~60–150 items). Precision at any prevalence then follows analytically (`metrics.precision_at_prevalence`, already implemented). The **headline number** is *recall on the `quiet` stratum at the FPR‑matched operating point*, exactly as `evals.md` §6.3 argues — because `quiet` is the silent‑fix proxy and pooled recall can be gamed by keying on announcements.

### 3.4 Concretely, to make the design runnable end‑to‑end
1. **Ship (or generate) the `ghsa-vfd` bundle.** The loader/stratifier (`corpus/bundle.py`) and the arm that consumes it (`strata_eval.ablation`) both exist; the bundle itself (`advisories.jsonl` + `commits.jsonl` + `.diff` tree) is gitignored and not present, so today the arm has nothing to run on. Add a `strata-eval corpus build` command that produces it from a shallow `github/advisory-database` clone, resolving SHAs through the existing bare‑repo cache (no GitHub API rate limit — the pilot in `evals.md` §3.6 failed at n=12 precisely because it used the API).
2. **Promote `strata_eval.ablation` into `strata-eval triage`** — same statistics, but under the umbrella CLI, and reading the `(prompt_id, prompt_hash, input_profile)` triple from T‑0 so the arm provably runs the profile `scan` ships (not a hardcoded default).
3. **Fold `ab_adjudicator` into `strata-eval adjudicate`** and emit the operating‑point JSON (`evals.md` §11.1) from both arms.

**Definition of done for this section:** `strata-eval triage --corpus ghsa-vfd` prints `quiet` recall with a CI, FPR with a CI, and the precision curve — provably using the same prompt+profile `scan` ships.

---

## 4. Does GHSA keep paying? Keep labelling & improving it? Community value?

**Short answer: yes to all three, with one scope discipline.**

**Why GHSA keeps paying.** The single most valuable empirical result in `evals.md` (§3.6) is that GHSA‑referenced commits are *substantially silent themselves*: in the (small) pilot, ~67% of fix commits carried no security language, and the commit→advisory lag had a p75 of ~1,871 days. That means **GHSA is not merely a corpus of announced fixes — it is a large, retroactively‑disclosed silent‑fix corpus**, which is exactly the population Strata claims to serve and which no public dataset isolates. It gives us, for free:
- a **recall arm with zero labelling** (every referenced fix commit is a TP by construction);
- **CWE labels** to score `l0_class`/`cwe_id` against something other than model self‑report;
- **multi‑commit advisories** (21% of reviewed advisories with commit links) to ground `fix_completeness`;
- a **temporal cutoff** for contamination control (`splits.temporal_holdout_assignments`).

**Keep labelling/improving — yes, but the highest‑leverage labelling is not GHSA.** GHSA positives are self‑labelling; the effort should go to (a) the **stratification quality** (the versioned keyword table in `corpus/keywords.py` — keep it hand‑validated and version‑bumped, it directly sets the denominator of every stratified recall number), and (b) a **small hand‑labelled `quiet` guardrail** (`evals.md` §8.3: n≈50, one day) to confirm GHSA recall transfers to genuinely‑silent fixes. GHSA is the cheap corpus; the guardrail is the honesty check. Do both.

**Scope discipline:** GHSA is *useless for VCC / introducing‑commit* ground truth (`evals.md` §3.2c — zero `GIT` ranges, zero introducing‑commit references). When we get to Phase 2, VCC truth comes from OSV's kernel conversion + `vulns.git` + V‑SZZ, **not** GHSA. Don't stretch GHSA past fix‑detection and completeness.

**Community value — genuine, and a cheap way to build credibility.** Two shippable community artifacts fall out of work we'd do anyway:
1. **The `ghsa-vfd` index** (a few MB: `(host, repo, sha)` fix‑commit pairs with `msg_class`, `lag_days`, resolved/unresolved, `n_in_advisory`). No public dataset ships GHSA *stratified by whether the commit is silent*. Publishing it (data + build script) is a small, defensible open‑source contribution and a magnet for the exact users we want.
2. **The silent‑fix framing itself** — "silent fixing is *policy*, not sloppiness" (`evals.md` §2.1) — is a positioning asset. A short write‑up with the stratified numbers is more persuasive than any benchmark table.

**Recommendation:** treat GHSA as a **maintained internal dataset with a public index**. Add `strata-eval corpus build/refresh`, version the keyword table, keep the 50‑item guardrail running in parallel, and publish the stratified index once T‑0/§3 land.

---

## 5. Introduce Codex to evals (a short scenario suite)

We already run Codex as a stage‑2 backend (`codex_adjudicator.py`) and can already A/B it against the chat backend (`ab_adjudicator.py --backend codex`). The ask is narrower and correct: **run Codex through the eval on a *few* scenarios**, kept short because the sandboxed run is slow (~200s/candidate, "roughly six times the latency" per the CLI help).

**Proposal — `strata-eval adjudicate --backend codex --suite tiny`:** a fixed, curated **8–12 commit** suite chosen to exercise the gates the sandbox is supposed to win on, not to estimate a population rate:
- 2–3 **containment** cases (a runtime abort `recover()` can't catch vs. a contained panic) — the Go appendix's `fatal error: concurrent map writes` family.
- 2–3 **direction** cases (an *introducing* commit that answers `narrows` under chat — e.g. the grpc‑go `39f16539d2` case called out in the A0/A1 prompt notes — where a shell can run `git log -S` and get it right).
- 2–3 **reachability** cases (library‑API trust boundary; the CVE‑2023‑29401 case the prompt notes say the sandbox handled).
- 1–2 **cross‑request/concurrency** cases.

Each scenario runs chat vs. codex (single‑shot, no consensus, to keep the adjudicator‑panel time bounded) and reports **per‑case verdict, gate values, tool/command count, latency, cost**, plus a one‑line "why they differed." This is a **qualitative capability probe**, explicitly *not* a precision estimate — the write‑up should say so, mirroring how `evals.md` §3.6 caveats its own n=12 pilot. Twelve commits × two backends × ~200s is a ~40‑minute run, which is the "shorter one, not many artifacts" the request asks for.

**Why this is worth it now:** the prompt notes already contain measured claims about where the sandbox helps and hurts (the `v8` reachability paragraph regressed chat 78%→63% but "belongs in the sandboxed backend's own guide, where the model can actually check a call graph"). A tiny, gate‑targeted Codex suite turns those anecdotes into a reproducible fixture — and it's the natural place to later plug tree‑sitter (§7) and see the reachability cases move.

---

## 6. Baseline, then benchmark both stages across models (cost & time)

Once §3 lands and we're happy with the numbers, freeze them as a **baseline** and sweep models on **both** stages.

**What "freeze a baseline" means concretely:** a `results/baseline/` bundle containing (a) the `strata-eval triage` operating‑point table, (b) the `strata-eval adjudicate` fixture report, (c) the `ghsa-vfd` bundle version + keyword‑table version, and (d) the prompt hashes. `truth.ScoreReport.diff_against` and `ab_adjudicator --compare` already render deltas against a saved report — so "did this change help?" is already a one‑liner once a baseline file exists.

**The sweep.** Both stages take model identity from config today (triage via `OPENAI_MODEL`; `ab_adjudicator` via `STRATA_MODEL`, default `gpt-5.4`). Add a thin `strata-eval sweep --models a,b,c` that runs each stage per model and emits one comparison table:

| Stage | Metric per model | Cost/time per model |
|---|---|---|
| Triage (`current-diff-only-v1` @ Dx) | `quiet` recall, FPR, precision@1.5% | $/1k commits, ms/commit, cache‑hit rate |
| Adjudicate (chat, A0) | precision, recall, abstain rate | $/candidate, s/candidate, mean tool calls |
| Adjudicate (codex, A0) | precision, recall, abstain rate | $/candidate, s/candidate, mean commands |
| Cascade (triage→adjudicate) | end‑to‑end P/R, **alerts/1000**, **reviewer‑hours/TP** | **expected $/commit** (`metrics.expected_cascade_cost`) |

Two things must be built to make this honest:
1. **Persist cost/latency.** Add token/cost/wall‑clock columns to the run store (`research-addendum` §4.5 in spirit) so `strata-eval sweep` reads them instead of re‑deriving. The estimator (`ModelPricing`, cache‑aware) already exists; it just isn't persisted per run.
2. **Per‑model pricing.** `ModelPricing` is currently hard‑coded to one triple (`1.25, 10.0, 0.125`) at every call site (`scan.py`, `__main__.py`, `ab_adjudicator.py`). Move it to a small `data/pricing.json` keyed by model so a sweep prices each model correctly.

**The economic frame to report** (`research.md` §3.2): stage 2 only sees ~1–13% of commits, so it can afford 30–100× the per‑commit spend — the sweep should surface **expected $/commit for the whole cascade**, not per‑call cost, because that is the number that decides whether a 124k‑commit import costs \$250 or \$6,000. `metrics.expected_cascade_cost` computes exactly this; wire it into the sweep output.

---

## 7. Tree‑sitter for adjudication — deep dive & technical proposal

This is the highest‑value technical increment, and the codebase is *primed* for it: the abstraction is already there, only the runner is missing.

### 7.1 What exists today
`static_analysis.py` defines an `Analyzer` protocol and an `OptionalToolAnalyzer` that **probes availability and refuses to fabricate findings** (status `available_not_run` when no runner is injected). `TreeSitterAnalyzer`, `AstGrepAnalyzer`, `CodeQLAnalyzer`, `JoernAnalyzer` are all declared. `tree-sitter-language-pack` is a **hard dependency**. But no runner is wired, so:
- **Symbol anchoring** (`hunk_to_symbol`) is regex per language and self‑labels `confidence="heuristic", method="text_fallback"`.
- **"Similar call sites"** (`search_similar_call_sites`) is a **textual** call‑name match — it will match a method call, a definition, a string, and a comment alike.
- The adjudicator's `search` tool is repository **text** search; there is no symbol‑ or call‑graph‑aware tool.

So the injection points exist (`OptionalToolAnalyzer(runner=…)`, the adjudicator tool allowlist), and the outputs that would consume real parsing (`SymbolAnchor`, `Fingerprint.sink_symbols`, `SharedSurface`) already exist.

### 7.2 Why tree‑sitter, ranked by ROI (from `research.md` §7, made concrete)
1. **Hunk→symbol anchoring that is correct across renames.** Every `Fingerprint`/anchor needs `{path, symbol, line_range}` at a revision *and* a mapping to HEAD. Regex gets C++ member functions, generics, and decorators wrong; a real parse gets the enclosing named node. This is a *hard dependency* for scoped invariant retrieval and for `still_applies`.
2. **A deterministic pre‑filter upgrade.** Today `hunk_is_comment_or_whitespace_only` compares normalised text. With tree‑sitter we can parse both sides and reject on **AST‑equal** changes (formatting, comment‑only, import reordering) with far fewer false negatives — free precision on the cost lever.
3. **A real "similar sites" / sink‑inventory tool.** Replace textual call matching with a tree‑sitter **query** ("call to `X` whose receiver is `Y`", "index expression without a preceding bounds check"). This is what turns `leads` and `sink_symbols` from grep output into something an adjudicator can trust.
4. **Sharper `still_applies` / Theseus folding.** The compiler already sets `Fingerprint.still_applies` line‑level (`compiler._still_applies`). Tree‑sitter upgrades it from "do these lines still exist" to "does the enclosing *symbol* still exist and still contain the guard," which is the version that survives a refactor that moved the code.

Where tree‑sitter **stops**: no cross‑file types, no call graph, no dataflow. Those stay in the heavyweight tier (Joern/CodeQL/`gopls`), run **only** inside the adjudicator on the ~1–13% that survive triage — which is exactly the existing `write`‑mode Codex sandbox where `gopls references` and `semgrep` already live.

### 7.3 Proposed integration (minimal, reversible, measured)

**A. Land a real `tree_sitter` runner behind the existing seam.**
```python
class TreeSitterRunner:                       # injected into TreeSitterAnalyzer(runner=…)
    def __call__(self, request, availability): # tree_sitter_language_pack.get_parser(lang)
        return {"findings": {
            "hunk_symbols":  [...],  # enclosing named node per changed line, method="tree_sitter"
            "ast_equal":     bool,   # parse both sides; True ⇒ formatting/comment-only
            "sink_matches":  [...],  # results of versioned .scm queries per language
        }, "result_count": n, "external_processes": 0}
```
`SymbolAnchor` already carries `method`/`confidence`; a tree‑sitter anchor sets `method="tree_sitter", confidence="parsed"`, and the regex path stays as the **fallback** for languages without a grammar (the module's "a generic prompt beats a wrong one" principle). No interface changes; `run_ablation` already reports `tree_sitter` vs `text_baseline` side‑by‑side, so the win is measurable on day one (`evals.md` E4: L0 vs L1 vs L2).

**B. Give the chat adjudicator a symbol‑aware tool.** Add `enclosing_symbol(path, line, revision)` and upgrade `search` with an optional `kind="symbol"` mode backed by the runner. This closes the gap the code already complains about ("the sandboxed backend's advantage here was mostly just being able to run `ls`") — the chat backend gets structure without a shell.

**C. Feed structure into the sandbox prompt.** In `codex_adjudicator.py`, prepend a tree‑sitter‑derived **anchor sheet** (enclosing symbols of the diff, sink matches) to the task so the model starts from parsed structure instead of re‑deriving it with `sed`. This is the concrete place the reachability regression note points to ("where the model can actually check a call graph").

**D. Ship language sink queries as data.** `prompts/adjudicator/lang/` is the existing per‑language home; add `queries/<lang>/sinks.scm` next to it, versioned like the keyword table, so adding a sink family is a data edit, not a code change.

### 7.4 How this couples to the Codex‑eval work (the request's insight)
The request's instinct is right: **with a Codex adjudicator eval in place (§5), tree‑sitter becomes trivially A/B‑able.** Run the tiny gate suite with tree‑sitter structure off vs. on and watch the *reachability* and *direction* cases specifically — those are the ones a parsed call graph should move, and they're already the suite's backbone. The `run_ablation` arms and the `ab_adjudicator --compare` delta view give the before/after for free. Sequence: **§5 (Codex tiny suite) → §7A/C (tree‑sitter runner + anchor sheet) → re‑run the suite → keep it if reachability cases improve without precision loss elsewhere.**

**Gate for adopting tree‑sitter:** it must (i) raise anchor `method="tree_sitter"` coverage on Go/Python/JS above ~90% of changed hunks, and (ii) not regress fixture precision. Cheap to check, because both numbers already have a home in the report.

---

## 8. What comes next (high level): security context → automated analysis

Today the pipeline **identifies** latent security issues and **compiles a security context an agent can consume**. The request asks whether the next step is to *take that context and run an automated analysis of the codebase*. **Yes — and the artifact was already built for it.** `context/narrative.py::build_agent_brief` deterministically emits a hunt protocol that:
- lists **shared guards that must hold on every entry point** ("one bypassed path is a live bug"),
- lists **hot components + known dangerous symbols** to review first,
- and states the discipline that *re‑confirming an already‑fixed bug is **not** a finding; an unguarded variant or a novel flaw **is**.*

That is precisely the input to a discovery agent. The next product is the **consumer**:

**"Strata Hunt" — a repo‑sweep consumer.** A bounded agent (reuse the sandboxed, read‑only, no‑network worktree pattern from `codex_adjudicator.py`) that takes `agent_brief` + `shared_surfaces` + `leads` and, at HEAD:
1. for each shared surface, traces every entry point and checks the guard is actually reached (the highest‑yield check the brief already specifies);
2. for each `lead` (unfixed sink match), attempts to show attacker‑controlled input reaching it without the guard;
3. emits **candidate findings in the same `finding-v1` shape**, which then go through the *same adjudicator/gates* — so a Hunt finding is held to exactly the standard a history finding is, and false positives die at the `narrows`/containment gates.

This closes the loop the thesis needs: history → context → **new** findings → (adjudicate) → context. And it is *directly measurable* — it is `research.md`'s E6/E7 (does the artifact produce lift over no‑context and over a generic CWE checklist?) with an execution‑verified oracle. Two design rules carry over verbatim: (a) **Profile B discipline** — the Hunt consumer must never see advisory/CVE/future info, or the offline number won't transfer; (b) **gate the `leads`** — this is the dual‑use surface and stays behind `--include-leads`/auth.

**Sequencing:** ship Hunt *after* §3's numbers exist, because Hunt's value proposition ("invariants produce lift") is exactly what E6/E7 test — building the consumer before we can measure lift repeats the mistake the whole project is trying to avoid.

**Beyond Hunt (later, `research.md` Phase 5):** PoC validation calibrated on ARVO/CyberGym first, and the distillation flywheel (adjudicated verdicts → fine‑tuned cheap triage model). Both are correctly deferred until the retrospective numbers are trustworthy.

---

## 9. Other features — nice‑to‑have and important

**Important (do soon):**
- **Fix the fresh‑checkout test break.** Pin a `pydantic`/`openai` combination that imports under Python 3.14 (or widen `requires-python`). The "hermetic suite" is a core selling point; it must run clean on `uv sync && uv run pytest`. Add a CI job on a *clean* interpreter so this can't regress silently.
- **Persist run cost/latency** (prerequisite for §6) — token/cost/wall‑clock per stage per run in the SQLite store.
- **Single source of truth for the production triage profile** (§3.2) — remove the D0/D3 contradiction and assert eval‑vs‑scan parity in a test.
- **MCP delivery of the artifact** (`research.md` §2.5/§3.3). The artifact is designed for tool‑call consumption (`get_security_context`, `get_invariants(paths[])`, `get_leads`); shipping it over MCP makes it usable by an agent without a human pasting a file, and path‑scoped `get_invariants` is the mechanism that turns a PR‑gate question from "is this diff vulnerable?" into "does it violate invariants I–J?".

**Nice‑to‑have (real value, not on the critical path):**
- **Incremental scan** — the store is resumable; add "adjudicate only commits since `head_sha`" so re‑scans are cheap and the artifact compounds.
- **Artifact diff / eval console** (`research.md` §9) — a small static page that diffs two artifacts (findings only in A/B, α/κ agreement by class) and surfaces the disagreement queue as a labelling UI. This is also the ground‑truth factory that feeds the §4 guardrail.
- **CWE hierarchy‑aware scoring** — score `cwe_id` with tree distance, not just exact match (the pinned catalog already records `ChildOf` parents, per `data/README.md`).
- **Multi‑commit completeness (E7)** — the schema already has `fix_completeness`; the GHSA multi‑commit advisories (21%) are the ground truth. Cheap given the corpus.
- **Severity provenance hygiene** — `finding-v1.severity.source` already separates `model_estimate` from `cvss`/`advisory`; keep the compiler from ever blending them (the `research.md` §5.7 warning).
- **Fixture growth beyond Go** — a small Python and a small JS gold set so the `python`/`javascript` appendices are measured, not assumed.

---

## 10. Prioritized roadmap

| # | Item | Why now | Depends on | Rough effort |
|---|---|---|---|---|
| 1 | Fix 3.14 import/test break; clean‑interpreter CI | Everything else assumes a runnable tree | — | hours |
| 2 | **T‑0**: single production triage profile + eval/scan parity test | Can't claim a grounded triage number otherwise | — | half day |
| 3 | `strata-eval corpus build` → ship `ghsa-vfd` bundle | Unlocks recall/FPR arms with zero labelling | — | 1–2 days |
| 4 | `strata-eval triage` (recall‑by‑stratum + FPR + precision curve) | **The number that reorders priorities** (§3) | 2,3 | 1–2 days |
| 5 | Fold `ab_adjudicator` into `strata-eval adjudicate`; persist cost/latency | Stage‑2 measurement + §6 prerequisite | — | 1 day |
| 6 | 50‑item hand‑labelled `quiet` guardrail (parallel, human) | Confirms GHSA recall transfers to silent fixes | 3 | 1 day human |
| 7 | Codex tiny gate suite (`--suite tiny`) | Turn sandbox anecdotes into a fixture (§5) | 5 | 1 day |
| 8 | **Tree‑sitter runner** + anchor sheet into sandbox (§7A/C) | Correct anchors + reachability lift, A/B‑able via 7 | 5,7 | 2–3 days |
| 9 | `strata-eval sweep --models` + `data/pricing.json` | Baseline + model/cost/time comparison (§6) | 4,5 | 1–2 days |
| 10 | Freeze baseline bundle; publish `ghsa-vfd` index + write‑up | Credibility + community (§4) | 4,5 | half day |
| 11 | MCP delivery of the artifact | Makes the artifact agent‑usable | — | 2 days |
| 12 | **Strata Hunt** repo‑sweep consumer + E6/E7 | The next product; measures the thesis (§8) | 4,8 | 3–4 weeks |
| — | Deferred: VCC attribution, PoC harness, distillation flywheel | Correct per `research.md` — after retrospective numbers | 4,12 | later |

Items 1–4 produce *the* number the project has been missing; everything downstream is built on it. Items 5–8 make measurement grounded and give tree‑sitter a place to prove itself. Items 9–12 turn a measured pipeline into a benchmarked, deliverable product.

---

## 11. Risks (carried from `research.md` §10, still live)

- **Base rates.** Precision at 1.5% prevalence is the make‑or‑break; the cascade + gates are the answer, and §3/§6 must report precision‑at‑prevalence, never dataset precision.
- **Contamination.** GHSA is public and old; keep the temporal holdout (`splits.py`) and a rolling post‑cutoff set as the honest number.
- **Optimisation drift.** Lock a test half never inspected during prompt tuning; the recall and FPR arms must run in the *same* loop or "say yes more" wins.
- **Dual use.** `leads` are an inventory of unfixed sites in live code — already gated; keep it gated, and never publish PoCs.
- **Language confounding.** Report analyzer coverage per language beside every metric until non‑Go has a gold set; tree‑sitter (§7) plus per‑language gold sets is the fix.

---

## Appendix — implementation map (for reviewers)

| Concern | Files |
|---|---|
| CLI | `src/strata/__main__.py`, `src/strata_eval/__main__.py` |
| Import/store | `importer.py`, `store.py` |
| Git | `git_repo.py`, `diffing.py` |
| Prefilter | `prefilter.py` |
| Triage | `triage.py`, `prompts/triage/current-diff-only-v1.*`, `schemas/triage-decision-v1.schema.json` |
| Adjudication | `adjudicator.py`, `codex_adjudicator.py`, `consensus.py`, `prompts/adjudicator/{a0-v1,a1-v1}.json`, `prompts/adjudicator/lang/*.md`, `language.py`, `schemas/finding-v1.schema.json` |
| Attribution | `attribution.py` |
| Artifact | `context/models.py`, `context/compiler.py`, `context/narrative.py` |
| Static analysis (tree‑sitter seam) | `static_analysis.py` |
| LLM/env | `llm.py`, `env.py`, `contracts.py`, `resources.py` |
| Taxonomy/CWE | `schemas/*`, `data/cwe-catalog-4.20.json`, `scripts/update_cwe_catalog.py` |
| Evals | `src/strata_eval/{truth,metrics,splits,redaction,ablation,manifest}.py`, `corpus/{bundle,keywords}.py`, `labeling/*`, `tests/fixtures/matrix-truth.json` |
| Benchmarks | `scripts/ab_adjudicator.py`, `scripts/scan_gin.py` |
