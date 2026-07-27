# Project Ideas — Evaluation

Two ideas are on the table for Strata:

1. **Migrating the codebase to Go.**
2. **A pluggable back end** — pick your harness (Codex, OpenCode, …), your model,
   and your execution sandbox (local, Modal, E2B, …).

This document evaluates both against the codebase as it actually stands today,
not against a generic "Go vs. Python" argument. The short version:

- **Idea 2 is a natural, high-value extension of seams that already exist.** Recommend
  doing it, incrementally. The single biggest win is not flexibility — it is moving the
  execution of *untrusted repository code* off the host into a disposable cloud sandbox.
- **Idea 1 is hard to justify as a full rewrite** for what Strata is (an LLM-latency-bound
  research pipeline whose value lives in prompts, the validator, and cascade economics).
  There are narrow, legitimate cases for Go, and a sensible middle path, both covered below.
- The two ideas interact: doing Idea 2 well *reduces* the marginal payoff of Idea 1,
  because it pushes the heavy compute out of the host process and leaves Strata as an
  orchestrator + validator — exactly the shape where a rewrite buys the least.

---

## Where Strata is today (the baseline both ideas are measured against)

Strata is a three-pass pipeline for discovering security-fixing commits:
**prefilter → triage → adjudication → context compilation.** Some numbers that
matter for both decisions:

| Fact | Value | Source |
|---|---|---|
| Core pipeline (`src/strata`) | ~12.7k LOC | `wc -l` |
| Eval harness (`src/strata_eval`) | ~5.3k LOC | `wc -l` |
| Tests | ~5.3k LOC across 21 files | `tests/` |
| Third-party deps | `openai`, `tiktoken`, `tree-sitter-language-pack` | `pyproject.toml` |
| Optional dep | `openai_codex` (imported dynamically) | `codex_adjudicator.py` |
| Concurrency model | `ThreadPoolExecutor`, no `asyncio` | `scan.py`, `importer.py` |
| Largest / most subtle module | `adjudicator.py`, 2.5k LOC | validation gates live here |

Two structural facts do most of the work in the analysis:

- **The workload is I/O-bound.** Wall-clock time is dominated by model latency — a single
  sandboxed adjudication legitimately runs ~200s because it is driving a real shell
  (`codex_adjudicator.py` sets `max_wall_clock_s=600`). The pipeline already gets its
  parallelism from threads over blocking network calls, and the GIL is released during
  that I/O. Strata is not CPU-bound and does not need more cores.
- **The value is in logic, not throughput.** What makes Strata *Strata* is the
  `validate_adjudication` gate (anchor re-verification against git bytes, the
  `reachability_delta` and `failure_containment` gates, the pinned CWE catalog, the closed
  L0 enum), the prompts, and the cascade economics tuned for ~1.5% base-rate prevalence.
  None of that is a performance problem.

---

## Idea 1 — Migrating to Go

### What it would actually mean

A faithful port is roughly an **18k-LOC rewrite** (12.7k core + a decision about the 5.3k
eval harness), plus re-porting ~5.3k LOC of tests. Broken down by difficulty:

**Mechanically portable (most of the code).** These are stdlib-on-stdlib and map cleanly:

- `git_repo.py` (1k LOC) shells out to `git` via `subprocess`; Go does the identical thing
  with `os/exec`, or uses `go-git`.
- `store.py` (1.2k LOC) is `sqlite3`; Go has `modernc.org/sqlite` (pure Go, no cgo) or
  `mattn/go-sqlite3` (cgo).
- `diffing.py` (0.7k, on the critical path), `prefilter.py`, `attribution.py`,
  `context/*`, `contracts.py`, and the CLI (`__main__.py`, `argparse` → `cobra`/`flag`)
  are pure logic and string handling.

**The genuinely hard part — the validator.** `adjudicator.py` (2.5k LOC) is the crown
jewel and the riskiest thing to move: it re-reads every evidence anchor from git and
byte-matches it, enforces the gates, and is backed by the densest tests in the repo. A port
is not "translate the syntax" — it is "re-establish, in a new language, a subtle contract
that took real measurement to get right" (the `llm.py` docstrings and the
`supports_temperature` comment are a record of how expensive those subtleties were). This is
where a rewrite most easily introduces a silent regression.

**The language-coupled pieces:**

- **`openai` SDK** → used only in `llm.py` and `codex_adjudicator.py`. Not a real blocker:
  `llm.py` already wraps the SDK in a *custom* retry/classification layer with
  `max_retries=0`, so the SDK is doing little beyond transport and typed responses. Go has
  OpenAI-compatible HTTP clients, and the domain-aware retry logic is hand-rolled anyway.
- **`tiktoken`** → used only in `llm.py` for *scheduling* estimates (explicitly "not
  billing"). Go ports exist (`pkoukk/tiktoken-go`) but lag on new encodings; the code
  already falls back to `o200k_base`, so approximate parity is acceptable.
- **`tree-sitter`** → this looks scary (cgo) but **is not on the critical path**:
  `static_analysis.py` (1k LOC) is imported *only by its own test*. It can be dropped from a
  first Go cut entirely, or kept in Python as a side tool. It is not a migration blocker.
- **`openai_codex`** → the one deeply Python-coupled dependency, and the sandbox harness for
  stage-2. **Idea 2 is precisely about abstracting this away** (see below), which is why the
  two ideas are entangled.
- **`strata_eval`** (metrics, ablation, splits, truth, corpus, rich labels; ~5.3k LOC) is
  research tooling that leans on Python's data/notebook ecosystem. The sane answer is *don't
  port it* — leave it in Python against the JSONL exports. But that means committing to a
  permanent two-language repo.

### Pros

- **Single static binary.** `go build` → one artifact, no `uv`/venv/interpreter to ship.
  This is the most concrete, real benefit for anyone running Strata as a CLI on other
  machines or in CI.
- **Long-running-service story.** If Strata's future is a hosted daemon scanning many repos
  concurrently, Go's goroutines + lower memory footprint + mature server tooling are a
  better fit than a thread-pool Python process.
- **Native integration** if the sandbox runtimes Strata drives are themselves Go/Rust
  (some agent runtimes are), letting you embed or link rather than subprocess.
- **Type safety at compile time** over a codebase that currently leans hard on runtime
  duck-typing and `dataclass` validation.

### Cons

- **No performance need.** The pipeline is I/O-bound; Go's core advantage (true parallelism)
  buys ~nothing on a workload that is waiting on model latency. This removes the usual
  headline reason to choose Go.
- **The GIL argument is already weak.** The repo targets **Python 3.14**, where free-threaded
  (no-GIL) builds are officially supported — so even a future CPU-bound need has a Python
  answer that isn't a rewrite. And today's thread pool over blocking I/O already scales fine.
- **Rewrite risk concentrates in the validator.** The highest-value, subtlest,
  hardest-won code is the most dangerous to reimplement. A regression there is a *quality*
  regression (wrong verdicts) that tests may not fully catch.
- **Ecosystem loss.** `tiktoken` fidelity, `tree-sitter` bindings, and the whole
  `strata_eval` research stack are cheaper in Python. A port either drags them along or
  splits the repo into two languages permanently.
- **Opportunity cost.** Every week spent porting is a week not spent on prompts, gates, and
  corpus — which is where Strata's accuracy actually comes from.

### Why would we? (the honest test)

Migrate to Go **only if** Strata's identity is shifting from *research pipeline* to
*distributed production service or a widely-distributed binary tool*, **and** that shift is
committed, not hypothetical. In that world the distribution and concurrency wins are real.
Absent that shift, the migration solves a problem Strata does not currently have.

### What it would imply

- A multi-month effort dominated by re-porting and re-validating `adjudicator.py` against the
  existing test corpus, run in parallel with the Python version until output parity is proven
  on the eval set (identical verdicts on the gin ground-truth set is the acceptance bar).
- A likely **permanent Python island** for `strata_eval` — accept the two-language repo, or
  budget to port the research tooling too (larger scope, weaker justification).
- Freezing prompt/gate changes during the port, or paying to keep two implementations in sync.

### Verdict

**Do not do a full rewrite now.** If the distribution pain is the real driver, the
proportionate move is the **middle path** below, not a port of the validator.

**Middle path (recommended if Go is attractive):** keep the pipeline and the validator in
Python, and introduce Go only where it earns its keep — e.g. a small Go *executor/harness
driver* (Idea 2's remote-sandbox component) shipped as a static binary, or a thin Go service
shell that invokes the Python pipeline. This captures the distribution/service benefits at
the boundary without risking the crown-jewel logic.

---

## Idea 2 — Pluggable harness / model / execution sandbox

### The key insight: the seams already exist

This is not greenfield. Strata *already* has three of the four pluggability axes, just not
factored as a clean, extensible interface:

- **Model is already pluggable.** Everything speaks an OpenAI-compatible endpoint via
  `(base_url, model, api_key)` (`env.py`, `llm.py`). Point it at OpenAI, Azure, a local
  server — no code change.
- **Harness is already dual-backed.** Stage-2 adjudication has *two* implementations behind
  `--adjudicator {chat,codex}` (`scan.py`, `__main__.py`): the eight-tool JSON `Adjudicator`
  (`adjudicator.py`) and the sandboxed `CodexAdjudicator` (`codex_adjudicator.py`). Both feed
  **the same** `validate_adjudication`.
- **Sandbox isolation is already parameterized.** `--sandbox {read-only, workspace-write,
  full-access}` maps to Codex's own modes and gates which tools are advertised
  (`_TOOL_CATALOG`, `_available_tools`).

So Idea 2 is a **generalization of an existing pattern**, which makes it far lower-risk than
it sounds. What it adds is a *fourth* axis and a real interface:

- **New axis — execution location.** Today the harness runs *locally*: a `tempfile` worktree
  next to the bare git mirror, driving local `rg`/`sed`/`semgrep`/`go`/`gopls`
  (`_worktree`, `_run_codex`). Idea 2 makes *where the investigation runs* a choice: local,
  Modal, E2B, Daytona, ….
- **New harnesses** — OpenCode, Codex, and others, as peers of the built-in `chat` backend.

### The invariant that must not break

`codex_adjudicator.py` states the design rule outright: *"The sandbox replaces how the model
investigates, never how a finding is validated."* Every backend, no matter how exotic, must
converge on the same output and pass the same gate:

- the model returns a JSON object matching `DECISION_SCHEMA`;
- every evidence anchor is **re-read from git and byte-matched on the host**, through the
  unchanged `validate_adjudication`.

This is what makes the idea safe: **the validator is the trust anchor and it stays home.** A
remote sandbox in Modal or E2B is only ever trusted to *investigate and propose*; the host
re-verifies every citation against local git bytes before a finding is real. A compromised or
buggy sandbox cannot manufacture a passing finding.

Also inherited from today's design: **triage stays a single cheap chat call and is
deliberately *not* switchable** — it is a one-bit decision over a diff and gains nothing from
a shell. The harness/sandbox abstraction applies to *adjudication only*.

### Proposed decomposition

The current `CodexAdjudicator` couples four concerns that Idea 2 wants orthogonal:
*where the code lives, what drives the model, which model answers, how it's isolated.*
Factor them into two interfaces around the existing worktree→investigate→collect→validate flow:

```
Executor   — provides an isolated, no-network checkout of the candidate commit and
             runs shell commands in it. Implementations: LocalWorktree (today's code),
             E2BSandbox, ModalSandbox, DaytonaSandbox.

Harness    — given an Executor + the prompt, drives a model to investigate and returns
             an Investigation{ answer_json, command_audit, usage }.
             Implementations: ChatEightTool (no executor needed), Codex, OpenCode, …

Backend    = Harness × Executor × Model, producing an Investigation that is fed —
             unchanged — to validate_adjudication on the host.
```

`--adjudicator` and `--sandbox` generalize to something like
`--harness {chat,codex,opencode}`, `--executor {local,e2b,modal}`, `--model …`. The `chat`
harness simply declares it needs no executor.

### Concrete back ends and the work each implies

| Axis | Options | Integration cost |
|---|---|---|
| **Harness** | Codex *(done)*, chat *(done)*, OpenCode, Claude Code, … | Per harness: adapt its output to `DECISION_SCHEMA` (Codex has `output_schema`; others need a JSON-shaping prompt + extraction) and adapt its command log to the `ToolAudit` trail. |
| **Executor** | Local worktree *(done)*, E2B, Modal, Daytona | Per executor: get repo *bytes* into the sandbox **without network** (ship a `git bundle`/archive of `parent..commit`, since the design forbids the sandbox from cloning), run commands, stream results back. |
| **Model** | any OpenAI-compatible *(done)*, harness-native | Mostly done; some harnesses pin their own model routing. |

### Pros

- **Off-host isolation of untrusted code — the strongest argument.** Strata scans *untrusted
  repositories*, and `workspace-write`/`full-access` modes run their build (`go build`,
  `semgrep`) on the host. Moving that into an E2B/Modal microVM is a genuine **security
  upgrade**, not just flexibility — a malicious repo can no longer touch the host.
- **Elastic scale.** Remote sandboxes let adjudication fan out past one machine's cores/disk
  without Strata owning the infrastructure.
- **Measurable harness/model comparison.** A clean interface makes "Codex vs. OpenCode vs.
  chat, at fixed model" and "model A vs. B, at fixed harness" first-class experiments — which
  is exactly the kind of question `strata_eval` exists to answer.
- **Low architectural risk.** It extends a proven seam and preserves the validator invariant,
  so a new backend can be wrong without producing a wrong *finding*.

### Cons / risks

- **Per-candidate latency and cost.** Remote sandboxes add cold-start + upload per candidate.
  Tolerable against a ~200s adjudication, but it argues for **reusing one sandbox per worker**
  across candidates rather than one microVM per commit, and for keeping local as the default.
- **Getting bytes in without network.** The no-network rule means each executor needs a
  bundle/archive path; that's the main new engineering, and it must not accidentally hand the
  sandbox more history than the candidate needs.
- **Harness output variance.** Harnesses without strict structured output need a
  prompt-engineered JSON contract + a tolerant extraction step (the repo already has
  `_prune_nulls` for exactly this class of problem).
- **Auth/secrets surface.** Each executor is another place the model provider key travels
  (today: `STRATA_PROVIDER_KEY` injected into the Codex env). Remote executors widen that
  surface and need care.
- **Dependency sprawl.** Each backend is an optional dependency; keep them dynamically
  imported and feature-detected, exactly as `codex_available()` already does.

### Verdict

**Do it, incrementally.** Suggested sequence:

1. **Refactor first, add nothing.** Extract `Executor` and `Harness` interfaces out of
   `CodexAdjudicator`, with `LocalWorktree` + `Codex` as the first implementations and the
   `chat` path slotted in as a no-executor harness. Pure refactor, behavior-preserving,
   covered by existing tests. This is the whole payoff-enabler and is low risk.
2. **Add one remote executor.** E2B is the most natural fit (purpose-built sandboxes for
   agents). Prove the `git bundle`→upload→run→stream-back path and the security win on one
   repo. Keep `local` the default.
3. **Add one alternative harness.** OpenCode, to validate that the `DECISION_SCHEMA` +
   `ToolAudit` adaptation generalizes beyond Codex.
4. **Expose the axes on the CLI** (`--harness/--executor/--model`) and let `strata_eval`
   compare them.

---

## How the two ideas interact

They pull in opposite directions, and that is the most useful thing to notice:

- **Idea 2 lowers the case for Idea 1.** If harnesses and sandboxes are external
  processes/services behind a thin interface, Strata's host process becomes an *orchestrator +
  validator*. Orchestration is where Python costs least and Go gains least, so a rewrite gets
  *less* attractive the more of Idea 2 you ship.
- **Idea 1's only strong scenario is also Idea 2's scaling scenario.** If Strata becomes a
  high-throughput hosted service coordinating many remote sandboxes, that is the one world
  where Go's concurrency/deployment story earns a rewrite — and even then the proportionate
  move is to port *the orchestrator/executor shell*, not the validator.
- **Sequencing:** do Idea 2's refactor **first** regardless. It delivers value on its own
  (off-host isolation), and it cleanly localizes the one deeply Python-coupled dependency
  (`openai_codex`) behind an interface — which is exactly what any future Go work at the
  boundary would want to target. Revisit Idea 1 only if a concrete production-service or
  binary-distribution mandate appears, and then prefer the middle path.

---

## Recommendation summary

| Idea | Recommendation | One-line why |
|---|---|---|
| **Migrate to Go** | **Not now** (prefer the middle path if Go is attractive) | I/O-bound workload with no perf need; the highest-value code (the validator) is the riskiest to port; Python 3.14 already removes the GIL argument. |
| **Pluggable harness/model/sandbox** | **Yes, incrementally — start with the interface refactor** | Extends seams that already exist; biggest win is moving untrusted-repo execution off-host; the validator stays the trust anchor, so backend bugs can't forge findings. |
