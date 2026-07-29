# Tree-sitter for the Strata adjudicator — a symbol-anchoring pilot

**Branch:** `claude/tree-sitter-golang-pilot-t2pghy`
**Date:** 2026-07-29
**Scope:** (1) a code review of the current changes on this branch, and (2) a
pilot that implements a real tree-sitter analysis arm for the adjudicator's
static-analysis stage and measures its accuracy against the shipped regex
baseline on real open-source repositories.

---

## TL;DR

- Strata's `static_analysis.py` is an **ablation harness** whose stated job is
  to decide which analyzers are worth feeding the adjudicator. It ships a
  regex **text baseline** as the always-on arm and a **tree-sitter arm that was
  a stub** (`available_not_run`). This pilot makes the tree-sitter arm real.
- On the core task the harness exists to serve — **anchoring a changed line to
  its enclosing function/method** — tree-sitter is a **clear, verified win**:
  - Go (gin, 2,784 function-body lines): the regex gets the fully-qualified
    symbol right only **37.6%** of the time and is **confidently wrong 3.3%**;
    it loses the receiver on **100% of the 1,709 method-body lines**.
  - Python (requests, 5,676 lines): the regex is **confidently wrong 7.2%**
    (411 lines), concentrated in security-relevant nested-scope code.
  - On real commit diffs the regex disagrees with the parse on **21% (gin) /
    10% (requests) / 23% (express)** of changed hunks; a manual audit of every
    disagreement category found **tree-sitter correct in 100% of sampled cases**.
- On a second axis — **classifying a change as cosmetic** (comment/whitespace
  only) for the prefilter — tree-sitter is **not** a clean win. Its token
  comparison beats the regex on inline-comment edits but has complementary
  blind spots (Go `//go:build` directives, Python docstring whitespace,
  import reorders). The recommendation there is a **hybrid**, not a swap.
- **Would it improve LLM output?** For symbol anchoring, yes, in a measurable
  and non-trivial fraction of commits, for reasons the codebase already
  accepts: the same "structural facts must not come from an approximation"
  principle that motivated the adjudicator's `cite` tool. A direct end-to-end
  LLM A/B needs an API key (absent here); the harness for it exists
  (`scripts/ab_adjudicator.py`) and the next step is spelled out below.

---

## 1. Background: where symbol anchoring lives, and why it reaches the model

Strata discovers security-fixing commits in three passes: a cheap triage, a
tool-using **adjudicator** that emits validated findings, and a context
compiler. Alongside these is `src/strata/static_analysis.py`, described in its
own docstring as *"measured, dependency-optional static-analysis ablations."*
It defines a set of analyzer **arms**:

| arm | what it is | status before this pilot |
|-----|------------|--------------------------|
| `text_baseline` | regex `hunk_to_symbol` + call-site search | always available, runs |
| `tree_sitter` | availability probe only | **stub — `available_not_run`** |
| `ast_grep`, `codeql`, `joern` | availability probes | stub |

The always-on arm answers a specific question for every changed hunk: **which
symbol (function / method / type) encloses this line?** It does so with a stack
of regexes (`_SYMBOL_PATTERNS`, `hunk_to_symbol`) that walk backwards from the
changed line looking for something that looks like a definition.

That answer is exactly the kind of *structural fact* the adjudicator reasons
over: "the change is in `(*Engine).Run`", "the fix touches
`HTTPDigestAuth.build_digest_header`". The finding contract carries
`affected_symbols`, and the compiled context tells the model where each change
sits. The adjudicator's own design already reflects a hard-won lesson about
structural facts — the `cite` tool exists because letting the model re-derive
line numbers from diff hunk headers produced *"correct text at wrong offsets …
the single largest source of lost findings."* Symbol anchoring is the same
problem one axis over: an approximate method naming the enclosing symbol is a
source of wrong-but-plausible structural context. Tree-sitter is the same class
of fix — get the fact from a real parse, not a regex.

> Note on wiring: today `static_analysis.py` is an evaluation/ablation
> component; its `hunk_symbols` are not yet injected into the live adjudicator
> prompt (the model currently names symbols itself via tool calls). This pilot
> answers the *precondition* question the harness is built to answer — "is the
> parser arm good enough to feed the adjudicator?" — not "is it already wired
> in." That is the honest framing and it matches the harness's purpose.

---

## 2. What this pilot adds

| file | purpose |
|------|---------|
| `src/strata/tree_sitter_symbols.py` | The real resolver. `enclosing_symbol`, `enumerate_symbols`, `is_cosmetic_change`, for Go / Python / JS / TS. Returns `None` (never a wrong answer) on unsupported input so callers fall back to the baseline. |
| `src/strata/static_analysis.py` | New `TreeSitterSymbolAnalyzer` arm mirroring `TextBaselineAnalyzer`'s output, added to `default_analyzers()`, so `run_ablation` puts the two side by side. Falls back to the text baseline per-hunk, so it is never *worse* than the baseline. |
| `scripts/ts_pilot.py` | The measurement harness (two experiments, offline, deterministic). |
| `tests/test_strata_tree_sitter_symbols.py` | 11 tests pinning the wins and the known blind spots. |

Design choices worth calling out:

- **Receivers.** A Go method's identity is `(receiver, name)`. `(*Buffer).Write`
  and `(*Reader).Write` are different functions the regex both calls `Write`.
  The resolver recovers the receiver from the parse tree.
- **Doc comments.** A doc comment sits *above* the node it documents, outside
  its span. Go/Python convention attaches it to the definition below; the
  resolver encodes that (`method="tree_sitter_doc"`), where the regex
  misattributes it to the *previous* function.
- **Fallback, never failure.** Unsupported language or unavailable parser →
  `None`, and the analyzer arm degrades to the text baseline for that hunk.

---

## 3. Experimental design

Both experiments run offline on real repositories, with the parse tree as
ground truth. Repositories: **gin-gonic/gin** (Go), **psf/requests** (Python),
**expressjs/express** (JavaScript).

**Experiment A — interior-line sweep (controlled accuracy).**
For every source file, enumerate every function/method with its exact line
span. For **every** line strictly inside a body (excluding the signature line
and blank/brace/comment-only lines — no sampling, no cherry-picking), the
ground-truth enclosing symbol is that innermost span. We then ask how often the
regex baseline reproduces it.

*On circularity:* the tree-sitter arm is ground truth here, so it scores 100%
by construction — that number is not the point. The measurement is the **regex
error rate against a real parse**, and we validate the ground truth by manually
auditing a sample of every disagreement category (Section 5). The regex is a
fully independent method, so this is a fair test of it.

**Experiment B — real-diff sweep (production scenario).**
For real commits, anchor each changed hunk with **both** methods, exactly as
`map_hunks_to_symbols` would (same anchor line fed to both). Record every
disagreement with a code snippet and an auto-classified cause, plus a
per-file cosmetic-change comparison.

**Metrics.** *Bare-name* accuracy strips receivers/qualifiers — the most
charitable reading of the regex, crediting it whenever it finds the right
function even if it can't name it fully. *Qualified* accuracy requires the full
name (`(*Server).Handle`, `A.Inner.deep`). We separately count *confidently
wrong* (names a different, real symbol — worse than giving up, because it
misleads) vs *gave up* (`<file>`).

---

## 4. Results

### 4.1 Interior-line sweep — regex baseline vs. the parse

| repo / lang | lines evaluated | regex **bare** acc. | regex **qualified** acc. | regex **confidently wrong** | method lines w/ receiver lost |
|-------------|----------------:|--------------------:|-------------------------:|----------------------------:|------------------------------:|
| gin / Go | 2,784 | 96.7% | **37.6%** | 3.3%  (92 lines) | **1,709 / 1,709 (100%)** |
| requests / Python | 5,676 | 92.8% | 91.5% | **7.2%  (411 lines)** | 29 |
| express / JS* | 136 | 89.7% | 89.7% | 10.3% | — |

*express `lib/` is small (6 files); included as a third-language sanity check,
not a headline number.*

Reading this:

- The regex finds the right **bare** function name most of the time (92–97%).
  That is its ceiling, and it is genuinely decent.
- On **Go**, qualified accuracy collapses to **37.6%** because the regex
  **never** emits a receiver — every one of the 1,709 method-body lines gets an
  ambiguous anchor (`Handle`, not `(*Server).Handle`). Tree-sitter recovers the
  receiver on all of them.
- The **confidently-wrong** rate is the most consequential number: 3.3% (Go) /
  7.2% (Python) of changed lines are attributed to the *wrong function*. That is
  a false structural fact, not a missing one.

### 4.2 Real-diff sweep — agreement and the shape of the disagreements

| repo | commits | hunks | agreement | regex disagreement | receiver recovered by ts |
|------|--------:|------:|----------:|-------------------:|-------------------------:|
| gin | 114 | 500 | 79.0% | 21.0% | 53 method hunks |
| requests | 87 | 487 | 89.9% | 10.1% | 0 |
| express | ~90 | 131 | 77.1% | 22.9% | 0 |

Disagreement causes (auto-classified, then hand-audited):

| cause | gin | requests | express | who is right |
|-------|----:|---------:|--------:|--------------|
| `doc_comment_attached` — changed doc line; ts attaches to documented fn | 47 | 0 | 0 | **ts** (regex names the *previous* fn) |
| `top_level_hallucination` — regex names a fn for a module/package-level line | 21 | 37 | 30 | **ts** (`<file>` is correct) |
| `closure_defer_func` — `defer func(){` makes the regex return the literal `"func"` | 20 | 0 | 0 | **ts** |
| `type_body_field` — struct/interface/class-body line | 16 | 6 | 0 | **ts** (the type) |
| `go_generic_signature` — `func F[T any](…)` unseen by the regex | (in wrong-sym) | 0 | 0 | **ts** |
| `nested_or_sibling_scope` — line after a nested def has closed | 1 | 6 | 0 | **ts** |

In every category, on every repo, the parse is right and the regex is wrong.

---

## 5. The failure catalog (verified against real source)

Each of these was confirmed by reading the actual file at the cited lines.

**1. Go receivers are always lost.** `gin/context.go` defines dozens of
`(*Context)` methods. A change inside any of them is `Handle`, `BindJSON`,
`Stream`… to the regex — never `(*Context).Handle`. 100% of method-body lines.
Consequence: two different types' `ServeHTTP`/`String`/`Error`/`Write` methods
are indistinguishable in the anchor.

**2. Go generics are invisible to the regex.** `gin/context.go:313`
`func getTyped[T any](c *Context, key any) (res T)`. The Go regex expects `(`
right after the function name; it sees `[` and skips the definition, so every
line of `getTyped`'s body is attributed to the previous function, `MustGet`.
Verified: lines 314–318 → regex `MustGet`, parse `getTyped`.

**3. `defer func(){` poisons the anchor.** `gin/gin.go:540`
`func (engine *Engine) Run(...)` whose first body line is
`defer func() { debugPrintError(err) }()`. The regex's C-style fallback pattern
matches `defer func(...) {` and captures the literal word **`func`** as the
symbol name. Every subsequent line of `Run` is reported as being in a function
called "func" (60 lines in `gin.go`, 24 in `recovery.go`).

**4. Python nested scopes mis-bind — in authentication code.**
`requests/auth.py:157` `HTTPDigestAuth.build_digest_header` defines nested
helpers (`md5_utf8`, `sha_utf8`, …, `KD`) at the top, then continues its own
body below them. The regex's indentation heuristic can't tell a nested def has
*closed*, so it attributes the method's own body — `path = p_parsed.path or "/"`,
`A1 = f"{self.username}:{realm}:{self.password}"` — to `HTTPDigestAuth.KD` /
`HTTPDigestAuth.sha512_utf8`. 50 mislabeled lines in one security-relevant file.

**5. Top-level changes get a hallucinated function.** `requests/__init__.py`
module-level `check_compatibility(...)` guard and `from cryptography import …`
→ regex `_check_cryptography`; parse `<file>` (correct — these are module-level).
Same shape in Go at function boundaries and in express's CommonJS
`module.exports` blocks.

**6. Struct/type bodies attributed to the previous function.**
`gin/render/render_test.go:140` fields of `type errorWriter struct` → regex
`TestRenderJsonpJSON`; parse `errorWriter`.

---

## 6. The second axis: cosmetic-change classification (a nuanced result)

The prefilter's job includes dropping comment/whitespace-only changes before
they cost an LLM call. The shipped `is_comment_or_whitespace_only_change` is a
line-diff heuristic; the pilot's `is_cosmetic_change` compares the two files'
**non-comment token streams**. Over 258 (gin) / 159 (requests) changed files
they disagree on 4 / 14. Auditing those disagreements shows **neither
dominates** — they have complementary blind spots:

| situation | regex | tree-sitter | better |
|-----------|-------|-------------|--------|
| inline `# type: ignore` pragma removed, code identical | "substantive" | "cosmetic" | **ts** (code tokens unchanged) |
| `//go:build linux` → `//go:build darwin` | "substantive" (behavioral-directive guard) | **"cosmetic"** (comment to the grammar) | **regex** |
| blank line added inside a docstring | "cosmetic" | "substantive" (docstring is a string token) | **regex** |
| identical import line reordered | "cosmetic" (multiset cancels) | "substantive" (token order changed) | **regex** (usually) |

**Conclusion for this axis:** do **not** swap the regex out for the token
comparison. The right production classifier is a **hybrid** — tree-sitter
token-equality *plus* the regex's behavioral-directive guard, docstring
awareness, and order-insensitivity for imports. This is the pilot's most
important negative result: tree-sitter is a scalpel for structure, not a
drop-in upgrade for every heuristic. (`is_cosmetic_change`'s `//go:build` blind
spot is pinned by a test so it can't be mistaken for correct.)

---

## 7. Would tree-sitter improve LLM output?

**For symbol anchoring: yes — with a measured, bounded claim.**

The deterministic result is that in a non-trivial fraction of real commits
(≈10–20% of changed hunks; 3–7% of individual function-body lines) the regex
hands downstream consumers a **false structural fact** — a wrong function name,
a lost receiver, a hallucinated enclosing function for module-level code. These
are precisely the inputs the adjudicator reasons over when it decides
reachability ("is the changed function attacker-reachable?"), containment
("does the framework's `recover()` catch a panic *in this function*?"), and when
it fills `affected_symbols`. The Go language appendix the adjudicator loads is
entirely about reasoning that hinges on *which function/goroutine* a change is
in — reasoning that a wrong anchor silently corrupts.

This is not a speculative concern for this codebase specifically: it already
paid for the same class of bug once and fixed it structurally. The `cite`
tool's whole reason for existing is that an approximate method (the model
reading hunk headers) produced *"correct text at wrong offsets — the single
largest source of lost findings."* A regex that names the wrong enclosing
symbol is the identical failure mode. Removing it is a strict improvement to
input fidelity, which is a **necessary condition** for correct reasoning.

**The honest boundary:** I cannot show the *final verdict* changes without
running the model, and this environment has no API key (`.env` absent,
`OPENAI_API_KEY` unset). Better inputs do not guarantee a different output on
any given commit — a strong model can sometimes recover from a wrong anchor by
reading the file itself. So the defensible claim is: **tree-sitter measurably
improves the fidelity of the structural context handed to the model, on a
meaningful fraction of commits, in categories (generics, receivers, nested
scope, top-level) the regex cannot fix by tuning.** Whether that moves
precision/recall is the next experiment, and it is cheap to run:

```
# with a funded OPENAI_* endpoint, over the frozen truth fixture:
uv run python -m scripts.ab_adjudicator --backend chat --out results/ab/base.json
# then: inject tree_sitter_symbols' hunk_symbols into the candidate context and re-run,
#       compare precision / recall / abstain on the same 50 commits.
```

---

## 8. Recommendation

1. **Adopt the tree-sitter arm for symbol anchoring** in the ablation harness
   (done here) and make it the source of `affected_symbols` / hunk anchors when
   available, with the text baseline as fallback. It is never worse per-hunk and
   is materially better on Go (receivers, generics, closures) and on
   nested-scope Python.
2. **Do not replace the cosmetic classifier**; build a hybrid that keeps the
   behavioral-directive guard.
3. **Run the end-to-end A/B** (Section 7) before wiring anchors into the live
   prompt, to quantify the verdict-level effect.
4. Grammar coverage is cheap to extend (Rust, C/C++, Java, Ruby) — the resolver
   is table-driven per language.

---

## 9. Limitations & threats to validity

- **Parser-as-ground-truth.** The interior sweep credits tree-sitter with 100%
  by construction. Mitigated by auditing every disagreement category by hand
  (Section 5) and by the fact that the interesting number is the *regex* error
  rate, measured independently.
- **No end-to-end LLM measurement** (no API key). Section 7 is careful to claim
  only input-fidelity improvement, not verdict change.
- **Repo/scale.** gin + requests + a small express slice; ~1,100 real hunks and
  ~8,600 interior lines total. Enough to establish the failure modes are
  systematic, not enough to pin a precise production rate.
- **Doc-comment attachment is a convention choice.** Reasonable people can
  argue a changed doc line isn't "in" the function; the resolver takes the
  Go/Python-idiomatic view and records it distinctly (`tree_sitter_doc`).
- **express JS sample is small**; treated as a sanity check only.

---

## 10. Code review of the current changes (7 commits, `38e5b5a..d416a6e`)

Reviewed independently and each finding confirmed by tracing the code. First, a
correction that shaped the review: the codebase's pervasive
`except A, B:` (unparenthesized) is **not** a bug — the project targets Python
≥3.14, which implements **PEP 758**, and `ruff format` (target `py314`)
actively rewrites the parenthesized form to it. It is house style, verified,
and only a concern for anyone running the code on <3.14.

**HIGH — `scan.py:251-262`: a stream-level fault silently truncates the scan.**
The streaming prefilter wraps `next(stream)` in `except Exception: … continue`.
A per-record fault is skippable, but a *terminal* stream fault (a
`GitTimeoutError`/`GitRepositoryError` raised **inside** the generator) finishes
the generator; the `continue` then calls `next()` on an exhausted generator →
`StopIteration` → `break`. The scan proceeds through triage/adjudication and
exits 0 having seen only the commits before the fault. Regression from the
per-`get_commit` path, where each fault was genuinely independent. Fix:
distinguish a per-record skip from a stream abort.

**HIGH — `git_repo.py` `stream_commits` / `_stream_bounded`: one 120 s
wall-clock budget spans the whole walk *including consumer time*.** The stream
is bounded by `fetch_timeout` (default **120 s**). Because the generator is
pull-based and the OS pipe buffers little, that single deadline covers git's
production **plus** all downstream prefilter processing for the entire history —
exactly the large-repo case streaming was added to speed up. Trip it and, via
the finding above, the scan truncates silently. Compounding: the
`--fetch-timeout` help says *"No effect on local repositories,"* but this bounds
the in-place local walk. Fix: give the walk its own budget (or a per-read idle
timeout) and correct the help text.

**MEDIUM — `git_repo.py:~415` `_stream_bounded`: timeout not enforced during a
blocking read.** The deadline is checked at the top of the loop, then
`process.stdout.read(1 MB)` blocks until 1 MB or EOF. If git stalls with
<1 MB buffered and no EOF, the read blocks forever and the deadline check is
never reached. `_run_bounded` does this correctly (drain threads +
`process.wait(timeout=…)`); `_stream_bounded` reads on the main thread. Fix:
mirror `_run_bounded`'s pattern.

**MEDIUM — `codex_adjudicator.py` `_worktree`: `git clone --local` full-copies
the object store when `$TMPDIR` is on a different filesystem.** `--local`
hardlinks only within one filesystem; across mounts (e.g. `/tmp` on tmpfs) it
copies the entire object store, per candidate, up to `workers` concurrently.
Fix: create the tempdir on the repo/cache filesystem, or reuse one clone per
worker.

**Minor (verified):** `introduction.py:135` has an unreachable `"no signal"`
branch (`blamed_any` is always `False` at that point); the OVERSIZE
`PrefilterDecision` (`prefilter.py`) now drops its classified metadata;
`_changed_paths_from_patch` always labels renames `R100` (benign — only `.path`
is consumed downstream). `progress.py`, `context/compiler.py` and the
`adjudicator.py` `raw_output` change reviewed clean.

*These are pre-existing on `main`, orthogonal to the pilot, and left as-is;
happy to fix any of them in a follow-up on request.*

---

## 11. Reproduction

```bash
uv sync
# clone the corpora (any commit; results are stable across nearby revisions)
git clone --depth 300 https://github.com/gin-gonic/gin.git   .strata/pilot/gin
git clone --depth 300 https://github.com/psf/requests.git    .strata/pilot/requests

# Experiment A — interior-line accuracy
uv run python -m scripts.ts_pilot interior --repo .strata/pilot/gin      --lang go
uv run python -m scripts.ts_pilot interior --repo .strata/pilot/requests --lang python

# Experiment B — real-diff scenario
uv run python -m scripts.ts_pilot diffs --repo .strata/pilot/gin      --commits 200
uv run python -m scripts.ts_pilot diffs --repo .strata/pilot/requests --commits 200

# the ablation harness now carries both arms side by side
uv run python -c "from strata.static_analysis import availability_report; import json; print(json.dumps(availability_report(), indent=2))"

uv run pytest tests/test_strata_tree_sitter_symbols.py -q
```

Raw result JSON for every run in this report is under
`.strata/pilot/results/` (gitignored).
