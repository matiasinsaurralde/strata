# VFD + security-context grounding — pilot harness

Supporting code and data for [`../../findings.md`](../../findings.md) (top-level).

Two quick experiments on real GHSA commits, run against the OpenAI API:

- **Experiment 1 — content ladder** (`exp1.py`, `exp1_prompt.py`): does a model need the
  commit message / PR to decide a commit is a security fix, or is the diff enough? Measures
  recall on 7 fix commits and false-positive rate on 4 non-fix commits, across
  diff-only / +message / +PR and across models/efforts, plus a neutral-prompt FPR ablation.
- **Experiment 2 — grounding** (`exp2.py`, `contexts.py`): does a `securitycontext.dev`-style
  context built from a repo's *past* vulns improve analysis of *new* code vs a blind look?
  Reviews full pre-/post-fix files under blind / relevant / irrelevant / leading contexts.

## Layout

| path | what |
|---|---|
| `manifest.json` | the 7 positive + 4 negative commits (repo, sha, GHSA, CWE, stratum) |
| `patches/` | verbatim `git format-patch` blobs (diff + commit message) |
| `pr/` | PR opening descriptions (author's first post only) |
| `code/` | full pre-fix (`*.before.go`) and post-fix (`*.after.go`) files for Exp 2 |
| `common.py` | OpenAI client, cost meter, patch parser, prompt builder, scoring |
| `diffregion.py` | reconstruct before/after code regions from a diff |
| `osv_fetch.py` | pull advisory metadata + references from OSV.dev |
| `runs/` | raw model outputs, one JSON row per call (committed) |
| `aggregate_exp1.py`, `aggregate_exp2.py` | render the summary tables |

## Run

```bash
export OPENAI_API_KEY=...            # never commit this
python exp1.py "gpt-5.4:none" "gpt-5.4:medium"
python exp1_prompt.py
python exp2.py "gpt-5.4:none" "gpt-5.4:medium"
python aggregate_exp1.py ; python aggregate_exp2.py
```

Data was gathered without GitHub API tokens: OSV.dev for advisory references, and public
`…/commit/<sha>.patch` + `raw.githubusercontent.com` for patches and full files.

**Caveat:** tiny n (pilot, not an estimate). See the Limitations section of `findings.md`.
