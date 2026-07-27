# Strata

[![CI](https://github.com/matiasinsaurralde/strata/actions/workflows/ci.yml/badge.svg)](https://github.com/matiasinsaurralde/strata/actions/workflows/ci.yml)

Strata is a Python research and reference pipeline for discovering
security-fixing commits:

1. a cheap recall-oriented commit triage pass;
2. a precision-oriented, tool-using adjudicator that emits validated findings;
3. a local Git importer with resumable SQLite storage and JSONL exports.

Early work in progress.

## Setup

```bash
uv sync
cp .env.example .env
```

The model endpoint is OpenAI-compatible and configured through
`OPENAI_BASE_URL`, `OPENAI_MODEL` and `OPENAI_API_KEY`. Note that the base URL
and API key resolve as a pair — see `src/strata/env.py`.

## Usage

```bash
uv run strata --help
```

Import state, bare mirrors, SQLite data and blobs live under `.strata/` and are
intentionally ignored.

## Tests

```bash
uv run pytest
```

The suite is hermetic: no network access and no API key required.

## License

[MIT](LICENSE)
