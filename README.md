# autohack

> Give an AI agent a target codebase. It hacks the codebase to discover **every
> external API it touches**, auto-mines the relevant documentation, and produces
> a complete inventory — like a vulnerability scanner's report, except the
> "vulnerability" is *API surface area*. Designed as a sibling to
> [autoresearch](../autoresearch): same skeleton, different goal.

The idea: you point the agent at a target project (e.g. a frontend app) whose
`program.md` describes it in plain English. The agent reads the description,
parses every manifest (npm/pypi/cargo/go/…), greps the source for HTTP clients
and known SaaS SDKs, attributes env vars, follows URL literals back to vendors,
and — for each finding — fetches the official docs and writes a per-API
markdown report with file:line citations.

Like autoresearch, you're not editing the Python files like you normally
would. Instead, you are programming the `program.md` Markdown file that
provides context to the agent. The default `program.md` is a baseline; the
expectation is that you iterate on it over time to find the prompt that
recovers the most APIs with the cleanest evidence.

## How it works

Three files matter:

- **`prepare.py`** — fixed utilities: target resolver, manifest parsers
  (package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml,
  Gemfile, composer.json), file walker, structured TSV/markdown writers,
  secret redaction. **Not modified.**
- **`hack.py`** — the single file the agent edits. Baseline scanner: walks
  manifests, greps for HTTP-client calls and URL literals, maps to known
  SaaS vendors, writes stub reports. The agent extends this pass by pass
  with new heuristics (more ecosystems, more libraries, more patterns,
  config-file scanning, env-var attribution, scoring). **The agent edits.**
- **`program.md`** — agent instructions. Defines the scan loop, output
  format, and rules. **The human edits.**

Every pass produces a row in `findings/apis.tsv` and a stack of
`findings/apis/<vendor>.md` files. The metric is **unique APIs discovered with
auto-mined docs**. The loop runs until convergence (3 consecutive passes find
nothing new and every manifest entry / env var is attributed).

## Quick start

**Requirements:** Python 3.11+ (for stdlib `tomllib`),
[uv](https://docs.astral.sh/uv/), an agent with `WebFetch` for doc mining.

```bash
# 1. install uv (if needed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. install deps
uv sync

# 3. point at a target — either env var or target.txt
export TARGET_DIR=/path/to/some/frontend/project
# or:
echo "/path/to/some/frontend/project" > target.txt

# 4. manually run one scan pass (~seconds)
uv run hack.py
```

The target directory **must** contain a `program.md` describing it (stack,
entry points, anything-not-to-scan hints). The agent reads that file before
the first pass.

## Running the agent

Spin up Claude / Codex / whatever in this repo, then prompt:

```
Hi, have a look at program.md and let's kick off an autohack run against the
target in target.txt. Do the setup first.
```

`program.md` is a lightweight "skill" — the agent reads it, sets up a fresh
branch, and starts the loop.

## Project structure

```
prepare.py        — fixed utilities (do not modify)
hack.py           — scanner driver (agent modifies)
program.md        — agent instructions (human modifies)
target.txt        — absolute path to the target project (or use $TARGET_DIR)
pyproject.toml    — dependencies
findings/         — generated, untracked
  apis.tsv        — one row per pass
  coverage.md     — manifest entries seen vs. attributed
  apis/           — one markdown per API discovered
```

## Output

After convergence, `findings/` looks something like:

```
findings/
  apis.tsv
  coverage.md
  REPORT.md             — final aggregated report
  apis/
    stripe.md
    auth0.md
    algolia.md
    sentry.md
    aws-s3.md
    internal-billing-api.md
    ...
```

Each `apis/<vendor>.md` carries: vendor + category + auth mechanism + SDK
version + docs URL (with fetch date) + endpoint list with file:line evidence +
a short summary of the relevant doc pages.

## Design choices

- **Single file to modify.** The agent only touches `hack.py`. Keeps scope
  small and diffs reviewable, exactly like autoresearch.
- **Static reconnaissance only.** The scanner never executes the target's
  code, never authenticates against any discovered API, never sends test
  traffic. Network egress is restricted to fetching public documentation
  pages.
- **Secrets get redacted, not exfiltrated.** If a grep surfaces something
  that looks like a real key, `prepare.redact` masks it before any write to
  `findings/`. If you spot a real secret in the target, tell the human;
  don't quietly persist it.
- **Convergence beats time budget.** Unlike autoresearch (fixed 5-min runs),
  passes here are cheap (seconds). The signal is whether a pass discovers
  anything new — when 3 consecutive passes don't, the scan is done.

## Ethics

`autohack` is built for code you own or have been authorized to audit
(internal apps, OSS dependency audits, CTF challenges, third-party security
reviews with engagement letters). It is **not** a tool for probing systems
you don't have permission to analyze. The `program.md` setup step requires
the human to establish scope before the loop starts.

## License

MIT
