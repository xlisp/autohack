# autohack

This is an experiment to have the LLM do its own reconnaissance: given a target
project, hack out a complete inventory of every external API the project touches
and auto-mine documentation for each, like a vulnerability scanner produces a
report — except the "vulnerability" we're scanning for is **API surface area**.

The target project is described by its own `program.md` (project info, entry
points, hints about where to look). You read that file, then iterate scans until
you converge on a complete API inventory.

## Setup

To set up a new scan, work with the user to:

1. **Agree on a run tag**: propose a tag based on today's date and target name
   (e.g. `mar5-acme-web`). The branch `autohack/<tag>` must not already exist —
   this is a fresh run.
2. **Create the branch**: `git checkout -b autohack/<tag>` from current main.
3. **Locate the target**: the user gives you a path (or git URL) to the project
   being analyzed. Set `TARGET_DIR` env var or write it into `target.txt` at the
   repo root. The target must contain a `program.md` describing what the project
   is, its stack, and any hints (e.g. "uses Stripe and Auth0", "ignore vendored
   code under /third_party").
4. **Read in-scope files**: The repo is small. Read these for full context:
   - `README.md` — repository context.
   - `prepare.py` — fixed utilities: manifest parsers, grep patterns, TSV/JSON
     writers, doc-mine helpers. Do not modify.
   - `hack.py` — the file you modify. Pass driver + heuristics + scoring.
   - `<target>/program.md` — the **target's** description. Read carefully.
5. **Initialize findings/**: Create `findings/` containing:
   - `apis.tsv` with header row only.
   - `coverage.md` with an empty checklist.
   - `apis/` empty directory (one markdown per discovered API).
6. **Confirm and go**: confirm setup looks good.

Once confirmed, kick off the scan loop.

## The scan model

A "scan" is one pass of `hack.py` against the target. Each pass produces a
delta: APIs discovered, endpoints catalogued, docs fetched. You iterate by
editing `hack.py` to add new heuristics or deepen existing ones.

**What you CAN do:**
- Modify `hack.py`. Add patterns, add manifest parsers, add doc-mine targets,
  refine scoring. This is the only source file you edit.
- Write findings into `findings/` (TSV row per pass, one markdown per API).
- Use `WebFetch` to pull official docs for any SDK / API URL you discover.
- Use `Bash` for grep, ripgrep, jq, tree, file — read-only inspection of the
  target.

**What you CANNOT do:**
- Modify `prepare.py`. It is read-only. Fixed parsers, fixed grep helpers,
  fixed output format.
- Modify any file under `<target>/`. The target is read-only. You are doing
  passive reconnaissance, not editing the project being analyzed.
- Run the target's code. No `npm install && npm start`, no `python app.py`.
  This is a static-analysis loop. Network egress only via `WebFetch` to
  documentation sites.
- Install new dependencies. Use what's in `pyproject.toml`.

**The goal is simple: maximize unique APIs discovered with full documentation.**
A discovery is "complete" when:
- The API/SDK name and version are known.
- The endpoints / methods used by the target are enumerated.
- Auth mechanism is identified (API key env var, OAuth, signed JWT, etc.).
- Official docs URL is recorded **and** the relevant pages have been fetched
  and summarized into `findings/apis/<api-name>.md`.

**Simplicity criterion**: All else being equal, a simpler scanner is better. A
0.05 coverage bump that adds 200 lines of regex spaghetti is not worth it. A
deletion that holds coverage steady is a win.

**The first pass**: Your very first run should always establish the baseline,
so you will run the scanner as-is.

## Output format

Each pass of `hack.py` prints a summary like this:

```
---
pass:              3
new_apis:          2
total_apis:        14
endpoints_found:   47
docs_mined:        11
files_scanned:     312
coverage_pct:      78.4
elapsed_seconds:   12.3
```

Extract the key metric from the log:

```
grep "^total_apis:\|^coverage_pct:" run.log
```

## Logging results

After each pass, append a row to `findings/apis.tsv` (tab-separated, NOT comma —
descriptions break on commas).

The TSV has a header row and 6 columns:

```
commit	pass	total_apis	docs_mined	status	description
```

1. git commit hash (short, 7 chars)
2. pass number (1, 2, 3, …)
3. total unique APIs discovered after this pass
4. number of APIs with auto-mined docs in `findings/apis/`
5. status: `keep`, `discard`, or `crash`
6. short description of what this pass added

Example:

```
commit	pass	total_apis	docs_mined	status	description
a1b2c3d	1	6	0	keep	baseline: package.json + simple fetch() grep
b2c3d4e	2	11	4	keep	add axios + got patterns, WebFetch Stripe docs
c3d4e5f	3	11	4	discard	tried tree-sitter AST walk — too slow, no new finds
d4e5f6g	4	14	11	keep	add env var heuristic, mine Auth0/Algolia/Mailgun docs
```

### Per-API report format

For every API in the inventory, write `findings/apis/<slug>.md`:

```markdown
# <API name>

- **Vendor**: e.g. Stripe, Auth0, internal
- **Category**: payment / auth / analytics / storage / mail / internal-rest / …
- **Auth**: API key (env: `STRIPE_SECRET_KEY`) / OAuth2 / mTLS / none
- **SDK / Library**: `stripe@14.2.0` (from package.json)
- **Docs**: https://stripe.com/docs/api  (auto-mined YYYY-MM-DD)
- **Evidence**: file:line citations where this API surfaces in the target

## Endpoints / methods used

- `POST /v1/charges` — src/billing/charge.ts:42
- `stripe.customers.create()` — src/users/signup.ts:88
- …

## Notes from official docs

<short summary of the relevant doc pages — rate limits, gotchas, deprecations>
```

## The scan loop

The scan runs on a dedicated branch (e.g. `autohack/mar5-acme-web`).

LOOP FOREVER:

1. Look at the git state: current branch / commit / `findings/apis.tsv` tail.
2. Form a hypothesis: what kind of API might still be hiding?
   - dependency manifest entries with no corresponding entry in the inventory
   - env vars referenced but not yet attributed to any API
   - URL string literals in source not yet associated with a vendor
   - SDK init calls (`new Stripe(...)`, `Auth0Client({...})`) not yet captured
3. Tune `hack.py` with a new heuristic / pattern / parser. Or improve doc-mining.
4. `git commit`.
5. Run the pass: `uv run hack.py > run.log 2>&1`
   (redirect everything — do NOT use tee or let output flood your context).
6. Read the summary: `grep "^pass:\|^total_apis:\|^coverage_pct:" run.log`.
7. If the grep output is empty, the pass crashed. Run `tail -n 50 run.log`,
   read the stack trace, and attempt a fix. If you can't get things to work
   after more than a few attempts, give up on this idea.
8. For any new API in this pass, WebFetch its official docs URL and write
   `findings/apis/<slug>.md`. Cite file:line evidence from the target.
9. Update `findings/coverage.md` — manifest entries seen vs. attributed.
10. Append a row to `findings/apis.tsv` (do NOT commit `findings/` — leave it
    untracked; the inventory is a side-effect, not part of the tool).
11. If `total_apis` increased OR `docs_mined` increased, you "advance" — keep
    the commit.
12. If the pass added nothing, `git reset` back to where you started.

The idea: you are an autonomous recon agent mapping out the target's external
API surface. Each pass is a probe. If it surfaces something new, keep. If not,
discard. You advance the branch so you can iterate on what worked.

**Convergence**: when 3 consecutive passes find nothing new AND every manifest
entry is attributed AND every env var is attributed, declare the scan converged
and produce a final `findings/REPORT.md` that aggregates all per-API markdowns
into one document.

**Crashes**: if a pass crashes (regex blowup, OOM on a giant minified bundle,
network timeout in WebFetch), use your judgment. Typos / missing imports → fix
and rerun. Fundamentally broken idea → log `crash`, revert, move on.

**Timeout**: each pass should take under 60 seconds on a normal repo. If a pass
exceeds 5 minutes, kill it. Most likely a runaway regex on a minified file —
add a size cap and try again.

**NEVER STOP**: once the loop is running, do NOT pause to ask the human if you
should continue. Do NOT ask "should I keep going?" or "is this a good stopping
point?". The human may be asleep and expects to wake up to a finished inventory.
You are autonomous. If you run out of ideas, think harder — re-read the
target's `program.md`, grep for protocol schemes you haven't covered (`ws://`,
`grpc://`, `mongodb://`, `redis://`, `s3://`), check CI configs, check
Dockerfiles, check `.env.example`, check GitHub Actions secrets, check
infrastructure-as-code (Terraform, Pulumi). The loop runs until the human
interrupts you or the convergence condition fires.

## Ethics & scope

This tool does **static reconnaissance** of a codebase you have been authorized
to analyze. It does not:
- send traffic to the discovered APIs,
- attempt authentication against them,
- exfiltrate secrets it finds (if you grep up a real API key, redact it in
  `findings/` and warn the human; never write secrets to disk verbatim).

If the target's `program.md` does not establish authorization (own code,
permitted audit, CTF, public OSS), stop and ask the human to confirm scope
before starting the loop.
