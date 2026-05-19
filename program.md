# autohack

This is an experiment to have the LLM do its own reconnaissance, in two modes:

- **codebase mode** — given a project directory, hack out a complete inventory
  of every external API the project touches and auto-mine documentation for
  each.
- **endpoint mode** — given a single API URL (no source code), recover its
  surface (paths, auth scheme, related hosts), mine its public docs, and find
  who calls it in the wild.

The mode is auto-detected: if `target.txt` (or `$TARGET_DIR`) contains an
`http(s)://…` URL, you're in endpoint mode; otherwise it's a directory and
you're in codebase mode. The agent's setup step decides which.

In **codebase mode** the target should also contain its own `program.md`
describing the project (stack, entry points, hints about where to look). You
read that file, then iterate scans until you converge on a complete inventory.

In **endpoint mode** the target is just a URL. You combine three signals to
build the inventory: (a) polite discovery probes against well-known files,
(b) public documentation mined via WebSearch / WebFetch, (c) third-party code
search (GitHub, grep.app, SourceGraph) to find callers in the wild.

## Setup

To set up a new scan, work with the user to:

1. **Agree on a run tag**: propose a tag based on today's date and target name
   (e.g. `mar5-acme-web` for a codebase, or `mar5-api-stripe` for an endpoint).
   The branch `autohack/<tag>` must not already exist — this is a fresh run.
2. **Create the branch**: `git checkout -b autohack/<tag>` from current main.
3. **Confirm authorization** before any probe. Endpoint mode in particular
   needs an explicit yes that the target is in scope. See the **Ethics & scope**
   section below.
4. **Locate the target**: the user gives you either a directory path OR a URL.
   - **Codebase mode** (directory): the target should also contain its own
     `program.md` describing the stack and any hints (e.g. "uses Stripe and
     Auth0", "ignore vendored code under /third_party").
   - **Endpoint mode** (URL): the user gives you the base URL of an API,
     e.g. `https://api.example.com` or `https://example.com/api/v1`.
   Set `$TARGET_DIR` or write the value into `target.txt` at the repo root.
5. **Read in-scope files**: The repo is small. Read these for full context:
   - `README.md` — repository context.
   - `prepare.py` — fixed utilities: target resolver, manifest parsers,
     polite HTTP probe session, TSV/JSON writers, redaction. Do not modify.
   - `hack.py` — the file you modify. Pass driver + heuristics + scoring.
   - codebase mode only: `<target>/program.md` — the **target's** description.
     Read carefully.
6. **Initialize findings/**: Create `findings/` containing:
   - `apis.tsv` with header row only.
   - `coverage.md` with an empty checklist.
   - `apis/` empty directory (one markdown per discovered API).
7. **Confirm and go**: confirm setup looks good.

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
2. Form a hypothesis: what might still be hiding?
   - **codebase mode**:
     - dependency manifest entries with no entry in the inventory
     - env vars referenced but not yet attributed to any API
     - URL string literals in source not yet associated with a vendor
     - SDK init calls (`new Stripe(...)`, `Auth0Client({...})`) not yet captured
   - **endpoint mode**:
     - well-known endpoints not yet polled (extend `WELL_KNOWN_PATHS`? only if
       the path is genuinely a public discovery endpoint, not a fuzz target)
     - OpenAPI doc says `securitySchemes` references an OAuth flow you haven't
       resolved — WebFetch the issuer's `.well-known/openid-configuration`
     - TLS SAN listed a sibling host — ask the user to authorize a follow-up
       pass against it
     - vendor's public docs reveal endpoints you haven't seen in the OpenAPI —
       WebFetch the official docs and reconcile
     - GitHub code search for `"<host>"` surfaces real callers (open-source
       client libraries, SDKs, public projects integrating the API)
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

## Endpoint mode — what counts as a "polite probe"

When the target is a URL, every active probe is governed by
`prepare.ProbeSession`. The rules are NOT negotiable from `hack.py`:

- **Methods**: only GET / HEAD / OPTIONS. Anything else is refused.
- **No credentials**: never send `Authorization`, `Cookie`, or any header
  containing a token. The session strips them by construction.
- **Allowlisted paths**: `prepare.WELL_KNOWN_PATHS` — a small set of public
  discovery endpoints (OpenAPI, OIDC, OAuth metadata, JWKS, robots.txt,
  sitemap.xml). Path fuzzing / brute force / endpoint guessing is
  **forbidden**.
- **Budget**: at most `PROBE_BUDGET_PER_HOST` (25) requests per host per
  pass. Cross-host probing requires explicit human approval (e.g. a TLS SAN
  surfaced a sibling host worth its own pass).
- **Body cap**: only the first 256 KB of each response is read.
- **User-Agent**: fixed string `autohack/0.1 …`; never spoofed.
- **No traffic to anything you don't own / aren't authorized to scan.** The
  setup step requires the human to confirm scope before the loop starts.

What endpoint mode IS designed to discover:

- **Surface**: paths and verbs (from OpenAPI/Swagger, OIDC discovery doc).
- **Auth scheme**: how login *works* — OAuth2 endpoints, JWT issuer / JWKS,
  API-key header names, OIDC scopes. Reading the public OIDC config tells
  you exactly *how* to authenticate; it does NOT tell you what token to use.
- **Related hosts**: TLS SAN names, CORS allowlist origins.
- **Docs**: official documentation URL, mined via WebSearch + WebFetch.
- **Callers**: who uses this API publicly — GitHub code search for the host
  name, grep.app, SourceGraph, vendor SDK repos. (Read-only; you're querying
  third-party search engines, not the target.)

What endpoint mode is NOT and will refuse to become:

- A credential tester. We never submit `Authorization` headers.
- A path fuzzer. We never probe paths outside `WELL_KNOWN_PATHS`.
- A GraphQL introspector by default. (Introspection is a server config
  signal — some operators treat it as sensitive. Off by default; requires
  explicit human OK.)
- A vulnerability scanner. We do not test for injection, auth bypass,
  SSRF, or anything else from the OWASP top 10. Authorized active testing
  is a different tool; this one only enumerates the published surface.

## Ethics & scope

This tool does **passive or polite-probe reconnaissance** of a target you
have been authorized to analyze:
- codebase mode is fully static — never executes target code.
- endpoint mode sends only the allowlisted polite probes above.

It does not:
- send traffic outside the polite-probe allowlist,
- attempt authentication against any discovered API,
- exfiltrate secrets it finds (if you grep up a real API key, redact it in
  `findings/` via `prepare.redact` and warn the human; never write secrets
  to disk verbatim).

Before starting the loop, confirm authorization with the human:
- codebase mode: own code, permitted audit, CTF, or public OSS.
- endpoint mode: own API, vendor with an active engagement, public API
  with terms-of-service that permit automated requests, or a CTF target.
If scope is unclear, stop and ask.
