"""
hack.py — the mutable scanner. THIS IS THE FILE THE AGENT EDITS.

Two target modes (auto-detected by prepare.target()):

  codebase mode (target is a directory)
    1. parse every manifest (npm/pypi/cargo/go/...)
    2. grep source for HTTP-client call sites (fetch/axios/requests/...)
    3. union: every dep that looks like an external SaaS SDK, plus every
       remote host extracted from a URL string literal
    4. write findings/apis/<slug>.md stubs; agent later WebFetches docs

  endpoint mode (target is an http(s):// URL)
    1. poll the well-known discovery endpoints (OpenAPI / OIDC / OAuth /
       JWKS / robots.txt / sitemap.xml) via prepare.ProbeSession — polite
       only, no auth headers ever, capped at PROBE_BUDGET_PER_HOST requests
    2. parse the OpenAPI doc if present -> enumerate paths + auth schemes
    3. parse the OIDC config if present -> identify authorization_endpoint,
       token_endpoint, jwks_uri, supported scopes/grant types
    4. read TLS SAN list -> sibling hostnames worth a follow-up pass
    5. record HTTP response headers (WWW-Authenticate, X-RateLimit-*,
       CORS-related) — they reveal the auth scheme without trying any creds
    6. agent then loop-step searches the public web (WebSearch / WebFetch)
       for "<host> API documentation" and for callers (github code search,
       grep.app, sourcegraph) and writes them into the per-API report

The pass interface is stable: end with prepare.print_summary(...). The agent
extends heuristics pass by pass. Adding new active probes BEYOND the
prepare.WELL_KNOWN_PATHS allowlist is FORBIDDEN — that would turn polite
recon into fuzzing.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import prepare


# ---------- known-SaaS allowlist (extend freely) ----------
# Maps a normalised name -> canonical vendor label. Match against manifest
# entries OR import statements. The point is to bias toward real external
# APIs and away from utility libs (lodash, chalk, etc).
KNOWN_SAAS: dict[str, str] = {
    "stripe": "Stripe",
    "@stripe/stripe-js": "Stripe",
    "twilio": "Twilio",
    "@sendgrid/mail": "SendGrid",
    "mailgun.js": "Mailgun",
    "mailgun-js": "Mailgun",
    "@auth0/auth0-react": "Auth0",
    "@auth0/auth0-spa-js": "Auth0",
    "auth0": "Auth0",
    "firebase": "Firebase",
    "@firebase/app": "Firebase",
    "@supabase/supabase-js": "Supabase",
    "supabase": "Supabase",
    "algoliasearch": "Algolia",
    "@algolia/client-search": "Algolia",
    "openai": "OpenAI",
    "@anthropic-ai/sdk": "Anthropic",
    "anthropic": "Anthropic",
    "@google-cloud/storage": "Google Cloud Storage",
    "@aws-sdk/client-s3": "AWS S3",
    "boto3": "AWS (boto3)",
    "@sentry/node": "Sentry",
    "@sentry/browser": "Sentry",
    "sentry-sdk": "Sentry",
    "posthog-js": "PostHog",
    "mixpanel-browser": "Mixpanel",
    "segment-analytics": "Segment",
    "@segment/analytics-node": "Segment",
    "datadog": "Datadog",
    "@datadog/browser-rum": "Datadog",
    "redis": "Redis",
    "ioredis": "Redis",
    "pg": "Postgres",
    "mysql2": "MySQL",
    "mongodb": "MongoDB",
    "mongoose": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "@elastic/elasticsearch": "Elasticsearch",
    "requests": "generic HTTP (Python)",
    "httpx": "generic HTTP (Python)",
    "axios": "generic HTTP (JS)",
    "got": "generic HTTP (JS)",
    "node-fetch": "generic HTTP (JS)",
}

# Hostnames whose appearance in a URL literal is a strong signal — same
# canonical labels as above. Extend as you discover targets.
KNOWN_HOSTS: dict[str, str] = {
    "api.stripe.com": "Stripe",
    "api.twilio.com": "Twilio",
    "api.sendgrid.com": "SendGrid",
    "api.mailgun.net": "Mailgun",
    "*.auth0.com": "Auth0",
    "*.firebaseio.com": "Firebase",
    "*.supabase.co": "Supabase",
    "*.algolia.net": "Algolia",
    "api.openai.com": "OpenAI",
    "api.anthropic.com": "Anthropic",
    "*.s3.amazonaws.com": "AWS S3",
    "sentry.io": "Sentry",
    "app.posthog.com": "PostHog",
    "api.mixpanel.com": "Mixpanel",
    "api.segment.io": "Segment",
}


# ---------- regex bank (the agent extends this) ----------

URL_RE = re.compile(
    r"""['"`]                              # opening quote
        (https?://[^\s'"`<>]{4,})          # URL
        ['"`]""",
    re.VERBOSE,
)

# JS / TS HTTP call sites.
JS_CALL_RE = re.compile(
    r"\b(fetch|axios|got|ky|superagent|request)\s*[.(]"
)

# Python HTTP call sites.
PY_CALL_RE = re.compile(
    r"\b(requests|httpx|aiohttp|urllib3?)\.(get|post|put|delete|patch|request|Session)\b"
)

# Common env-var idioms that point at a 3rd-party API.
ENV_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]{4,})(?:_API_KEY|_TOKEN|_SECRET|_URL|_ENDPOINT|_HOST)\b"
)


# ---------- discovery model ----------

@dataclass
class Discovery:
    canonical: str               # e.g. "Stripe"
    sources: set[str] = field(default_factory=set)   # "manifest:npm:stripe", "host:api.stripe.com"
    evidence: list[str] = field(default_factory=list)  # "file:line" snippets
    endpoints: set[str] = field(default_factory=set)
    env_vars: set[str] = field(default_factory=set)

    def slug(self) -> str:
        return prepare.slugify(self.canonical)


def host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) or host == pattern[2:]
    return host == pattern


def canonicalize_host(host: str) -> str | None:
    for pat, label in KNOWN_HOSTS.items():
        if host_matches(host, pat):
            return label
    return None


# ---------- one scan pass (codebase mode) ----------

def scan(target: Path, pass_no: int) -> tuple[int, int, int, int, int, float]:
    """Returns (new_apis, total_apis, endpoints_found, docs_mined, files_scanned, coverage_pct)."""
    discoveries: dict[str, Discovery] = {}

    def discovery(canonical: str) -> Discovery:
        if canonical not in discoveries:
            discoveries[canonical] = Discovery(canonical=canonical)
        return discoveries[canonical]

    # --- 1. manifest scan ---
    manifests = prepare.parse_manifests(target)
    manifest_total = len(manifests)
    manifest_attributed = 0
    for m in manifests:
        label = KNOWN_SAAS.get(m.name.lower())
        if label:
            d = discovery(label)
            d.sources.add(f"manifest:{m.ecosystem}:{m.name}@{m.version}")
            d.evidence.append(f"{m.source_path}: dep {m.name}@{m.version}")
            manifest_attributed += 1

    # --- 2. source grep ---
    files_scanned = 0
    endpoints_found = 0
    for path in prepare.iter_files(target):
        files_scanned += 1
        text = prepare.read_text(path)
        if not text:
            continue
        rel = str(path.relative_to(target))

        # URL literals -> attribute by host
        for m in URL_RE.finditer(text):
            url = m.group(1)
            try:
                host = urlparse(url).hostname or ""
            except ValueError:
                continue
            label = canonicalize_host(host)
            if label:
                d = discovery(label)
                d.sources.add(f"host:{host}")
                d.endpoints.add(urlparse(url).path or "/")
                endpoints_found += 1
                line_no = text.count("\n", 0, m.start()) + 1
                d.evidence.append(f"{rel}:{line_no} {prepare.redact(url)}")

        # env-var idioms — record the prefix as a hint; agent attributes later
        for m in ENV_RE.finditer(text):
            prefix = m.group(1).lower()
            for key, label in KNOWN_SAAS.items():
                if prefix in key.lower():
                    d = discovery(label)
                    d.env_vars.add(m.group(0))
                    line_no = text.count("\n", 0, m.start()) + 1
                    d.evidence.append(f"{rel}:{line_no} env {m.group(0)}")
                    break

    # --- 3. write per-API stub reports ---
    docs_mined = 0  # baseline doesn't WebFetch; the agent does that from the loop
    for d in discoveries.values():
        body = render_stub(d)
        prepare.write_api_report(d.slug(), body)

    # --- 4. coverage ---
    coverage_pct = (manifest_attributed / manifest_total * 100.0) if manifest_total else 0.0
    write_coverage(manifests, discoveries)

    # In the baseline every discovery is "new" — the agent's loop diffs against
    # the previous pass and computes new_apis itself before logging the TSV row.
    new_apis = len(discoveries)
    total_apis = len(discoveries)
    return new_apis, total_apis, endpoints_found, docs_mined, files_scanned, coverage_pct


def render_stub(d: Discovery) -> str:
    lines = [f"# {d.canonical}", ""]
    lines.append(f"- **Sources**: {', '.join(sorted(d.sources)) or '—'}")
    lines.append(f"- **Env vars**: {', '.join(sorted(d.env_vars)) or '—'}")
    lines.append(f"- **Docs**: _to be auto-mined by the agent loop_")
    lines.append("")
    if d.endpoints:
        lines.append("## Endpoints / paths observed")
        for ep in sorted(d.endpoints):
            lines.append(f"- `{ep}`")
        lines.append("")
    lines.append("## Evidence")
    for ev in d.evidence[:50]:
        lines.append(f"- {ev}")
    if len(d.evidence) > 50:
        lines.append(f"- _… {len(d.evidence) - 50} more_")
    lines.append("")
    return "\n".join(lines)


def write_coverage(manifests: list[prepare.ManifestEntry],
                   discoveries: dict[str, Discovery]) -> None:
    attributed_keys: set[str] = set()
    for d in discoveries.values():
        for s in d.sources:
            if s.startswith("manifest:"):
                _, eco, rest = s.split(":", 2)
                name = rest.split("@", 1)[0]
                attributed_keys.add(f"{eco}:{name}")

    lines = ["# Coverage", "", "## Manifest entries", ""]
    for m in sorted(manifests, key=lambda x: (x.ecosystem, x.name.lower())):
        mark = "x" if m.key() in attributed_keys else " "
        lines.append(f"- [{mark}] `{m.key()}` ({m.source_path})")
    prepare.COVERAGE_PATH.write_text("\n".join(lines) + "\n")


# ---------- one scan pass (endpoint mode) ----------

def scan_endpoint(base_url: str, pass_no: int) -> tuple[int, int, int, int, int, float]:
    """Polite recon of a remote API. Returns the same tuple shape as scan()
    so the caller's summary code doesn't care which mode ran."""
    from urllib.parse import urlparse
    host = urlparse(base_url).hostname or base_url
    canonical = host

    discoveries: dict[str, Discovery] = {}
    d = Discovery(canonical=canonical)
    discoveries[canonical] = d

    endpoints_found = 0
    docs_mined = 0
    files_scanned = 0  # repurposed: number of probes sent

    with prepare.ProbeSession() as sess:
        # 1) base URL: HEAD then OPTIONS — surfaces auth scheme via headers.
        for method in ("HEAD", "OPTIONS"):
            r = sess.request(method, base_url)
            files_scanned += 1
            if r.error:
                d.evidence.append(f"{method} {base_url} -> error: {r.error}")
                continue
            d.evidence.append(f"{method} {base_url} -> {r.status}")
            _record_auth_hints(d, r.headers)

        # 2) well-known discovery endpoints.
        for r in prepare.probe_well_known(sess, base_url):
            files_scanned += 1
            d.sources.add(f"well-known:{urlparse(r.url).path}")
            d.evidence.append(f"GET {r.url} -> {r.status} ({len(r.body_preview)}B)")
            _ingest_well_known(d, r)
            endpoints_found += _count_paths_from(r)

        # 3) TLS SAN list -> sibling hosts (record only; agent decides whether
        # to schedule follow-up passes against them, with explicit user OK).
        for san in prepare.tls_san_names(host):
            d.evidence.append(f"tls-san: {san}")

    # Write the report stub. Doc mining (WebFetch on the docs URL we found)
    # happens in the agent's loop step, not here.
    body = render_endpoint_stub(d, base_url)
    prepare.write_api_report(prepare.slugify(canonical), body)

    coverage_pct = 100.0 if d.sources else 0.0
    new_apis = 1
    total_apis = 1
    return new_apis, total_apis, endpoints_found, docs_mined, files_scanned, coverage_pct


# Header names that announce the auth scheme without us trying any creds.
_AUTH_HEADER_HINTS = {
    "www-authenticate": "challenge",
    "x-api-key": "api-key-header",
    "x-amz-security-token": "aws-sigv4",
    "x-goog-api-key": "google-api-key",
}


def _record_auth_hints(d: Discovery, headers: dict[str, str]) -> None:
    lower = {k.lower(): v for k, v in headers.items()}
    for name, label in _AUTH_HEADER_HINTS.items():
        if name in lower:
            d.env_vars.add(f"{label}={lower[name][:80]}")


def _ingest_well_known(d: Discovery, r) -> None:
    """Parse the body of a well-known response — OpenAPI or OIDC."""
    text = r.body_preview
    path = urlparse(r.url).path
    if "openapi" in path or "swagger" in path or path.endswith("/api-docs"):
        spec = _try_json(text)
        if not spec:
            return
        # OpenAPI auth schemes
        comps = (spec.get("components") or {}).get("securitySchemes") or {}
        for name, scheme in comps.items():
            kind = scheme.get("type", "?")
            d.env_vars.add(f"openapi-security:{name}:{kind}")
        # Paths
        for p in (spec.get("paths") or {}):
            d.endpoints.add(p)
    elif path.endswith("openid-configuration") or path.endswith("oauth-authorization-server"):
        spec = _try_json(text)
        if not spec:
            return
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri",
                    "issuer", "userinfo_endpoint", "revocation_endpoint"):
            v = spec.get(key)
            if v:
                d.env_vars.add(f"oidc:{key}={v}")
        for key in ("grant_types_supported", "scopes_supported",
                    "response_types_supported"):
            vals = spec.get(key)
            if isinstance(vals, list):
                d.env_vars.add(f"oidc:{key}=" + ",".join(map(str, vals[:8])))


def _try_json(text: str) -> dict | None:
    import json
    try:
        v = json.loads(text)
        return v if isinstance(v, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _count_paths_from(r) -> int:
    if not r.body_preview:
        return 0
    spec = _try_json(r.body_preview)
    if not spec:
        return 0
    return len(spec.get("paths") or {})


def render_endpoint_stub(d: Discovery, base_url: str) -> str:
    lines = [f"# {d.canonical}", ""]
    lines.append(f"- **Base URL**: {base_url}")
    lines.append(f"- **Discovery sources**: {', '.join(sorted(d.sources)) or '—'}")
    lines.append(f"- **Auth hints**: {', '.join(sorted(d.env_vars)) or '—'}")
    lines.append(f"- **Docs**: _to be auto-mined by the agent loop_")
    lines.append(f"- **Callers in the wild**: _to be auto-mined (WebSearch / code search) by the agent_")
    lines.append("")
    if d.endpoints:
        lines.append("## Paths (from OpenAPI)")
        for ep in sorted(d.endpoints):
            lines.append(f"- `{ep}`")
        lines.append("")
    lines.append("## Probe log")
    for ev in d.evidence:
        lines.append(f"- {ev}")
    lines.append("")
    return "\n".join(lines)


# ---------- entrypoint ----------

def main() -> None:
    prepare.ensure_findings_dirs()
    tgt = prepare.target()

    # Pass number is read from the existing TSV (header + N data rows -> next is N+1).
    existing = prepare.TSV_PATH.read_text().splitlines()
    pass_no = max(1, len(existing))  # header counts as "0 data rows" -> first pass is 1

    t0 = time.monotonic()
    if tgt.mode == "codebase":
        assert tgt.path is not None
        result = scan(tgt.path, pass_no)
    elif tgt.mode == "endpoint":
        assert tgt.url is not None
        result = scan_endpoint(tgt.url, pass_no)
    else:
        sys.exit(f"unknown target mode: {tgt.mode}")
    new_apis, total_apis, endpoints_found, docs_mined, files_scanned, coverage_pct = result
    elapsed = time.monotonic() - t0

    prepare.print_summary(
        pass_no=pass_no,
        new_apis=new_apis,
        total_apis=total_apis,
        endpoints_found=endpoints_found,
        docs_mined=docs_mined,
        files_scanned=files_scanned,
        coverage_pct=coverage_pct,
        elapsed_seconds=elapsed,
    )


if __name__ == "__main__":
    import sys  # used in main() for the unknown-mode branch
    main()
