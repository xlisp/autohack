"""
hack.py — the mutable scanner. THIS IS THE FILE THE AGENT EDITS.

Baseline behaviour (pass 1):
  1. resolve target directory
  2. parse every manifest under it (npm/pypi/cargo/go/...)
  3. grep source for HTTP-client call sites (fetch/axios/requests/...)
  4. union: every dependency that looks like an external SaaS SDK, plus every
     remote host extracted from a URL string literal
  5. write a row to findings/apis.tsv, write one stub findings/apis/<slug>.md
     per discovery, print the summary

This baseline is intentionally shallow. The agent's job is to extend it pass
by pass — add ecosystems (composer, gradle, terraform), add HTTP-client
libraries, add env-var attribution, add config-file scanning (yaml/toml/k8s),
add doc-mining (via WebFetch from the agent loop, not from here), tighten
scoring, drop noisy false positives.

The pass interface is stable:
  - read target from prepare.target_dir()
  - end with prepare.print_summary(...)
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


# ---------- one scan pass ----------

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


# ---------- entrypoint ----------

def main() -> None:
    prepare.ensure_findings_dirs()
    target = prepare.target_dir()

    # Pass number is read from the existing TSV (header + N data rows -> next is N+1).
    existing = prepare.TSV_PATH.read_text().splitlines()
    pass_no = max(1, len(existing))  # header counts as "0 data rows" -> first pass is 1

    t0 = time.monotonic()
    new_apis, total_apis, endpoints_found, docs_mined, files_scanned, coverage_pct = scan(target, pass_no)
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
    main()
