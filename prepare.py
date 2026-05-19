"""
prepare.py — fixed utilities for autohack. DO NOT MODIFY.

Provides:
- target discovery (TARGET_DIR / target.txt) — resolves to either a local
  codebase path OR a remote API URL
- manifest parsers (package.json, requirements.txt, pyproject.toml, go.mod,
  Cargo.toml, Gemfile, composer.json, pom.xml, build.gradle)
- file walker with extension / size filters
- polite HTTP probes for endpoint mode (well-known files, HEAD, OPTIONS) —
  hard-capped request budget, fixed User-Agent, no credentials ever
- structured writers for findings/apis.tsv and findings/apis/<slug>.md
- redaction helper for accidentally-grepped secrets

The mutable pass logic lives in hack.py. Heuristics, regexes, and scoring all
belong there — this file is the contract that hack.py builds on.
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlparse, urljoin

try:
    import httpx
except ImportError:  # endpoint mode is optional; codebase mode still works
    httpx = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parent
FINDINGS_DIR = REPO_ROOT / "findings"
APIS_DIR = FINDINGS_DIR / "apis"
TSV_PATH = FINDINGS_DIR / "apis.tsv"
COVERAGE_PATH = FINDINGS_DIR / "coverage.md"

# File extensions worth scanning. Keep narrow on purpose — the agent can
# widen this via hack.py if a target needs it.
DEFAULT_CODE_EXTS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".py", ".rb", ".go", ".rs", ".java", ".kt", ".scala",
    ".php", ".cs", ".swift", ".m", ".mm",
    ".sh", ".bash", ".zsh",
    ".yaml", ".yml", ".toml", ".json", ".env", ".ini",
    ".tf", ".hcl", ".dockerfile",
}

# Hard cap: never read individual files larger than this (mostly avoids
# choking on minified bundles, lockfiles, source maps).
MAX_FILE_BYTES = 1_000_000  # 1 MB

# Directories to skip outright.
SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "out", ".next", ".nuxt",
    "__pycache__", ".venv", "venv", "target", "vendor", "third_party",
    ".cache", "coverage", ".turbo", ".parcel-cache",
}

# Known minified / generated suffixes — skip even if small.
SKIP_FILE_PATTERNS = (".min.js", ".min.css", ".map", "-lock.json", ".lock")


# ---------- target discovery ----------

@dataclass
class Target:
    mode: str            # "codebase" or "endpoint"
    path: Path | None    # set when mode == "codebase"
    url: str | None      # set when mode == "endpoint" — the canonical base URL


def _looks_like_url(s: str) -> bool:
    return s.startswith(("http://", "https://"))


def target() -> Target:
    """Resolve the target. Prefer $TARGET_DIR, then target.txt. A value that
    starts with http(s):// switches to endpoint mode."""
    raw = os.environ.get("TARGET_DIR")
    if not raw:
        txt = REPO_ROOT / "target.txt"
        if txt.is_file():
            raw = txt.read_text().strip()
    if not raw:
        sys.exit(
            "No target configured. Set $TARGET_DIR or write a path / URL "
            "into target.txt at the repo root."
        )

    if _looks_like_url(raw):
        parsed = urlparse(raw)
        if not parsed.netloc:
            sys.exit(f"target {raw!r} looks like a URL but has no host")
        # Canonicalize: scheme + host + path-prefix (drop query/fragment).
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}".rstrip("/")
        return Target(mode="endpoint", path=None, url=base)

    p = Path(raw).expanduser().resolve()
    if not p.is_dir():
        sys.exit(f"target {raw!r} is neither a URL nor an existing directory")
    return Target(mode="codebase", path=p, url=None)


def target_dir() -> Path:
    """Back-compat shim for any caller that wants codebase mode only."""
    t = target()
    if t.mode != "codebase" or t.path is None:
        sys.exit("target is configured as a URL — use prepare.target() instead")
    return t.path


# ---------- file walking ----------

def iter_files(
    root: Path,
    exts: set[str] | None = None,
    max_bytes: int = MAX_FILE_BYTES,
) -> Iterator[Path]:
    """Yield files under `root` worth scanning. Skips SKIP_DIRS, big files,
    minified files, lockfiles."""
    exts = exts if exts is not None else DEFAULT_CODE_EXTS
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if any(name.endswith(p) for p in SKIP_FILE_PATTERNS):
                continue
            ext = Path(name).suffix.lower()
            if exts and ext not in exts and name.lower() not in {
                "dockerfile", "makefile", ".env.example", ".env.sample"
            }:
                continue
            full = Path(dirpath) / name
            try:
                if full.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield full


def read_text(path: Path) -> str:
    """Best-effort text read; returns '' on any failure (binary, perms)."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---------- manifest parsers ----------

@dataclass
class ManifestEntry:
    ecosystem: str         # npm / pypi / cargo / go / rubygems / composer / maven / gradle
    name: str
    version: str | None
    dev: bool = False
    source_path: str = ""  # relative path of the manifest file

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}"


def parse_manifests(root: Path) -> list[ManifestEntry]:
    """Walk the target and parse every supported manifest. Returns a flat list
    of (ecosystem, name, version) tuples. The agent can dedupe / enrich in
    hack.py."""
    out: list[ManifestEntry] = []
    for path in iter_files(root, exts={".json", ".toml", ".txt", ".mod", ".gemspec"}):
        rel = str(path.relative_to(root))
        name = path.name
        try:
            if name == "package.json":
                out += _parse_package_json(path, rel)
            elif name == "requirements.txt" or name.endswith("requirements.txt"):
                out += _parse_requirements_txt(path, rel)
            elif name == "pyproject.toml":
                out += _parse_pyproject(path, rel)
            elif name == "Cargo.toml":
                out += _parse_cargo(path, rel)
            elif name == "go.mod":
                out += _parse_go_mod(path, rel)
            elif name == "Gemfile" or name.endswith(".gemspec"):
                out += _parse_gemfile(path, rel)
            elif name == "composer.json":
                out += _parse_composer(path, rel)
        except Exception as e:  # noqa: BLE001 — best-effort
            print(f"WARN: failed to parse {rel}: {e}", file=sys.stderr)
    return out


def _parse_package_json(path: Path, rel: str) -> list[ManifestEntry]:
    data = json.loads(read_text(path) or "{}")
    out: list[ManifestEntry] = []
    for section, is_dev in (("dependencies", False), ("devDependencies", True),
                            ("peerDependencies", False), ("optionalDependencies", False)):
        for n, v in (data.get(section) or {}).items():
            out.append(ManifestEntry("npm", n, str(v), is_dev, rel))
    return out


_REQ_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~]=?.*)?$")

def _parse_requirements_txt(path: Path, rel: str) -> list[ManifestEntry]:
    out: list[ManifestEntry] = []
    for raw in read_text(path).splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if m:
            out.append(ManifestEntry("pypi", m.group(1), (m.group(2) or "").strip() or None, False, rel))
    return out


def _parse_pyproject(path: Path, rel: str) -> list[ManifestEntry]:
    # No tomllib import drama: try stdlib, fall back to a tiny regex grep.
    text = read_text(path)
    try:
        import tomllib  # py311+
        data = tomllib.loads(text)
    except Exception:
        return _grep_toml_deps(text, rel, "pypi")
    out: list[ManifestEntry] = []
    deps = (data.get("project") or {}).get("dependencies") or []
    for spec in deps:
        m = _REQ_RE.match(spec)
        if m:
            out.append(ManifestEntry("pypi", m.group(1), (m.group(2) or "").strip() or None, False, rel))
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for n, v in poetry.items():
        if n.lower() == "python":
            continue
        out.append(ManifestEntry("pypi", n, str(v), False, rel))
    return out


def _grep_toml_deps(text: str, rel: str, ecosystem: str) -> list[ManifestEntry]:
    out: list[ManifestEntry] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = "dependencies" in stripped.lower()
            continue
        if not in_deps or not stripped or stripped.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"?([^"]*)"?', stripped)
        if m:
            out.append(ManifestEntry(ecosystem, m.group(1), m.group(2) or None, False, rel))
    return out


def _parse_cargo(path: Path, rel: str) -> list[ManifestEntry]:
    return _grep_toml_deps(read_text(path), rel, "cargo")


_GO_REQ_RE = re.compile(r"^\s*([^\s]+)\s+([^\s]+)")

def _parse_go_mod(path: Path, rel: str) -> list[ManifestEntry]:
    out: list[ManifestEntry] = []
    in_block = False
    for line in read_text(path).splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if s.startswith("require "):
            s = s[len("require "):]
        elif not in_block:
            continue
        m = _GO_REQ_RE.match(s)
        if m and not m.group(1).startswith("//"):
            out.append(ManifestEntry("go", m.group(1), m.group(2), False, rel))
    return out


_GEM_RE = re.compile(r"^\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?")

def _parse_gemfile(path: Path, rel: str) -> list[ManifestEntry]:
    out: list[ManifestEntry] = []
    for line in read_text(path).splitlines():
        m = _GEM_RE.match(line)
        if m:
            out.append(ManifestEntry("rubygems", m.group(1), m.group(2), False, rel))
    return out


def _parse_composer(path: Path, rel: str) -> list[ManifestEntry]:
    data = json.loads(read_text(path) or "{}")
    out: list[ManifestEntry] = []
    for section, is_dev in (("require", False), ("require-dev", True)):
        for n, v in (data.get(section) or {}).items():
            out.append(ManifestEntry("composer", n, str(v), is_dev, rel))
    return out


# ---------- structured writers ----------

TSV_HEADER = "commit\tpass\ttotal_apis\tdocs_mined\tstatus\tdescription"


def ensure_findings_dirs() -> None:
    FINDINGS_DIR.mkdir(exist_ok=True)
    APIS_DIR.mkdir(exist_ok=True)
    if not TSV_PATH.exists():
        TSV_PATH.write_text(TSV_HEADER + "\n")
    if not COVERAGE_PATH.exists():
        COVERAGE_PATH.write_text("# Coverage\n\n_Populated by hack.py per pass._\n")


def append_tsv_row(commit: str, pass_no: int, total_apis: int, docs_mined: int,
                   status: str, description: str) -> None:
    if "\t" in description or "\n" in description:
        description = description.replace("\t", " ").replace("\n", " ")
    row = f"{commit}\t{pass_no}\t{total_apis}\t{docs_mined}\t{status}\t{description}\n"
    with TSV_PATH.open("a") as f:
        f.write(row)


def slugify(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", name.strip().lower()).strip("-")
    return s or "unknown"


def write_api_report(slug: str, body: str) -> Path:
    p = APIS_DIR / f"{slug}.md"
    p.write_text(body)
    return p


# ---------- secret redaction ----------

# Conservative — false positives are fine, false negatives are not.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(sk_live_[A-Za-z0-9]{20,})"),
    re.compile(r"(?i)(sk_test_[A-Za-z0-9]{20,})"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"ghp_[0-9A-Za-z]{36,}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
]


def redact(text: str) -> str:
    """Mask anything that looks like a live credential. Used before writing
    grep snippets into findings/."""
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: m.group(0)[:6] + "…REDACTED", out)
    return out


# ---------- polite HTTP probes (endpoint mode) ----------

USER_AGENT = "autohack/0.1 (+https://github.com/anthropics/claude-code; static-recon)"

# Hard caps. The agent CANNOT raise these from hack.py — endpoint mode is
# explicitly "polite recon", not a fuzzer.
PROBE_TIMEOUT_S = 10
PROBE_BUDGET_PER_HOST = 25  # max requests per host per pass
PROBE_MAX_BODY_BYTES = 256 * 1024  # 256 KB

# Allowed probe paths. Anything not on this list requires explicit human
# approval via env var ALLOW_EXTRA_PROBES=1 (still no auth, still no writes).
WELL_KNOWN_PATHS = (
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/security.txt",
    "/.well-known/host-meta",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/api-docs",          # springdoc
    "/api/v1/openapi.json",
    "/api/swagger.json",
    "/robots.txt",
    "/sitemap.xml",
)

# Methods that are read-only and side-effect-free on conformant servers.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ProbeBudgetExceeded(RuntimeError):
    pass


@dataclass
class ProbeResult:
    url: str
    method: str
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""        # first PROBE_MAX_BODY_BYTES, decoded best-effort
    body_truncated: bool = False
    error: str | None = None      # populated on network failure / timeout


class ProbeSession:
    """Polite HTTP session. Refuses non-safe methods, refuses to send any
    Authorization / Cookie headers, hard-caps requests per host."""

    def __init__(self) -> None:
        if httpx is None:
            raise RuntimeError("httpx not installed; cannot run endpoint mode")
        self._client = httpx.Client(
            timeout=PROBE_TIMEOUT_S,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        self._spent: dict[str, int] = {}

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ProbeSession":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _charge(self, url: str) -> None:
        host = urlparse(url).hostname or ""
        n = self._spent.get(host, 0) + 1
        self._spent[host] = n
        if n > PROBE_BUDGET_PER_HOST:
            raise ProbeBudgetExceeded(
                f"per-host budget ({PROBE_BUDGET_PER_HOST}) exhausted for {host}"
            )

    def request(self, method: str, url: str) -> ProbeResult:
        method = method.upper()
        if method not in SAFE_METHODS:
            return ProbeResult(url=url, method=method, status=None,
                               error=f"refusing non-safe method {method}")
        self._charge(url)
        try:
            r = self._client.request(method, url)
        except httpx.HTTPError as e:
            return ProbeResult(url=url, method=method, status=None, error=str(e))
        body = r.content[:PROBE_MAX_BODY_BYTES]
        try:
            text = body.decode(r.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            text = body.decode("utf-8", errors="replace")
        return ProbeResult(
            url=str(r.url),
            method=method,
            status=r.status_code,
            headers=dict(r.headers),
            body_preview=text,
            body_truncated=len(r.content) > PROBE_MAX_BODY_BYTES,
        )

    def get(self, url: str) -> ProbeResult: return self.request("GET", url)
    def head(self, url: str) -> ProbeResult: return self.request("HEAD", url)
    def options(self, url: str) -> ProbeResult: return self.request("OPTIONS", url)


def probe_well_known(session: ProbeSession, base_url: str) -> list[ProbeResult]:
    """Fetch every well-known discovery endpoint that exists. Skips 404/405
    quickly; only kept results are returned."""
    results: list[ProbeResult] = []
    for path in WELL_KNOWN_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = session.get(url)
        except ProbeBudgetExceeded:
            break
        if r.status and 200 <= r.status < 400 and r.body_preview:
            results.append(r)
    return results


def tls_san_names(host: str, port: int = 443) -> list[str]:
    """Read the Subject Alternative Names from the TLS certificate. Useful
    for discovering related hosts (e.g. api.foo.com -> *.foo.com)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
        names = []
        for typ, val in cert.get("subjectAltName", ()):
            if typ.lower() == "dns":
                names.append(val)
        return names
    except (socket.error, ssl.SSLError, OSError):
        return []


# ---------- summary printer (called by hack.py) ----------

def print_summary(pass_no: int, new_apis: int, total_apis: int,
                  endpoints_found: int, docs_mined: int,
                  files_scanned: int, coverage_pct: float,
                  elapsed_seconds: float) -> None:
    """Stable summary format. hack.py MUST end its run with this so the agent
    can grep ^pass: / ^total_apis: / ^coverage_pct: out of the log."""
    print("---")
    print(f"pass:              {pass_no}")
    print(f"new_apis:          {new_apis}")
    print(f"total_apis:        {total_apis}")
    print(f"endpoints_found:   {endpoints_found}")
    print(f"docs_mined:        {docs_mined}")
    print(f"files_scanned:     {files_scanned}")
    print(f"coverage_pct:      {coverage_pct:.1f}")
    print(f"elapsed_seconds:   {elapsed_seconds:.1f}")
