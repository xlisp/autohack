"""
prepare.py — fixed utilities for autohack. DO NOT MODIFY.

Provides:
- target discovery (TARGET_DIR / target.txt)
- manifest parsers (package.json, requirements.txt, pyproject.toml, go.mod,
  Cargo.toml, Gemfile, composer.json, pom.xml, build.gradle)
- file walker with extension / size filters
- structured writers for findings/apis.tsv and findings/apis/<slug>.md
- redaction helper for accidentally-grepped secrets

The mutable pass logic lives in hack.py. Heuristics, regexes, and scoring all
belong there — this file is the contract that hack.py builds on.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Iterator

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

def target_dir() -> Path:
    """Resolve the target directory. Prefer $TARGET_DIR, then target.txt."""
    env = os.environ.get("TARGET_DIR")
    if env:
        p = Path(env).expanduser().resolve()
        if not p.is_dir():
            sys.exit(f"TARGET_DIR={env} is not a directory")
        return p
    txt = REPO_ROOT / "target.txt"
    if txt.is_file():
        p = Path(txt.read_text().strip()).expanduser().resolve()
        if not p.is_dir():
            sys.exit(f"target.txt points to {p}, which is not a directory")
        return p
    sys.exit(
        "No target configured. Set $TARGET_DIR or write the absolute path "
        "into target.txt at the repo root."
    )


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
