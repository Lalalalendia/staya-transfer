"""Fail-closed STAYA PR workflow selection and auto-merge eligibility.

The rules mirror the current on.pull_request.paths filters in
.github/workflows/*.yml. Unknown paths are an ERROR, not "docs only".
Run unit tests before modifying this registry or any workflow path filters.

This file is not an authorization to merge. Native GitHub branch protection
and required checks MUST be configured by the repository administrator.
"""
from __future__ import annotations

from fnmatch import fnmatchcase


WORKFLOW_PATTERNS: dict[str, tuple[str, ...]] = {
    "Iroh FsStore compatibility": (
        "interop/**",
        ".github/workflows/iroh-compat.yml",
        "Cargo.toml",
        "Cargo.lock",
        "src/**",
    ),
    "STY-G1g distinct Docker network direct QUIC preview": (
        "interop/**",
        ".github/workflows/g1g-isolated-network-preview.yml",
    ),
    "STY-G2 real Windows FsStore crash recovery": (
        "interop/**",
        "custody/**",
        "native-windows-host/**",
        ".github/workflows/g2-windows-fsstore-kill.yml",
        "Cargo.toml",
        "Cargo.lock",
        "src/**",
    ),
    "STY-G2 cooperative writer custody": (
        "custody/**",
        "interop/fsstore_partial_adapter.rs",
        "interop/fsstore_partial_gate.rs",
        "interop/fsstore_shutdown_supervisor.rs",
        ".github/workflows/g2-custody.yml",
    ),
    "STY-G2-05h3e Linux native parent-death laboratory": (
        "native-host/**",
        ".github/workflows/g2-native-linux-parent.yml",
    ),
    "STY-G2-05h3f Windows suspended JobObject laboratory": (
        "native-windows-host/**",
        ".github/workflows/g2-native-windows-job.yml",
    ),
}

ALWAYS_REQUIRED = "Rust contracts"
# These are the ONLY paths safe for automatic enrollment in native auto-merge.
DOCS_ONLY = ("README.md", "docs/**/*.md", "docs/*.md")
# All other current repository paths must be explicitly covered before they
# can be evaluated. This protects against new, unreviewed build/script areas.
KNOWN_NON_DOC_PATHS = (
    ".gitignore",
    "LICENSE-MIT",
    "Cargo.toml",
    "Cargo.lock",
    "src/**",
    "interop/**",
    "custody/**",
    "native-host/**",
    "native-windows-host/**",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".github/scripts/**",
    ".github/dependabot.yml",
    ".github/CODEOWNERS",
)


class UnsafePathError(ValueError):
    """A new path family has no explicit CI policy."""


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(path, pattern) for pattern in patterns)


def changed_paths(files: list[dict]) -> set[str]:
    """Include both sides of a rename so old scopes cannot evade a gate."""
    if not files:
        raise UnsafePathError("PR file list empty or unavailable")
    paths: set[str] = set()
    for item in files:
        name = item.get("filename")
        if not isinstance(name, str) or not name or name.startswith("/"):
            raise UnsafePathError("missing or unsafe changed filename")
        paths.add(name)
        if item.get("status") == "renamed":
            previous = item.get("previous_filename")
            if not isinstance(previous, str) or not previous:
                raise UnsafePathError("rename has no previous_filename")
            paths.add(previous)
    return paths


def docs_only(paths: set[str]) -> bool:
    return bool(paths) and all(_matches(p, DOCS_ONLY) for p in paths)


def required_workflows(paths: set[str]) -> set[str]:
    if not paths:
        raise UnsafePathError("no changed paths")
    for path in paths:
        if not (_matches(path, DOCS_ONLY) or _matches(path, KNOWN_NON_DOC_PATHS)):
            raise UnsafePathError(f"unclassified PR path: {path}")
    return {ALWAYS_REQUIRED} | {
        name
        for name, patterns in WORKFLOW_PATTERNS.items()
        if any(_matches(p, patterns) for p in paths)
    }


def risk_class(paths: set[str]) -> str:
    """Informational. Never treat it as a substitute for required reviews."""
    if docs_only(paths):
        return "docs-only"
    if any(
        p.startswith((
            ".github/workflows/", ".github/scripts/", "interop/", "custody/",
            "native-host/", "native-windows-host/",
        )) or p in ("Cargo.lock", "Cargo.toml", ".github/dependabot.yml", ".github/CODEOWNERS")
        or p in ("src/bao.rs", "src/recovery.rs")
        for p in paths
    ):
        return "sensitive-manual"
    return "code-review"
