"""STAYA always-present merge check, using GitHub's exact PR head SHA.

This job is READ-ONLY. It does NOT merge, approve, label, dispatch or modify
anything. It waits for every applicable existing workflow after preflight.
Keep required path filters synchronized with staya_merge_policy.py.

The mandatory GitHub branch protection for main must require the
STY Merge Gate / ready check and branches up-to-date with main.
Without that admin setting, this job is informative, NOT a merge safeguard.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from staya_merge_policy import changed_paths, docs_only, required_workflows, risk_class


REQUIRED_WORKFLOW_PATHS = {
    "Rust contracts": ".github/workflows/ci.yml",
    "Iroh FsStore compatibility": ".github/workflows/iroh-compat.yml",
    "STY-G1g distinct Docker network direct QUIC preview":
        ".github/workflows/g1g-isolated-network-preview.yml",
    "STY-G2 real Windows FsStore crash recovery":
        ".github/workflows/g2-windows-fsstore-kill.yml",
    "STY-G2 cooperative writer custody":
        ".github/workflows/g2-custody.yml",
    "STY-G2-05h3e Linux native parent-death laboratory":
        ".github/workflows/g2-native-linux-parent.yml",
    "STY-G2-05h3f Windows suspended JobObject laboratory":
        ".github/workflows/g2-native-windows-job.yml",
}


def api_get(api: str, token: str, path: str):
    req = urllib.request.Request(
        api.rstrip("/") + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "staya-read-only-merge-gate",
        },
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=25) as response:
                return json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            retryable = not isinstance(exc, urllib.error.HTTPError) or exc.code in (
                429, 500, 502, 503, 504,
            )
            if not retryable or attempt == 2:
                raise RuntimeError(f"GitHub read failed: {path}: {type(exc).__name__}") from exc
            time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def read_all_pages(api: str, token: str, endpoint: str, array_key: str | None):
    rows = []
    for page in range(1, 11):
        query = "&" if "?" in endpoint else "?"
        response = api_get(api, token, f"{endpoint}{query}per_page=100&page={page}")
        items = response[array_key] if array_key else response
        if not isinstance(items, list):
            raise RuntimeError("GitHub returned a non-list page")
        rows.extend(items)
        if len(items) < 100:
            return rows
    raise RuntimeError("GitHub result exceeds 1000 items; refusing incomplete gate")


def latest_runs(api: str, token: str, repository: str, sha: str, pr_number: int):
    q = urllib.parse.quote(sha)
    runs = read_all_pages(
        api, token,
        f"/repos/{repository}/actions/runs?head_sha={q}&event=pull_request",
        "workflow_runs",
    )
    selected = {}
    for run in runs:
        if run.get("head_sha") != sha or run.get("event") != "pull_request":
            continue
        prs = run.get("pull_requests") or []
        if not any(item.get("number") == pr_number for item in prs):
            continue
        name = run.get("name")
        # Same-named but different workflow run MUST NEVER satisfy this gate.
        if REQUIRED_WORKFLOW_PATHS.get(name) != run.get("path"):
            continue
        old = selected.get(name)
        rank = (run.get("created_at") or "", run.get("run_attempt") or 0, run.get("id") or 0)
        old_rank = (
            old.get("created_at") or "", old.get("run_attempt") or 0,
            old.get("id") or 0,
        ) if old else None
        if old_rank is None or rank > old_rank:
            selected[name] = run
    return selected



def pending_or_fail(required: set[str], runs: dict[str, dict], sha: str):
    """Return pending names, or fail immediately for ANY non-success terminal."""
    pending = []
    for name in sorted(required):
        run = runs.get(name)
        if run is None:
            pending.append(f"{name}: not started")
            continue
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status == "completed" and conclusion == "success":
            continue
        if status == "completed":
            raise RuntimeError(
                f"required workflow {name} concluded {conclusion or 'unknown'} "
                f"on exact head {sha}: {run.get('html_url')}"
            )
        pending.append(f"{name}: {status or 'unknown'}")
    return pending


def check_current_pr(api: str, token: str, repository: str, number: int, sha: str):
    pr = api_get(api, token, f"/repos/{repository}/pulls/{number}")
    if pr["state"] != "open" or pr["head"]["sha"] != sha:
        raise RuntimeError("PR closed or head SHA changed during gate; refusing stale result")
    if pr["base"]["ref"] != "main":
        raise RuntimeError("this gate is configured for PRs targeting main only")
    return pr


def summary(message: str):
    print(message, flush=True)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(message + "\n")


def main():
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    token = os.environ["GITHUB_TOKEN"]
    repository = os.environ["GITHUB_REPOSITORY"]
    pr_number = int(os.environ["STY_PR_NUMBER"])
    sha = os.environ["STY_PR_HEAD_SHA"]
    timeout_seconds = int(os.environ.get("STY_GATE_TIMEOUT_SECONDS", "6300"))

    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise RuntimeError("missing validated exact 40-hex PR head SHA")
    if "/" not in repository:
        raise RuntimeError("invalid repository identifier")
    check_current_pr(api, token, repository, pr_number, sha)

    rows = read_all_pages(
        api, token, f"/repos/{repository}/pulls/{pr_number}/files", None,
    )
    paths = changed_paths(rows)
    required = required_workflows(paths)
    if not required.issubset(REQUIRED_WORKFLOW_PATHS):
        raise RuntimeError("unregistered mandatory workflow")

    summary(
        f"### STY merge gate (read-only)\n\n"
        f"PR #{pr_number}, head: {sha}  \n"
        f"Risk: **{risk_class(paths)}**  \n"
        f"Docs-only auto-merge candidate: **{docs_only(paths)}**  \n"
        f"Expected exact-head workflows: {', '.join(sorted(required))}  \n"
        f"**This check never calls merge. Branch protection is required.**"
    )
    start = time.monotonic()
    last = None
    while time.monotonic() - start < timeout_seconds:
        check_current_pr(api, token, repository, pr_number, sha)
        runs = latest_runs(api, token, repository, sha, pr_number)
        pending = pending_or_fail(required, runs, sha)
        if not pending:
            check_current_pr(api, token, repository, pr_number, sha)
            summary(
                f"\n**PASS**: all {len(required)} applicable workflow groups "
                f"completed successfully on exact SHA {sha}."
            )
            return
        snapshot = "; ".join(pending)
        if snapshot != last:
            print(f"WAIT (not a pass): {snapshot}", flush=True)
            last = snapshot
        time.sleep(30)
    raise RuntimeError(
        f"required workflow never passed within {timeout_seconds}s: {last}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        summary(f"\n**HOLD / FAIL**: {exc}")
        sys.exit(1)
