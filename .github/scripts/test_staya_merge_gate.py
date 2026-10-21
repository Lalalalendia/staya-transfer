"""Offline adversarial tests for exact-head read-only merge gate."""
import unittest
from unittest.mock import patch

import staya_merge_gate as gate


SHA = "a" * 40
REPO = "Lalalalendia/staya-transfer"
RUST = "Rust contracts"
IROH = "Iroh FsStore compatibility"


def run(name, sha=SHA, pr=91, status="completed", conclusion="success",
        path=None, number=999):
    return {
        "id": number,
        "name": name,
        "head_sha": sha,
        "event": "pull_request",
        "pull_requests": [{"number": pr}],
        "path": path or gate.REQUIRED_WORKFLOW_PATHS[name],
        "status": status,
        "conclusion": conclusion,
        "created_at": "2026-10-21T00:00:00Z",
        "run_attempt": 1,
        "html_url": "https://github.com/Lalalalendia/staya-transfer/actions/runs/999",
    }


class MergeGateTests(unittest.TestCase):
    def test_exact_run_from_same_pr_is_accepted(self):
        with patch.object(gate, "read_all_pages", return_value=[run(RUST), run(IROH)]):
            selected = gate.latest_runs("api", "test-token", REPO, SHA, 91)
        self.assertEqual(set(selected), {RUST, IROH})
        self.assertEqual(gate.pending_or_fail({RUST, IROH}, selected, SHA), [])

    def test_wrong_pr_sha_and_workflow_path_are_excluded(self):
        records = [
            run(RUST, sha="b" * 40, number=1),
            run(IROH, pr=9, number=2),
            run(RUST, path=".github/workflows/untrusted.yml", number=3),
        ]
        with patch.object(gate, "read_all_pages", return_value=records):
            selected = gate.latest_runs("api", "test-token", REPO, SHA, 91)
        self.assertEqual(selected, {})
        self.assertEqual(
            gate.pending_or_fail({RUST, IROH}, selected, SHA),
            [f"{IROH}: not started", f"{RUST}: not started"],
        )

    def test_any_terminal_status_except_success_is_a_hard_fail(self):
        for conclusion in (
            "failure", "cancelled", "timed_out", "skipped", "neutral",
            "startup_failure", "action_required", None,
        ):
            with self.subTest(conclusion=conclusion):
                with self.assertRaises(RuntimeError):
                    gate.pending_or_fail(
                        {RUST}, {RUST: run(RUST, conclusion=conclusion)}, SHA
                    )

    def test_queued_and_in_progress_are_not_success(self):
        for status in ("queued", "in_progress", "waiting", "requested"):
            with self.subTest(status=status):
                work = {RUST: run(RUST, status=status, conclusion=None)}
                self.assertEqual(
                    gate.pending_or_fail({RUST}, work, SHA),
                    [f"{RUST}: {status}"],
                )

    def test_run_from_stale_head_can_never_be_used(self):
        with patch.object(
            gate, "api_get",
            return_value={
                "state": "open",
                "head": {"sha": "b" * 40},
                "base": {"ref": "main"},
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "head SHA changed"):
                gate.check_current_pr("api", "token", REPO, 91, SHA)

    def test_latest_attempt_supersedes_older_success(self):
        older = run(RUST, number=1)
        latest = run(RUST, number=2, conclusion="failure")
        with patch.object(gate, "read_all_pages", return_value=[older, latest]):
            selected = gate.latest_runs("api", "token", REPO, SHA, 91)
        self.assertEqual(selected[RUST]["id"], 2)
        with self.assertRaisesRegex(RuntimeError, "concluded failure"):
            gate.pending_or_fail({RUST}, selected, SHA)


if __name__ == "__main__":
    unittest.main()
