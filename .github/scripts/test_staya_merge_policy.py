"""Offline tests: keep these rules in sync with GitHub workflow path filters."""
import unittest

from staya_merge_policy import (
    ALWAYS_REQUIRED, UnsafePathError, changed_paths, docs_only,
    required_workflows, risk_class,
)

IROH = "Iroh FsStore compatibility"
DOCKER = "STY-G1g distinct Docker network direct QUIC preview"
WINDOWS = "STY-G2 real Windows FsStore crash recovery"
CUSTODY = "STY-G2 cooperative writer custody"
LINUX_PARENT = "STY-G2-05h3e Linux native parent-death laboratory"
WINDOWS_JOB = "STY-G2-05h3f Windows suspended JobObject laboratory"


class MergePolicyTests(unittest.TestCase):
    def test_docs_only_is_eligible_but_still_runs_rust(self):
        paths = {"docs/ADR-0041-automation.md", "README.md"}
        self.assertTrue(docs_only(paths))
        self.assertEqual(required_workflows(paths), {ALWAYS_REQUIRED})
        self.assertEqual(risk_class(paths), "docs-only")

    def test_src_core_needs_real_windows_and_iroh(self):
        paths = {"src/queue.rs"}
        self.assertEqual(
            required_workflows(paths), {ALWAYS_REQUIRED, IROH, WINDOWS}
        )
        self.assertFalse(docs_only(paths))

    def test_interop_triggers_direct_network_and_windows(self):
        self.assertEqual(
            required_workflows({"interop/staya_direct_preview.rs"}),
            {ALWAYS_REQUIRED, IROH, DOCKER, WINDOWS},
        )
        self.assertEqual(
            required_workflows({"interop/fsstore_partial_adapter.rs"}),
            {ALWAYS_REQUIRED, IROH, DOCKER, WINDOWS, CUSTODY},
        )
        self.assertEqual(
            risk_class({"interop/staya_direct_preview.rs"}), "sensitive-manual"
        )

    def test_custody_native_linux_and_windows(self):
        self.assertEqual(
            required_workflows({"custody/src/checkpoint.rs"}),
            {ALWAYS_REQUIRED, CUSTODY, WINDOWS},
        )
        self.assertEqual(
            required_workflows({"native-host/src/ipc.rs"}),
            {ALWAYS_REQUIRED, LINUX_PARENT},
        )
        self.assertEqual(
            required_workflows({"native-windows-host/src/windows.rs"}),
            {ALWAYS_REQUIRED, WINDOWS, WINDOWS_JOB},
        )

    def test_each_sensitive_workflow_has_a_corresponding_ci(self):
        cases = {
            ".github/workflows/ci.yml": {ALWAYS_REQUIRED},
            ".github/workflows/iroh-compat.yml": {ALWAYS_REQUIRED, IROH},
            ".github/workflows/g1g-isolated-network-preview.yml": {
                ALWAYS_REQUIRED, DOCKER,
            },
            ".github/workflows/g2-windows-fsstore-kill.yml": {
                ALWAYS_REQUIRED, WINDOWS,
            },
            ".github/workflows/g2-custody.yml": {ALWAYS_REQUIRED, CUSTODY},
            ".github/workflows/g2-native-linux-parent.yml": {
                ALWAYS_REQUIRED, LINUX_PARENT,
            },
            ".github/workflows/g2-native-windows-job.yml": {
                ALWAYS_REQUIRED, WINDOWS_JOB,
            },
            ".github/workflows/sty-merge-gate.yml": {ALWAYS_REQUIRED},
            ".github/workflows/sty-docs-auto-merge.yml": {ALWAYS_REQUIRED},
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(required_workflows({path}), expected)
                self.assertEqual(risk_class({path}), "sensitive-manual")

    def test_root_manifest_needs_iroh_and_windows(self):
        for name in ("Cargo.toml", "Cargo.lock"):
            self.assertEqual(
                required_workflows({name}), {ALWAYS_REQUIRED, IROH, WINDOWS}
            )
            self.assertFalse(docs_only({name}))

    def test_rename_checks_both_old_and_new_locations(self):
        files = [{
            "filename": "docs/new.md",
            "previous_filename": "interop/staya_store_worker.rs",
            "status": "renamed",
        }]
        paths = changed_paths(files)
        self.assertFalse(docs_only(paths))
        self.assertEqual(
            required_workflows(paths), {ALWAYS_REQUIRED, IROH, WINDOWS, DOCKER}
        )

    def test_unknown_paths_fail_closed(self):
        for path in ("server/start.py", ".github/super-admin.sh", "new-crate/Cargo.toml"):
            with self.subTest(path=path):
                with self.assertRaises(UnsafePathError):
                    required_workflows({path})
        with self.assertRaises(UnsafePathError):
            required_workflows(set())
        with self.assertRaises(UnsafePathError):
            changed_paths([{"filename": "docs/new.md", "status": "renamed"}])
        with self.assertRaises(UnsafePathError):
            changed_paths([])

    def test_no_auto_merge_from_code_or_workflow_edits(self):
        for path in (
            ".github/scripts/staya_merge_policy.py", "src/source_stream.rs",
            "interop/staya_direct_preview.rs", ".github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                self.assertFalse(docs_only({path}))


if __name__ == "__main__":
    unittest.main()
