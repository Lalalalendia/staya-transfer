# STY-CI-01 — fail-closed merge automation (review checklist)

## Why
As of 2026-10-21, GitHub reports that the public `Lalalalendia/staya-transfer` repository has `main.protected=false`, zero required CI contexts, `allow_auto_merge=false`, and `delete_branch_on_merge=false`. The connected GitHub App can edit repository files but cannot set repository/branch administration options. **No script or green GitHub Action is a substitute for enforcing protected `main` on the GitHub server.**

## Implemented in this PR
1. `STY Merge Gate` is an **always-running**, unfiltered `pull_request` workflow. `preflight` runs Python policy tests, Rustfmt for all six Rust workspaces and workflow YAML parser checks **before** costly integration code runs in this workflow. The existing Rust/Iroh/Windows/Docker workflow files are also changed to run rustfmt *first* and fail quickly instead of after expensive tests.
2. Its final `ready` job has **read-only** `contents:read`, `pull-requests:read` and `actions:read`. It reads changed PR filenames (including both sides of a rename) and waits for **only the workflows actually triggered by those paths**. It verifies the **exact source commit SHA, PR number, workflow path and terminal `success` conclusion**, rejecting missing/skipped/neutral/failing/stale checks. Unknown file families fail closed until the policy is extended. There is no direct merge, push or destructive API call.
3. `STY Safe Docs Auto-merge Enrollment` uses `pull_request_target`, **without checkout or execution of untrusted PR code**. It only considers non-draft owner-authored PRs from the same repository, containing at most 30 `README.md` or `docs/**/*.md` changes. It checks live GitHub settings: protected `main`, native auto-merge enabled, and that the **classic branch protection required check includes `STY Merge Gate / ready`**. Only then it asks GitHub to enable its **native SQUASH auto-merge**. GitHub itself enforces the required check; the script never falls back to a direct merge. Code, Cargo, QUIC, ACL, workflow and arbitrary path PRs are **never automatically enrolled**.
4. `Dependabot` is limited to two weekly **GitHub Actions** dependency update PRs. No unreviewed update of Iroh, Bao or Cargo protocol pins.

## Required owner configuration — not available through the current connector

These are explicit manual one-time GitHub UI actions. Perform **after this PR is accepted and its gate workflow appears in Checks**.

- [ ] Open [repository Settings → Branches](https://github.com/Lalalalendia/staya-transfer/settings/branches), add a **classic branch protection rule** matching exactly `main`.
- [ ] Require a pull request before merging; disallow force pushes and branch deletion, include administrators / disable bypass where GitHub offers it.
- [ ] Require passing status checks, select **`STY Merge Gate / ready`**. Do not require path-filtered workflow checks directly: they may not run for docs-only PRs and thus remain pending indefinitely. The Merge Gate dynamically insists on every path-applicable workflow.
- [ ] Enable **Require branches to be up to date before merging**. This stops merging an old green SHA after `main` advances. The gate itself also checks the PR head SHA. Require reviews for security-sensitive code if an independent reviewer is available; do not make a solo owner unable to merge their own work.
- [ ] Open [repository Settings → General](https://github.com/Lalalalendia/staya-transfer/settings), under Pull Requests enable **Allow auto-merge**, prefer **Squash merging**, and enable **Automatically delete head branches**. Also consider **Always suggest updating pull request branches**.
- [ ] Create a **docs-only test PR** and confirm it enrolls in native auto-merge, but cannot merge until Merge Gate reports success. Create a harmless Rust test PR to confirm it **does not** auto-enroll and that Iroh/Windows checks are required when applicable.
- [ ] Explicitly verify that no PR can be merged through the GitHub UI if `ready` failed or was missing; test a docs PR with a failing preflight to confirm the server rejects it.

The docs enrollment checks *classic branch protection*. If you instead use a ruleset or the current GitHub API no longer exposes `required_status_checks` in `getBranch`, enrollment remains intentionally disabled until that check is updated and security-reviewed. **Fail closed, not fallback.**

## Future improvements
- Replace polling of existing path-filtered workflows (read-only but holds an Actions runner, max 105 minutes) with an audited event-driven Check Run aggregator *only after* the baseline gate is demonstrated end to end. Do not claim free or instantaneous automation.
- Collect runner queue vs compilation time metrics and insert caches in bottlenecked workflows without weakening pinned dependency lock requirements.
- Manually enable native Auto-merge on individual code PRs after architectural/security review; the GitHub branch protection applies throughout. Keep File Gate, Device/Vault authorization, updater/security and G2 correctness changes under human review.
- Do **not** automate production GitHub releases, tag signing, File Gate or Akula vault mutation from the PR merge workflow.

## Acceptance
1. Nine merge-policy tests and six adversarial gate tests PASS; Rustfmt across six manifests and all workflow YAML parse. 
2. `STY Merge Gate / ready` successfully waits for every applicable workflow on this *exact* PR SHA. Missing / skipped / failed outcomes have tests proving they cannot be mistaken for green.
3. The owner then enforces protected `main` and enabled native auto-merge in GitHub Settings. Until (3), the automation is **prepared but not active** and no completed PR is entitled to automatic merging solely from these files.
