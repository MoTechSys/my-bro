# CI workflow — pending activation

`validate.yml` is a candidate, **not an active workflow in this directory**.
On activation it runs `scripts/validate/validate_all.sh`, including the bounded
local unittest suite, on Python 3.12 and 3.13. Actions are pinned to commit SHAs,
permissions are `contents: read`, checkout does not persist credentials, and
jobs have timeout/concurrency limits. None of these checks deploys the lab.

## Permission verified on 2026-09-11

GitHub Actions is enabled for the repository, but pushing the candidate to
`.github/workflows/validate.yml` was explicitly rejected:

> refusing to allow a GitHub App to create or update workflow without workflows permission

The unpublished activation commit was replaced with this pending-only candidate;
there is no hidden active workflow or successful Actions run to report. T-40 and
ISSUE-038 remain blocked. Repository write/admin access alone does not prove the
installed application's workflow permission.

## Activation by an appropriately authorized operator

Grant the GitHub integration **Workflows: write**, approve the updated installation
permissions, or use an independently authorized owner session. Never paste an API
token into a commit, issue, PR or chat. Then, from a reviewed up-to-date branch:

```bash
mkdir -p .github/workflows
git mv .github/workflows-pending/validate.yml .github/workflows/validate.yml
git add -A .github/workflows .github/workflows-pending
git commit -m "ci: activate reviewed validation matrix"
git push
```

Follow the normal PR/sync policy. Confirm successful jobs for both Python versions
on the actual PR commit before closing T-40. A local validator pass or a successful
workflow-file push is not proof that CI executed successfully. Update this README
and the taskboard after activation, retaining the dated denial as historical context.
