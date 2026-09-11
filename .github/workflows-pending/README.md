# CI activation history and verification

The reviewed workflow now lives at [`../workflows/validate.yml`](../workflows/validate.yml),
not in this historical pending directory. It runs the repository validator and its
bounded unittest suite on Python 3.12 and 3.13. It does not deploy the cloud lab.

## Verified authorization — 2026-09-11

The owner explicitly authorized temporary token use. GitHub `/user` verified
`MoTechSys`; repository push permission and the `workflow` scope were present.
Repository Actions policy was enabled, and both action commit pins were resolved
against their upstream repositories before moving the candidate.

Credentials are not part of this workflow or repository. `contents: read`, pinned
actions, `persist-credentials: false`, eight-minute job timeouts, and concurrency
limits remain unchanged. No extra deployment permission is requested.

## Verified first activation — 2026-09-11

Commit `095cd869f08a23d88f7ed3d9d434db816c04fb37` was pushed and verified as PR #28's head.
Both the [PR run](https://github.com/MoTechSys/my-bro/actions/runs/34598831817) and [push run](https://github.com/MoTechSys/my-bro/actions/runs/34598830852) completed successfully.
The PR job logs were read directly and each contains `Ran 212 tests` and
`ALL CHECKS PASSED`:

| Job | Result | Test count | Suite runtime (not job or SOC latency) |
|---|---|---|---|
| [Python 3.12](https://github.com/MoTechSys/my-bro/actions/runs/34598831817/job/103260895963) | success | 212 | 2.390s |
| [Python 3.13](https://github.com/MoTechSys/my-bro/actions/runs/34598831817/job/103260896103) | success | 212 | 1.912s |

T-40/ISSUE-038 are verified for this revision. Subsequent commits must pass their
own runs; this historical success is not proof of future checks or cloud recovery.

## Continuing acceptance gate

Activation was published through PR #28; the PR remains open for review. Inspect the actual run and head SHA at:
https://github.com/MoTechSys/my-bro/actions/workflows/validate.yml

Both `validate (3.12)` and `validate (3.13)` must finish successfully on the current
PR revision before T-40 is considered verified. Pushing a workflow or passing
212 tests locally is not evidence that GitHub executed it. Current observations
are recorded in `docs/SESSIONS_LOG.md` and the PR; native SOC acceptance stays open.

## Historical rejection

Earlier on 2026-09-11 the configured GitHub App rejected activation with:

> refusing to allow a GitHub App to create or update workflow without workflows permission

That attempt was safely restored to pending-only. Owner-token authorization is a
separate, verified session; it does not retroactively grant the App permission or
make earlier CI claims valid. The old candidate remains recoverable in Git history.
