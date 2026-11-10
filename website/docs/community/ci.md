# CI and main-branch health

## Fast pull request checks

Pull requests run unit tests with the race detector, linting, generated-file
verification, vulnerability scanning, action-pin checks, and title validation.
The required `required` and `unit-tests` checks remain separate from end-to-end
(E2E) testing. A failed, canceled, or unexpectedly skipped prerequisite must not
produce a passing aggregate check.

The target is two to five minutes for PR checks, not a guaranteed timeout or
service level. Before this change, a recent run spent about four minutes and
46 seconds verifying generated files, four minutes and 19 seconds on unit tests,
and six minutes and 19 seconds preparing E2E images before any cluster tests
could start. Removing E2E from PRs removes the image-build and cluster-test
critical path; hosted-runner queueing, cold caches, and code generation can
still exceed five minutes. Measure elapsed time from PR update to all required
checks finishing, including queueing, rather than only timing individual steps.

## Scheduled E2E testing

The E2E pipeline checks for new `main` commits every 30 minutes. It tests
main-branch commits in first-parent order: a merge or squash commit represents
the integrated PR, rather than testing every internal commit on a PR branch.
It does not sample only the newest commit and skip intermediate integrations.
GitHub can delay scheduled workflows; the persisted backlog must survive missed
ticks, workflow cancellation, and runner outages.

Scheduling and reporting share a controller concurrency group. Before sending
a dispatch request, the controller persists a 15-minute lease so delayed run
discovery cannot immediately trigger another dispatch. Expired leases allow
recovery after an interrupted or ambiguous request. A separate trusted
registration job atomically binds the run to its claim before building images
or executing tests; a duplicate workflow cannot launch another matrix.

Each commit is tested at its immutable SHA against all five Chainsaw suites
on all four configured Kubernetes versions:

| Suite | Test directory |
| --- | --- |
| Envoy authorization server | `tests/e2e/authz-server/envoy` |
| HTTP authorization server | `tests/e2e/authz-server/http` |
| Sidecar injector | `tests/e2e/sidecar-injector` |
| Envoy validation webhook | `tests/e2e/validation-webhook/envoy` |
| HTTP validation webhook | `tests/e2e/validation-webhook/http` |

There is no E2E work when there are no untested commits. A failed attempt is
retried once. An unsuccessful retry, including an infrastructure failure, makes
main unhealthy. A failure does not discard the remaining backlog: later repair
commits must still be tested.

## Incidents and merge blocking

After a terminal failure, the pipeline creates or updates an incident issue
with the tested SHA, associated PRs, failed suite and Kubernetes version,
workflow links, reproduction instructions, and repair or revert guidance.
These details identify the integration that failed testing; they do not prove
that a product bug caused an infrastructure failure or a flaky test. The
pipeline must not invent a root cause or claim to have generated a verified fix.

The required `main-health` status is published on PR heads and refreshed for
already-open PRs after health changes. Unknown or uninitialized health must
not be treated as success. No-change scheduler runs and manually closed issues
must not turn an unhealthy main green.

Once a baseline is established, queued or running tests alone do not block PRs:
the PR gate reflects the last known main-health result until a terminal
failure. The status on main itself can remain pending until that exact commit
passes; this distinction prevents the 30-minute schedule from becoming a
mandatory wait for every healthy PR.

This is asynchronous enforcement, not a transactional branch lock: a PR with
an existing green status can merge during the short interval between detecting
a failure and updating that PR's status. Administrators are the designated
repair bypass. Ordinary contributors must not receive a bypass merely by
adding a label or editing an issue.

To repair main, an administrator reviews and merges a minimal fix or revert
using the existing review and fast-check process. Only a newer commit passing
the complete E2E matrix restores health; an older in-flight success must not
overwrite a newer failure. Do not remove the required check or manually publish
a green status as a repair procedure.

## Trust boundaries

PR-health reporting reads PR metadata only and must never execute code from a
fork or PR head with a write-capable token. E2E jobs execute the selected commit
with read-only permissions. Trusted control jobs manage durable state, issues,
and commit statuses separately from the tested code.

The registration job runs only trusted controller code with state-write
permission. It does not execute the tested commit. Checkouts in the source
build and test jobs disable credential persistence, including the neighboring
trusted-tools checkout, so tested code cannot read a saved checkout token.
Dispatch uses the default-branch workflow, while execution pins its resolved
GitHub SHA and verifies the claimed suite fingerprint before running the
matrix. A changed suite cannot silently satisfy an older claim.

Workflow logs and artifacts can contain untrusted application output. Incident
issues should link to diagnostics rather than copy arbitrary logs, credentials,
environment dumps, or attacker-controlled commands into issue bodies.

## Publication

Image, documentation, chart, and release publishing retain their existing
triggers. Scheduled E2E is a main-health and merge gate, not a publication gate:
an image can be published before its commit finishes scheduled E2E testing.

## Safe rollout

Deploy the workflows to the default branch before adding `main-health` as a
required check. Otherwise all PRs can become blocked on a check that cannot run.
Repository settings are not changed just by merging workflow files.

An administrator selects an exact, reviewed first-parent commit as the start
boundary and initializes the durable state:

```sh
gh workflow run main-e2e-scheduler.yaml --repo kyverno/kyverno-authz \
  -f mode=bootstrap -f base_sha=<reviewed-40-character-commit-sha>
```

Bootstrap creates `ci-main-e2e-state` with unknown health and a cursor at that
boundary; it does not certify the boundary as passing E2E. Select a boundary
before the first commit to test, not the newest head as a way to skip backlog.
The scheduler processes the oldest outstanding first-parent commit each tick.
If commits arrive faster than tests are processed, backlog grows rather than
being silently discarded.

After a subsequent complete E2E pass establishes a green baseline, preview the
configuration helper before applying changes. Activation must preserve the
existing `DCO`, `required`, and `unit-tests` requirements and review protections.
Both classic branch protection and the `main-status` ruleset need to agree.
The activation helper adds `main-health` to the active `main-status` ruleset;
classic protection keeps its existing required checks. GitHub enforces both,
so the additional ruleset requirement blocks ordinary merges without replacing
the classic protection configuration.

Use an explicit repository target, since a local checkout might point to a fork:

```sh
GITHUB_REPOSITORY=kyverno/kyverno-authz \
  bash .github/scripts/configure-main-health-rule.sh \
  --baseline-sha <current-main-green-40-character-commit-sha>
```

After reviewing the preview, pass `--apply` to activate. If the named-user
bypass below is still present, activation also requires the explicit
`--remove-user-bypass` option. Do not run either change until the baseline and
recovery procedure have been verified.

The existing repository has a named-user ruleset bypass in addition to the
administrator bypass. Review and explicitly remove any non-administrator bypass
when activating the administrator-only repair policy; do not silently treat
existing exceptions as compliant.

Verify enforcement with a non-administrator test PR, including a simulated
unhealthy state, failure propagation to an already-green PR, recovery after a
new full matrix pass, and inability to unlock by closing an incident issue.
Do not activate the production gate until these checks and the recovery path
are understood.

## Local controller checks

The controller's scheduling and health transitions are tested without GitHub
credentials or a Kubernetes cluster:

```sh
python3 -m unittest discover -s .github/scripts/tests -p 'test*.py'
bash -n .github/scripts/run-e2e-suite.sh .github/scripts/configure-main-health-rule.sh
actionlint .github/workflows/pr.yaml .github/workflows/code-coverage.yaml \
  .github/workflows/main-e2e-scheduler.yaml .github/workflows/main-health.yaml \
  .github/workflows/e2e.yaml .github/workflows/e2e-attempt.yaml
```

The Python and shell-syntax checks also run on PRs. These checks do not replace
an actual hosted E2E run or the non-administrator merge-enforcement exercise.
