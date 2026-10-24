# Maintaining the redaction fork

Keep the fork's default branch as an upstream-compatible TruffleHog tree with a small, separately reviewed redaction layer. Preserve the upstream module path and detector registry. This lets the redactor use the current upstream detector implementations while keeping source-editing policy in `pkg/redaction`, shared filesystem transactions in `internal/sourceredact`, and a small opt-in `--in-place` route in the existing TruffleHog CLI. `cmd/trufflehog-redact` remains a compatibility wrapper. Retain all upstream CLI declarations and ordinary scanning behavior; new redaction must not replace the normal command.

The initial upstream baseline is commit `0e427395344c7039c0b15a1147f5782805685b3e` (2026-10-08). Record the tested upstream commit when publishing each redaction build. Pin the binary version used by the importing pipeline so an upstream update becomes a reviewed release rather than an unannounced production change.

The published fork is [cxosmobb/trufflehog-with-inline-redact](https://github.com/cxosmobb/trufflehog-with-inline-redact).
The 2026-10-23 update incorporates upstream `main` at
`d6ea4a52e3f4705989210e60e9f0da0deafe84bf`. SonarQube and LambdaCloud raise the
reviewed registry from the original 897 to 899 instances; the exact command corpus
contains 900 files. The workflows select the latest Go patch in the release series
required by upstream's current `go.mod`.

## Compatibility checks

Run from the repository root:

```sh
CGO_ENABLED=0 go build -p 2 -o /tmp/trufflehog .
CGO_ENABLED=0 go build -p 2 -o /tmp/trufflehog-redact ./cmd/trufflehog-redact
REDACTION_TEST_MAIN_BINARY=/tmp/trufflehog REDACTION_TEST_BINARY=/tmp/trufflehog-redact CGO_ENABLED=0 go test -p 2 -count=1 -timeout=30m ./pkg/redaction/... ./internal/sourceredact/... ./cmd/trufflehog-redact/...
REDACTION_TEST_MAIN_BINARY=/tmp/trufflehog REDACTION_TEST_BINARY=/tmp/trufflehog-redact REDACTION_REQUIRE_IN_PLACE=1 CGO_ENABLED=0 go test -p 2 -count=1 -timeout=30m ./internal/sourceredact/... -run 'TestEveryDetectorRedactsInPlace|TestCommandRedactsDetectorCorpusInPlace|TestCommandInPlaceExactMultiFileFixtures'
go test -p 2 -count=1 ./pkg/detectors/redaction_context.go ./pkg/detectors/redaction_context_test.go
go test -p 2 -count=1 ./pkg/engine -run '^TestSelectDetectors'
go test -p 2 -count=1 ./scripts/redaction-audit.go ./scripts/redaction-audit_test.go
go run ./scripts/redaction-audit.go > /tmp/redaction-detector-schema.json
cmp pkg/redaction/detector-schema.json /tmp/redaction-detector-schema.json
```

The explicit `REDACTION_REQUIRE_IN_PLACE=1` command requires supported Linux storage or a private Windows NTFS tree with ordinary read/write access. Windows must pass without enabling `SeSecurityPrivilege` or running as Administrator. It fails when successful in-place edits cannot be exercised; a skipped platform test is not evidence that in-place redaction works.

The detector inventory and behavioral tests serve different purposes. Tests in `pkg/redaction` compare the reviewed inventory with current production detector code and require policies for known secret-component keys. `scripts/redaction-audit.go` prints the current inventory for review; it does not approve or update the policy. Behavioral tests check that secret components become `REDACTED` and that unrelated identifiers, punctuation, whitespace, and surrounding source remain intact. The separate in-place corpus exercises real detector fixtures through source-file staging and replacement, and command fixtures run the executable against nested multi-file trees. An inventory count, a populated `SecretParts` map, or a passing source-stream test alone does not prove correct in-place redaction.

`.github/workflows/redaction-test.yml` builds full TruffleHog and the compatibility wrapper first. It supplies `REDACTION_TEST_MAIN_BINARY` for native CLI and in-place corpus tests and `REDACTION_TEST_BINARY` for compatibility stream checks, then runs the complete redaction suite on standard public Linux and Windows hosted runners. It clears the local detector filter and requires actual successful in-place edits on Linux and Windows. Windows must exercise the complete corpus with ordinary file permissions; its locked same-file writes retain original identity and security metadata without privileged descriptor copying. Both platforms test the inventory generator and compare its result with the reviewed snapshot. No detector policy or inventory is automatically accepted. Native CLI regressions also require original source commands and flags in help, ordinary offline JSON findings without file changes, original-secret findings plus local filesystem redaction, no second-pass findings, reporting filters which do not suppress editing, and rejection of unsupported write targets. Test newly added upstream flags with redaction when they can affect scope or security.

Every job that executes proposed source has read-only repository permissions, no persistent checkout credentials, no caches, and no provider secrets. Ordinary pull-request runs explicitly test the proposed head SHA; strict branch protection requires it to contain the current base. A separate default-branch workflow, `.github/workflows/redaction-status.yml`, handles `workflow_run` completion without checking out source or downloading artifacts. It verifies the originating workflow ID, file path, repository, event, exact head SHA, run attempt, and both matrix jobs before publishing `redaction-compatibility`. If either platform fails, times out, or is cancelled, the aggregate status cannot report success. Pull-request statuses apply only while an open pull request retains the tested head and that head contains its current base. When GitHub evaluates checks on a synthetic merge, the publisher also reports there after verifying that it is current and has exactly the tested head's tree. This publisher supports external-fork pull requests without granting write access to their source execution.

Require the **`redaction-compatibility` commit status** from the GitHub Actions app on the fork's default branch, with branches required to be up to date. The matrix job checks remain useful diagnostics but are not the protection context: scheduled reusable validation does not have a pull-request event. Keep auto-merge enabled for validated upstream proposals. Retain manual review for changes you or contributors make to policies, fixtures, audits and workflows.

Upstream's existing detector and source integration workflows often depend on Truffle Security's infrastructure or explicitly exclude forks. Keep the redaction compatibility check independent of those jobs. Run any applicable upstream community tests as an additional check when detector APIs or shared dependencies change; passing provider verification tests does not replace source-editing tests.

## Reviewing detector changes

For every new or changed detector, review the actual `FromData` results and component construction before updating the accepted inventory. Determine which values are sensitive and which values identify accounts, users, endpoints, or providers. `Raw`, `RawV2`, and display-oriented `Redacted` values are not a safe substitute for this review: they can contain identifiers, reconstructed combinations, or surrounding context.

Use this review sequence:

1. Review the changed detector and any helper or decoder it uses. Confirm that every returned credential representation has an explicit redaction policy.
2. Add synthetic positive fixtures for each secret variant. A multipart credential needs coverage for its secret components while preserving public identifiers and separators.
3. Assert the complete expected output, including surrounding source. Include repeated occurrences, adjacent matches, already-redacted input, and a benign value that resembles the detector's identifiers. Exercise the original file through `--in-place` as well as the library; compare every resulting file byte, check a second run is unchanged, and verify no staging files remain.
4. Add fixtures for structured or encoded representations when the detector supports them. Check that edits map back to the original bytes without removing encoded context. Exercise parser fallbacks together with directly matched values, such as a JDBC DSN with both userinfo and query passwords. A credential parsing failure must withhold the complete source batch.
5. Update the reviewed inventory or policy only after these fixtures pass. Run the full suite, not only tests for the changed detector.

Additional secret components are exposed only when the caller explicitly uses
`detectors.WithSourceRedaction(ctx)`. Keep that opt-in limited to source editing;
ordinary TruffleHog scan results and their JSON output must retain the upstream
component set. This prevents a redaction change from adding confidential values
to normal scanner output. Test both contexts when changing an adapter.

Reject an update when a detection cannot be mapped precisely, when a component's sensitivity is ambiguous, or when a newly enabled detector lacks a redaction policy. Keep the importing pipeline gated on the redactor's successful exit. An audit failure or redaction error must prevent the original input from reaching the downstream scanner.

The offline suite does not verify whether synthetic credentials authenticate to provider services, and it cannot promise detection of secrets that TruffleHog itself misses. Maintain detection quality with upstream detector tests and review upstream additions; maintain source-editing correctness with this fork's exact-output fixtures.

## Automatic upstream synchronization

`.github/workflows/redaction-upstream-sync.yml` checks upstream daily at 06:23 UTC and can be dispatched manually from the fork's default branch. It discovers the current default branch of `trufflesecurity/trufflehog` from Git's symbolic HEAD; it does not assume `master` or `main`. Standard GitHub-hosted Linux and Windows runners are free for this public repository. No paid runner, personal access token, provider credentials, or external service is required. See [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

Configure the fork as follows:

1. Enable Actions and allow Actions to create pull requests.
2. Enable repository auto-merge and preserve merge commits, so upstream ancestry remains intact.
3. Protect the default branch with strict up-to-date checks and require `redaction-compatibility` from the GitHub Actions app. Configure the requirement after the first successful compatibility run makes the status available. Prevent force pushes and branch deletion. Requiring human approval on every sync PR will deliberately make upstream integration require that approval.
4. Set the Actions repository variable `REDACTION_UPSTREAM_SYNC` to `true` after protection is in place.
5. Dispatch synchronization once and check its validation, proposal and merge behavior before relying on the schedule.

A preparation job with read-only repository permissions merges upstream into the current fork base and saves an incremental Git bundle. It executes no repository code. Separate Linux and Windows workers restore that exact commit and run the production-binary, complete detector, in-place, exact-output, security and inventory checks with read-only permissions.

Only after validation finishes does a fresh proposal job receive contents, pull-request and status write permissions. It verifies the bundle's exact commit and both parents, checks that the fork base has not changed, and pushes the tested commit. It never checks out or executes the merged source. The job checks the pull request's head and base again before publishing `redaction-compatibility` on that exact head SHA. A successful Linux **and** Windows result opens a ready pull request and requests protected auto-merge with a matching-head guard. A failed validation opens a draft with a failing required status and leaves the workflow failed. Conflicts stop preparation before a branch is pushed. Failures need reviewed fixes; the automation never changes a policy or weakens a gate to obtain a pass.

GitHub-token-created pull requests can queue approval-required workflows. Also, job checks from `workflow_dispatch` do not satisfy pull-request required checks. Synchronization therefore publishes a commit status for the already completed isolated validation; it does not depend on recursive workflow events, approval bypasses, or dispatch checks to make a merge possible. Branch protection requires that exact status from the expected GitHub Actions app, and strict protection blocks a stale base. See [workflow triggering](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow) and [required-check behavior](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

Proposal names contain both upstream and fork base commit identifiers. Existing branches are left for review rather than force-pushed. If the fork advances during validation, the run fails and the next run prepares a fresh candidate. If a push succeeds but pull-request creation or auto-merge setup fails, repair the visible run or open the saved branch's pull request manually. Rejected or superseded proposals should be closed and their branches removed after review. Set `REDACTION_UPSTREAM_SYNC` to `false` to stop scheduled integration; compatibility checks stay enabled.

The schedule keeps compatible upstream changes integrated. It cannot guarantee that an arbitrary future upstream change will remain compatible; changed detector contracts, unmappable secrets and conflicts intentionally stop integration and require maintenance. Keep the importing pipeline on a tested, pinned binary release until the new revision has been accepted.

These workflows target GitHub.com and pin official Actions. Review and refresh those pins with dependency updates. GitHub Enterprise Server needs compatible artifact actions and a separate deployment review.

## Manual upstream updates

Work from a clean checkout of the fork and use a review branch:

```sh
git remote add upstream https://github.com/trufflesecurity/trufflehog.git
git fetch upstream
git remote set-head upstream -a
git switch -c review/upstream-redaction-update
git merge --no-ff upstream/HEAD
```

If `upstream` already exists, use that remote rather than adding it again. Resolve conflicts, complete the detector review above, and run the compatibility checks. Open a pull request into the fork and publish a new pinned redaction build only after review and successful checks. Retain the upstream merge commit so later merges share their history; routinely rebasing the production fork makes both maintenance and audit history harder to follow.

The scheduled workflow takes action only when its repository variable is enabled. Repository setup, branch protection and the first cloud run must be verified when publishing this fork.

Windows ZIPs contain the full `trufflehog.exe` and compatibility wrapper. Release
smoke checks must prove upstream command help and ordinary offline JSON scanning
still work without changing source, then run `trufflehog filesystem --in-place`
against a nested
two-file NTFS directory, compare exact bytes, verify unchanged file identities
and repeat the operation unchanged. They must never enable privileges to obtain
a pass. Keep tests for hard-link, read-only, lock and partial-write rollback
failures when changing Windows file commits; same-file writes remain vulnerable
to abrupt termination, so do not describe them as crash-atomic.
