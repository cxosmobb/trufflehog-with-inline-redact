# Original-source redaction

This fork adds `trufflehog-redact`, an offline preprocessing command that changes
the **original input source bytes**, replacing sensitive credential components
with `REDACTED`. It does not redact TruffleHog's printed findings. Public IDs,
usernames, hosts, formatting, comments, and unrelated source bytes are retained.

Build the companion command from the fork:

```sh
go build -o trufflehog-redact ./cmd/trufflehog-redact
```

To overwrite an imported source tree before running a downstream scanner:

```sh
./trufflehog-redact --in-place ./imported-source && untrusted-scanner ./imported-source
```

For one source stream, output is buffered until the scan succeeds:

```sh
./trufflehog-redact < original.go > redacted.go && untrusted-scanner redacted.go
```

Only start the downstream scanner on exit status zero. A failed scan produces
no source on stdout. Shell redirection may still create an empty output file.
Do not connect this command to a streaming consumer which treats partial or
empty input as successful; check its exit code first.

All detected candidates are replaced, including expired and unverified secrets.
Credential verification is disabled, so the command does not deliberately send
credentials to provider APIs. Pattern matches can be false positives; this mode
cannot prove that every candidate is live. Detector keyword prefilters match
TruffleHog's normal scanning semantics, while output filters, ignore comments,
entropy filters, and deduplication are bypassed. Multiple occurrences of a
sensitive value are replaced.

Additional credential components are requested through a redaction-only context;
ordinary TruffleHog findings retain their original component fields. Detector
context logs are discarded, and recovered detector/decoder panics withhold
output without printing their payloads.

## Windows release ZIPs

Download the Windows x64 ZIP and `SHA256SUMS` from this fork's
[Releases](https://github.com/cxosmobb/trufflehog-with-inline-redact/releases).
Verify the ZIP's SHA-256 digest against the manifest, then extract it. Each ZIP
contains `trufflehog-redact.exe`, the license, usage instructions, and the exact
source commit/toolchain in `BUILD.txt`. Builds are unsigned.

```powershell
Get-FileHash .\trufflehog-redact-windows-amd64-<commit>.zip -Algorithm SHA256
.\trufflehog-redact.exe --help
.\trufflehog-redact.exe --in-place C:\path\to\private-import
if ($LASTEXITCODE -ne 0) { throw 'Redaction failed; do not run the downstream scanner' }
```

Windows `--in-place` requires an already-enabled `SeSecurityPrivilege` and a
filesystem supporting the complete security descriptor. The executable never
enables privileges; it refuses replacement if the required access is absent.
Source-stream mode remains available without that privilege. Use `cmd.exe`
redirection when byte-preserving stdin/stdout is required, and check the command's
exit status before using the output. Read the in-place operating constraints below.

The release workflow runs on standard free public GitHub-hosted runners. It
publishes only the current default-branch revision after independently verifying
a successful Linux/Windows compatibility matrix and its required status. A
read-only Windows job builds with the latest Go patch in the release series
required by `go.mod`, runs the actual executable through exact source redaction,
second-pass idempotence and help checks, then creates the ZIP. An isolated
publisher validates the archive and checksum without executing repository code
or the executable. Release tags are `redact-<12-character-source-commit>`.

Hourly checks and compatibility completion events detect newly validated source.
When a token-created upstream merge has no compatibility run of its own, an
isolated job requests the first full matrix for that exact current revision.
Pending or failed runs are not retried automatically; failures withhold releases
until a maintainer fixes them and reruns compatibility validation. Successful
Windows source-stream checks do not assert that privilege-dependent in-place
tests executed.

## Byte preservation and supported encodings

The redactor uses the detector's individual credential components instead of
assuming `Raw`, `RawV2`, or the display-only `Redacted` is the source secret.
Structured adapters redact connection-string passwords, GCP JSON private keys,
Docker authentication passwords, Azure SAS signatures, and Slack/Discord webhook
tokens while retaining the remaining credential structure. Multipart detector
results that omitted a sensitive component have additive fixes in this fork.
Repeated password/signature parameters and duplicate GCP `private_key` fields
are all redacted, including values which a normal parsed map would overwrite.

Plaintext, Unicode escapes, HTML entities, percent encoding, UTF-16, and ASCII
base64 envelopes have offset-preserving views. UTF-16 uses an encoded marker.
For base64, only sensitive *decoded* bytes become `REDACTED`, then the original
envelope is reencoded; other decoded bytes are unchanged. In JSON, the quotes
and surrounding properties remain in place. The marker changes string lengths
and may make a credential unusable or violate a schema; source parsing and
application execution are not guaranteed after replacing credential values.

TruffleHog's current decoder outputs are also audited. A finding from a lossy or
new decoder which cannot be mapped precisely blocks source output. Unknown
credential component names, unmatched sensitive values, conflicting encoded
edits, detector errors, cancellation, and limits also block output. Nested
encodings have a bounded mapping depth. Archives, compressed files, and PDFs
must be extracted into source files before running this command.
Detector and upstream decoder calls use TruffleHog's 10 KiB source chunks with
a 3 KiB overlap. As with ordinary scanning, a credential requiring more context
than a chunk can escape detection. Whole-source provenance still maps every
occurrence of components found in those chunks.

## In-place batches

`--in-place` accepts files and directories. It scans every regular file without
extension-based exclusions. Git metadata directories named `.git` are excluded;
this command does not rewrite repository history. Symlinks, special files, and
unreadable files are rejected. Use an exclusively owned, private imported tree
and exclude concurrent writers until the downstream scanner has finished.

Every input is scanned and every changed file staged beside its original before
the first original is replaced. Source identity, contents, security metadata,
and staged contents are rechecked before commit and after replacement. Filesystem
operations use a pinned root. Temporary files are private before writing source
bytes; Windows staging uses a protected ACL rather than relying on mode bits.
File modes and supported security metadata are retained. A commit error attempts rollback, and the command fails if rollback
is incomplete. Individual replacement is atomic; a directory batch is **not** a
filesystem transaction, and interruption/crash during commit can leave a mixed
batch. Always gate downstream access on successful completion and keep the
import private until then. In-place replacement changes file identity and breaks
hard-link aliases to the replaced inode. Linux preserves ownership and extended
attributes; Windows requires reading and preserving the full owner/group/DACL/
SACL security descriptor, including audit rules and mandatory integrity labels.
Windows in-place mode requires an already-enabled `SeSecurityPrivilege`; the
command never enables privileges or mutates process tokens. Missing access,
unsupported filesystems and metadata-copy failures block replacement.
Other operating systems currently
support stdin mode only. Modification timestamps and all filesystem-specific
properties are not guaranteed to survive replacement.

Only file contents are scanned. Filenames, Git metadata, extended attributes,
alternate data streams, and other filesystem metadata can contain secrets and
are outside the redaction guarantee. Limit downstream access to the processed
file contents; preserving security metadata does not sanitize that metadata.

The default limits are 16 MiB per input, 256 MiB total per in-place batch,
10,000 files, 10,000 directories, a directory depth of 128, and
a five-minute time budget checked during scanning and commit. Input reads and
individual detector calls can block until they return. Use `--max-bytes`, `--max-total-bytes`, and `--timeout`
to adjust them; `--max-files` controls both the file and directory count.
Limit overruns fail rather than skipping files. Fixed library budgets additionally
cap decoded views (32 MiB each, 128 MiB total), provenance, findings, source edits,
residual-match patterns, and detector work. Increasing CLI limits does not disable
these safeguards. A deadline cannot interrupt a detector or blocking read which
ignores cancellation; use process-level resource limits for hostile imports.

## Coverage and updates

The public fork is [cxosmobb/trufflehog-with-inline-redact](https://github.com/cxosmobb/trufflehog-with-inline-redact).
The current reviewed upstream revision is `d6ea4a52e3f4705989210e60e9f0da0deafe84bf`
from upstream `main` on 2026-10-23. SonarQube and LambdaCloud raise the original
897-instance baseline to 899 registered scanner instances, using the same
source-redaction policy and mandatory coverage gates.

The full-registry directory batch contains **900 files**. The complete Linux
suite requires actual file replacement and a second unchanged pass for every
scanner and the production command. Fifteen additional fixtures specify exact
output bytes independently, including structured duplicates and supported
encodings. The engine/security/schema suite and registry-completeness audit are
also required. See the compatibility workflow for results for each commit.
Successful Windows full-descriptor replacement requires audit-security privilege;
its absence explicitly skips positive cases and exercises safe refusal instead.

The current baseline has **899/899 registered scanner instances** with a positive
offline redaction fixture, with zero detection or mapping gaps. This includes
scanner versions and feature-gated implementations, plus the upstream registry's
known Guru and Tru omissions. A registry-completeness test compares the redaction
registry with every active and feature-gated upstream registration.

The scope is the command's registered scanners. Upstream also retains 26
implemented, nondeprecated types which it intentionally disables. This command
does not activate them: `Abstract`, `AdobeIO`, `Alconost`, `Apollo`,
`AzureFunctionKey`, `Besnappy`, `BlockNative`, `DailyCO`, `Debounce`, `Generic`,
`GetEmail`, `GetEmails`, `Hive`, `IbmCloudUserKey`, `LineMessaging`, `M3o`,
`Magnetic`, `Manifest`, `Mixpanel`, `NasdaqDataLink`, `Raven`, `Sparkpost`,
`SpotifyKey`, `TogglTrack`, `WePay`, and `ZapierWebhook`. Upstream explicitly cites
false positives for AzureFunctionKey and an API issue for BlockNative; it gives
no individual reason for the remaining entries beyond its disabled-detector
classification. Old commented Restpack and Rockset registrations have no
corresponding implementation; Rockset's enum is deprecated. Configuration-defined
`CustomRegex`, test-only types, and enum entries without an implementation are
also outside the companion command's registry.

Positive corpus coverage establishes one fixture per registered scanner; it is
not exhaustive proof for every possible
input, encoding composition, or upstream false positive. Separate regression
tests cover exact source preservation, structured credentials, repeated values,
encoding mappings, residual components, and file-batch failure behavior.
Security regressions cover duplicate structured secrets, private staging,
tampering and path substitution, diagnostic confidentiality, bounded input work,
and preservation of ordinary scanner component fields.

Every exact copy of a known sensitive value is treated as sensitive, including
copies in comments. If a retained substring or an encoded copy makes it
impossible to prove the component is gone without altering unrelated source,
the command withholds output. Ambiguous upstream multipart roles can also
produce false positives; offline scanning cannot establish provider validity.

Run the exact scanner corpus and source-edit regression suite:

```sh
go test -p 2 -count=1 ./pkg/redaction/... ./cmd/trufflehog-redact/...
```

The corpus tests invoke actual compiled detector instances with verification
disabled. Positive fixtures are synthesized from detector patterns and upstream
test literals; missing detection or source-mapping coverage fails the test.
In-place tests write fixtures into a nested multi-file tree, exercise staging and
replacement, check the resulting bytes and a second unchanged pass, and check
that no staging files remain. Corpus file bytes are compared with the validated engine output; separate command fixtures independently specify exact expected
output for plaintext, repeated and structured values, escaped and encoded
credentials, CRLF, UTF-16, empty files, and benign source.

Shortening a secret can change another detector's keyword context. A synthetic
Box OAuth example exposed a public client ID becoming a new Box-token candidate
after replacement. The corpus uses an unambiguous positive example, and a
separate regression requires that ambiguous example to fail with both original
files untouched and no staging residue. The residual audit is retained; the
redactor does not erase the public ID to force the batch to succeed.

Require actual in-place execution on a supported filesystem:

```sh
REDACTION_REQUIRE_IN_PLACE=1 go test -p 2 -count=1 -timeout=15m ./cmd/trufflehog-redact/... -run 'TestEveryDetectorRedactsInPlace|TestCommandRedactsDetectorCorpusInPlace|TestCommandInPlaceExactMultiFileFixtures'
```

Set `REDACTION_TEST_BINARY` to the absolute path of a built production command to
run command fixtures against that binary. Otherwise they exercise `main` in a
test subprocess. Linux CI requires successful disk replacement; Windows hosts
without the complete audit-security access can skip positive in-place tests
unless `REDACTION_REQUIRE_IN_PLACE=1` is set. Required coverage also rejects short mode and a nonempty `REDACTION_TEST_DETECTORS` filter. Such a skip is not a successful
in-place test.

The reviewed detector schema snapshot also fails when detector files or
component names change, and covers decoder and registry production files.
This makes new upstream detectors and result changes
visible for review instead of silently declaring them covered.

See [fork maintenance](redaction-maintenance.md) for the reviewed update workflow.
See [security review](redaction-security-review.md) for the findings and remaining
operating constraints.
Secret scanning remains detection-based: credentials which TruffleHog does not
detect cannot be redacted by this feature. Treat this as a preprocessing layer,
not a guarantee that arbitrary input is free of every possible secret.
