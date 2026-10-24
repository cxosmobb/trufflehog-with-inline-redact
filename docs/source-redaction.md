# Original-source redaction

This fork keeps the complete `trufflehog` command and adds `--in-place` for local
filesystem scans. Existing commands, flags, output formats and normal scanning
behavior remain available. With `--in-place`, TruffleHog scans the originals and
prints its normal findings, then changes the **original input source bytes**,
replacing sensitive credential components with
`REDACTED`. It does not redact TruffleHog's printed findings. Public IDs,
usernames, hosts, formatting, comments, and unrelated source bytes are retained.

Build full TruffleHog from the fork:

```sh
go build -o trufflehog .
```

To overwrite an imported source tree before running a downstream scanner:

```sh
./trufflehog --no-update --no-verification filesystem --in-place ./imported-source && untrusted-scanner ./imported-source
```

For a repository, pass the checked-out working-tree folder to `filesystem`.
`--in-place` does not rewrite remote sources, Git history, or historical scan
results. Other source commands continue to scan normally without this flag.
An ordinary scan retains upstream findings and leaves source unchanged:

```sh
./trufflehog --no-update --no-verification --json filesystem ./source
```

The `trufflehog-redact` companion remains as a compatibility wrapper around the
same source-redaction implementation. Build it for buffered stream redaction:

```sh
go build -o trufflehog-redact ./cmd/trufflehog-redact
./trufflehog-redact < original.go > redacted.go && untrusted-scanner redacted.go
```

Only start the downstream scanner on exit status zero. Native `--in-place`
prints findings about the original source using normal output flags, including
raw credentials where the selected format ordinarily includes them. Protect
that output and require a successful exit even if findings were already printed.
For the compatibility stream wrapper, failures produce no source on stdout;
shell redirection can still create an empty output file. Buffer the complete
result and check success before giving it to a downstream consumer.

All detected candidates in the selected scope are redacted, including expired
and unverified secrets. The source-editing pass always disables credential
verification. Native TruffleHog's preceding ordinary scan retains its normal
verification behavior: use `--no-verification` to prevent provider API checks.
Pattern matches can be false positives; offline detection cannot prove whether
a candidate is live. Multiple occurrences of a sensitive value are replaced.

Normal output-format flags, `--results`, entropy filters, ignore comments and
deduplication still govern printed findings. They do not suppress edits in the
separate source-redaction pass. Detector keyword prefilters retain upstream
semantics. A successful command with `--fail` can return the upstream findings
status 183; omit it when the importing pipeline requires exit status zero.
Requested profiling and detection-strategy comparison retain ordinary behavior.
Self-update checks are skipped during in-place editing so the running fork
cannot replace itself with an upstream binary lacking the redaction feature.

Native detector include/exclude flags and custom configured detectors define
which credential types are scanned. Configured detectors must produce auditable
sensitive components; an unmappable match refuses the entire batch. Configured
sources are rejected because in-place targets must be explicit local paths.
Configuration and path-filter files are limited to 1 MiB each; each include or
exclude file can contain at most 1,024 regular expressions. Nonzero symlink
following is unavailable in in-place mode; symbolic edit targets are rejected.
Combining `--output-report` with `--in-place` is rejected without opening or
truncating its destination. These restrictions affect the new editing
mode; ordinary upstream scans retain those features.

`--in-place=false` and `--no-in-place` disable editing and select ordinary scan
behavior. The new boolean's explicit assignment syntax also works in `@file`
argument files. Argument-file expansion is bounded to eight nesting levels,
1 MiB total data, 10,000 expanded arguments and 64 KiB per line; exceeding these
limits fails before source edits.

Additional credential components are requested through a redaction-only context;
ordinary TruffleHog findings retain their original component fields. Detector
context logs are discarded in the editing pass, and recovered detector/decoder
panics block source edits without printing their payloads. Ordinary findings
may already have been printed before a redaction failure.

## Windows release ZIPs

Download the Windows x64 ZIP and `SHA256SUMS` from this fork's
[Releases](https://github.com/cxosmobb/trufflehog-with-inline-redact/releases).
Verify the ZIP's SHA-256 digest against the manifest, then extract it. Each ZIP
contains full `trufflehog.exe`, the `trufflehog-redact.exe` compatibility wrapper,
the license, usage instructions, and exact source commit/toolchain in
`BUILD.txt`. Builds are unsigned.

```powershell
Get-FileHash .\trufflehog-redact-windows-amd64-<commit>.zip -Algorithm SHA256
.\trufflehog.exe --help
.\trufflehog.exe --no-update --no-verification filesystem --in-place C:\path\to\private-import
if ($LASTEXITCODE -ne 0) { throw 'Redaction failed; do not run the downstream scanner' }
```

Run Windows `--in-place` from an ordinary PowerShell session on a private NTFS
import that your account can read and write. Administrator access and
`SeSecurityPrivilege` are not required. The command rewrites the existing file
object, preserving its ownership and security descriptor without reading audit
rules or changing privileges. Read-only, hard-linked or locked changed files
block the batch before writes begin. Use `cmd.exe` redirection when
byte-preserving stdin/stdout is required, and check the command's exit status
before using the output. Read the in-place operating constraints below.

The release workflow runs on standard free public GitHub-hosted runners. It
publishes only the current default-branch revision after independently verifying
a successful Linux/Windows compatibility matrix and its required status. A
read-only Windows job builds with the latest Go patch in the release series
required by `go.mod`, builds both executables and checks original command help,
ordinary offline JSON findings without source changes, exact compatibility
stream redaction and native two-file directory in-place edits. Native JSON
findings must describe the original secret on the first pass and contain no
findings on the second. The directory checks also require exact edited bytes,
second-pass idempotence and unchanged original file identities.
An isolated publisher validates the archive and checksum without executing repository code
or the executable. Release tags are `redact-<12-character-source-commit>`.

Hourly checks and compatibility completion events detect newly validated source.
When a token-created upstream merge has no compatibility run of its own, an
isolated job requests the first full matrix for that exact current revision.
Pending or failed runs are not retried automatically; failures withhold releases
until a maintainer fixes them and reruns compatibility validation. Successful
Windows releases require successful in-place execution by the packaged executable; a skipped in-place test cannot satisfy that smoke check.

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
new decoder which cannot be mapped precisely blocks edited-source output or
in-place commit. Unknown credential component names, unmatched sensitive values,
conflicting encoded edits, detector errors, cancellation, and limits do likewise. Nested
encodings have a bounded mapping depth. Archives, compressed files, and PDFs
must be extracted into source files before running this command.
Detector and upstream decoder calls use TruffleHog's 10 KiB source chunks with
a 3 KiB overlap. As with ordinary scanning, a credential requiring more context
than a chunk can escape detection. Whole-source provenance still maps every
occurrence of components found in those chunks.

## In-place batches

`trufflehog filesystem --in-place` accepts files and directories, including
the existing `--directory` spelling. It honors detector selection, configuration
and filesystem include/exclude path filters; excluded files or detector types
remain outside the redaction scope. Without path filters, it scans every regular
file without extension-based exclusions. The compatibility wrapper retains its
`trufflehog-redact --in-place PATH` syntax. Git metadata directories named `.git` are excluded;
this command does not rewrite repository history. Symlinks, special files, and
unreadable files are rejected. Use an exclusively owned, private imported tree
and exclude concurrent writers until the downstream scanner has finished.

Every input is scanned and every changed file staged beside its original before
the first original is edited. Source identity, contents, security metadata,
and staged contents are rechecked before commit and after writing. Filesystem
operations use a pinned root. Temporary files are private before writing source
bytes; Windows staging uses a protected ACL rather than relying on mode bits.
A commit error attempts rollback, including the currently written file; the
command fails if rollback is incomplete.

On Linux, each replacement is an atomic rename. This changes file identity and
breaks hard-link aliases to the replaced inode; ownership and supported extended
attributes are copied onto the replacement. On Windows, all changed originals
are opened for writing with concurrent write/delete sharing denied before the
first edit. Hard-linked, read-only, substituted and unavailable files are
rejected. The command writes and truncates each original through its retained
handle, flushes it and verifies the exact contents. File identity and the
original owner/group/DACL/SACL remain intact because the original object and
its security descriptor are never replaced. Ordinary read/write permissions
are sufficient; no elevated privilege or token change is used.

A directory batch is **not** a filesystem transaction. Windows same-file writes
are also **not** individually crash-atomic: abrupt termination or power loss can
leave a partially written file. Controlled errors attempt to restore the original
bytes through the retained handles. Keep the import private, keep a separate
original copy if recovery is required, and start the downstream scanner only
after successful completion. Other operating systems currently support stdin
mode only. Modification timestamps and all filesystem-specific properties are
not guaranteed to survive editing.

Only file contents are scanned. Filenames, Git metadata, extended attributes,
alternate data streams, and other filesystem metadata can contain secrets and
are outside the redaction guarantee. Limit downstream access to the processed
file contents; preserving security metadata does not sanitize that metadata.

The default limits are 16 MiB per input, 256 MiB total per in-place batch,
10,000 files, 10,000 directories, a directory depth of 128, and
a five-minute time budget checked during scanning and commit. Input reads and
individual detector calls can block until they return. Full TruffleHog exposes
`--redaction-max-bytes`, `--redaction-max-total-bytes`, `--redaction-max-files`
and `--redaction-timeout`; the file limit also controls directory count.
The compatibility wrapper retains `--max-bytes`, `--max-total-bytes`,
`--max-files` and `--timeout`.
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
Windows CI also requires actual unprivileged in-place edits for the complete corpus. Security tests cover unchanged file identity, ACLs and refusal of unsafe file aliases.

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
the command refuses edited-source output or in-place commit. Ambiguous
upstream multipart roles can also
produce false positives; offline scanning cannot establish provider validity.

Run the exact scanner corpus and source-edit regression suite:

```sh
go test -p 2 -count=1 ./pkg/redaction/... ./internal/sourceredact/... ./cmd/trufflehog-redact/...
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
REDACTION_REQUIRE_IN_PLACE=1 go test -p 2 -count=1 -timeout=30m ./internal/sourceredact/... -run 'TestEveryDetectorRedactsInPlace|TestCommandRedactsDetectorCorpusInPlace|TestCommandInPlaceExactMultiFileFixtures'
```

Set `REDACTION_TEST_MAIN_BINARY` to the absolute path of full TruffleHog to run
the production in-place command corpus through `filesystem --in-place`.
Set `REDACTION_TEST_BINARY` to the compatibility wrapper for stream checks.
Linux and Windows CI build both, require ordinary scanning regressions and
successful native in-place edits on supported storage.
Required coverage also rejects short mode and a nonempty
`REDACTION_TEST_DETECTORS` filter. A skipped platform test is not a successful
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
