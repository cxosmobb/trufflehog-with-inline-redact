# Source-redaction security review

Reviewed on 2026-10-08, 2026-10-19, and 2026-10-23. The review covers the fork additions and their interaction
with the original detector results, decoders, filesystem command, and update CI.
Reproductions use synthetic local credentials; verification remains disabled.

## Findings and repairs

| Risk | Confirmed behavior | Repair and regression coverage |
| --- | --- | --- |
| Confidentiality: residual structured secrets | Returning the first URI password/SAS signature or the last JSON private key left other values in the source while the audit passed. GCP also normalized away duplicate fields before redaction. | Collect all password/signature/private-key values; request original GCP JSON only in source mode. Tests invoke real JDBC, Azure SAS and GCP detectors and compare exact edited source. |
| Confidentiality: expanded scanner output | Additive `SecretParts` entries were also serialized by the ordinary TruffleHog JSON printer. | Request extra components only with a source-redaction context. The full scanner corpus checks ordinary results omit each added field and source results contain it. |
| Confidentiality: diagnostics and temporary files | Detector panic payloads, context logs, invalid flag values, writer errors, and insufficient staging permissions could expose source information. Windows mode `0600` did not restrict ACLs. | Recover panics without payloads, discard detector context logs, sanitize command errors, and enforce private staging before writing bytes. Windows uses and verifies a protected process-user/LocalSystem DACL. |
| Integrity: filesystem substitutions | Staged bytes were not rechecked; file identity/mode substitutions and parent replacement could redirect or alter writes. Replacing files lost security metadata. | Pin filesystem roots; check canonical paths, identity, contents and security metadata; recheck staging and committed outputs; preserve supported security metadata and attempt bounded rollback on failure. Linux applies original security metadata before restoring mode bits; Windows retains the original object and security descriptor. |
| Availability: excessive work | Per-character provenance, whole-source multipart detection/HTML parsing, reverse-splicing Unicode escapes, unbounded rechecks, and unlimited directory enumeration amplified input cost. | Compact provenance; use upstream-sized detector/decoder windows; use linear Unicode reconstruction; cap views, patterns, findings, unique edits, detector work, metadata, files and directories; bound rechecks. |
| Functional correctness and future review | Duplicate multipart combinations exhausted a span budget for the same source occurrences. The static audit omitted some computed map writes/direct assignments, weakening update review. | Deduplicate physical spans before accounting. Strengthen the AST audit and test its dynamic-key/assignment handling; compare a freshly generated inventory in CI. |

## Refactor review on 2026-10-19

Two additional defects were reproduced with failing tests before correction:

- **P1, confidentiality:** a MySQL JDBC DSN containing both userinfo and a query
  password could return successfully after redacting only the query value. The
  generic URI parser rejects the DSN host syntax; the old early return skipped
  the JDBC fallback. The same partial acceptance occurred for malformed URI
  userinfo. Connection extraction now includes the fallback password even when
  another password was found, and refuses unresolved parse errors. Real JDBC
  detector regressions cover both cases; exact command fixtures preserve the
  username, host and query syntax, and a batch-failure test preserves originals.
- **P2, correctness:** a source at the library's size boundary could be rejected
  because an early expanding edit exceeded an intermediate estimate, even when
  later shrinking edits brought final output within budget. The check now uses
  the final size with 64-bit arithmetic. A boundary regression checks exact
  untouched bytes and continued refusal of genuinely oversized output.

Shared helpers now perform exhaustive credential validation, bounded offline
execution for both scan phases, checked staged-file opening, durable close and
identity verification, and source-edit copying. Private staging, root pinning,
security metadata restoration, rollback, work budgets and residual detection
remain enforced. No upstream detector policy or reviewed inventory was relaxed.

## Windows runner path repair on 2026-10-19

The first published Windows CI run exposed a functional refusal of legitimate
8.3 paths: its `RUNNER~1` temporary-directory spelling differed from the long
path returned by the open handle. The new native regression failed before the
repair and passes afterward. The guard now derives short aliases from the
resolved handle target and accepts each component's long or short spelling.
It never resolves the caller's potentially symbolic spelling to authorize it.
Direct long paths retain their fast path; real directory-junction rejection
passes, and existing file/ancestor-symlink rejection remains enforced.

## Windows standard-user editing

The earlier Windows implementation replaced the source with a staged file and
copied its complete security descriptor, including the audit SACL. Reading and
restoring that SACL introduced a `SeSecurityPrivilege` requirement even for files
the user owned. This was an implementation constraint, not a requirement for
editing ordinary source-file contents. The previous elevation guidance is
superseded by the same-file mechanism below.

Windows now retains each original file object. After scanning and private
staging finish, it acquires read/write handles for every changed file with
write/delete sharing denied. It validates file identity and contents and rejects
hard links, read-only files, reparse points and unavailable locks before editing
any original. It writes, truncates, flushes and verifies through those handles;
controlled failures restore the current and earlier files through the same
handles. No original owner, DACL, SACL or integrity label is copied or changed,
so no audit privilege, Administrator session or token modification is required.
Microsoft documents [file access and sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
and [reopening the existing object](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile).

Same-file writes can be interrupted by process termination or power loss and
are not crash-atomic. Rollback covers controlled failures, not every operating
system or storage failure. The importing pipeline must keep the tree private
and require exit status zero before exposing it downstream.

## Native CLI integration

Full TruffleHog retains its upstream commands, flags and normal scanner path.
`--in-place` opts local filesystem inputs into the same bounded source-editing
implementation used by the compatibility wrapper. It runs the ordinary scanner
against the original source, prints its normal findings, then commits redaction.
The preceding scan preserves verification, output, result filters, profiling and
comparison semantics; importing pipelines should use `--no-verification` to
prevent provider checks. Its printed findings can contain original credentials,
as explicitly requested, so stdout and other normal output channels must remain
trusted. The separate source-editing pass always disables verification and ignores
reporting filters. Self-updates are skipped during editing to retain the fork's
redaction implementation. Remote sources and Git history cannot be edited.
Detector and path selections bound what is redacted, so importing pipelines
must avoid exclusions which hide secrets from their selected scope.

Release smoke tests capture ordinary JSON findings without printing them and
verify the source remains byte-for-byte unchanged. Native in-place tests require
original-secret JSON findings, exact edits, second-pass absence of findings,
idempotence and preserved Windows file identity. Both native and
wrapper executables are bound to the same reviewed source revision and archive
allowlist; the isolated publisher validates both x64 executable headers without
running them or checking out repository code.

## Validation

The current corpus requires positive coverage for **899/899 registered scanner
instances**, with no detection or mapping gaps. This is one positive fixture per
scanner, supplemented by exact-source, structured-credential, encoding,
idempotence, failure, cancellation, resource-budget and confidentiality tests.

Linux validation requires actual in-place writes and a second unchanged pass for
all 899 scanner samples. The full production-registry command exercises a nested
900-file tree on two runs. Fifteen separate fixtures specify exact expected
source bytes independently; connection-parse failure and Box ambiguity
regressions preserve their entire original batches. Linux ownership, extended
attribute and POSIX ACL tests run on native Linux storage. Compatibility CI
records the passing results for each published revision.

Windows compatibility requires the actual in-place corpus, exact command fixtures
and second unchanged pass on NTFS without privileged descriptor copying. The
release build separately requires packaged full TruffleHog to preserve ordinary
offline JSON findings and upstream command help, then edit two nested files via
`filesystem --in-place`, preserve their identities and pass again unchanged.
The compatibility wrapper also passes exact UTF-8/CRLF source-stream checks. Audit-SACL fixture creation can require
privileged test setup; that optional fixture cannot replace ordinary successful
in-place tests. Linux metadata tests execute on native Linux storage. The decoder
and GCP upstream unit suites, static-audit and context tests, workflow lint, and
diff whitespace checks are also run. See each revision's CI results rather than
reusing results from the earlier privilege-dependent implementation.

## Remaining operating constraints

- Gate downstream access on exit status zero, and use an exclusively owned
  imported tree. A malicious concurrent writer cannot be excluded by a
  filesystem-wide compare-and-swap operation; a batch is not crash-atomic.
- Windows storage must retain protected staging ACLs and stable file identity.
  Use a private NTFS import with ordinary read/write access. Files with read-only
  attributes, hard-link aliases or conflicting access are rejected before the
  batch is edited. The command does not elevate or modify its token.
- Linux preserves uid/gid and readable extended attributes by copying them to
  replacements. Windows retains the existing file object and its owner/group/
  DACL/SACL, including audit rules and mandatory integrity labels. Unsupported
  metadata, unavailable access and other operating systems block in-place edits.
  Windows same-file writes can leave a partially written file after abrupt
  termination; Linux individual renames remain atomic.
- Only file contents are redacted. Git history, filenames, alternate data
  streams, extended attributes and other metadata can retain credentials.
- The positive corpus covers the 899 registered scanner instances. Twenty-six
  intentionally disabled upstream implementations remain outside this command.
  Ambiguous Box OAuth layouts can be refused when a retained public identifier
  becomes a new post-edit candidate; the original batch remains untouched.
- Verification is disabled and candidates can be false positives. Secrets
  outside detector coverage or requiring context beyond upstream-sized chunks
  are not guaranteed to be found. Encoded/ambiguous matches can fail closed.
- Cooperative deadlines and checked budgets cannot interrupt every blocking
  syscall/detector, recover fatal runtime failures, or replace process-level
  CPU/memory limits for hostile imports. Replacing credentials can invalidate
  source schemas or application behavior by design.

See [usage](source-redaction.md) and [maintenance](redaction-maintenance.md).
