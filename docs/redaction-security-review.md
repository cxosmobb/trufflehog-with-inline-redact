# Source-redaction security review

Reviewed on 2026-10-08, 2026-10-19, 2026-10-23, and 2026-10-24. The review covers the fork additions and their interaction
with the original detector results, decoders, filesystem command, and update CI.
Unit reproductions use synthetic local credentials; integration also uses the
public, intentionally vulnerable WrongSecrets fixture. Verification remains disabled.

## Findings and repairs

| Risk | Confirmed behavior | Repair and regression coverage |
| --- | --- | --- |
| Confidentiality: residual structured secrets | Returning the first URI password/SAS signature or the last JSON private key left other values in the source while the audit passed. GCP also normalized away duplicate fields before redaction. | Collect all password/signature/private-key values; request original GCP JSON only in source mode. Tests invoke real JDBC, Azure SAS and GCP detectors and compare exact edited source. |
| Confidentiality: expanded scanner output | Additive `SecretParts` entries were also serialized by the ordinary TruffleHog JSON printer. | Request extra components only with a source-redaction context. The full scanner corpus checks ordinary results omit each added field and source results contain it. |
| Confidentiality: diagnostics and recovery files | Detector panic payloads, context logs, invalid flag values, writer errors, and insufficient staging permissions could expose source information. Windows mode `0600` did not restrict ACLs. | Recover panics without payloads, discard editing-pass context logs, sanitize command errors, and protect Linux stages before writing bytes. Windows stores authenticated undo contents only as user-scoped DPAPI ciphertext in source-bound ADS; it creates no visible sidecar stages. |
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

Windows retains each original file object. It acquires read/write handles for
every changed file with write/delete sharing denied, validates identity and
contents, and rejects hard links, read-only files, reparse points and unavailable
locks before editing. It writes, truncates, flushes and verifies through those
handles; controlled failures restore the current and earlier files through the
same handles. The owner, DACL, SACL and integrity label are never copied or
changed, so no audit privilege, Administrator session or token modification is
required. Microsoft documents [file access and sharing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
and [reopening the existing object](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile).

## Windows interrupted-write recovery

Same-file writes previously relied on process-local rollback. Terminating a
process during a write left a torn file after the original bytes disappeared
from memory. Windows now durably records each original and intended target
before mutation. The authenticated record uses user-scoped Windows DPAPI and
lives in reserved ADS on the original source object. It is bound to that file's
identity, parent identity, canonical path and readable security metadata.
Original source bytes never reach a recovery stream as plaintext. Windows
creates no visible sidecar stages, and unrelated ADS remain attached unchanged.

The encrypted payload is flushed before its ready marker is created and flushed;
the base object is flushed before its source bytes change. After all changed
sources are flushed and verified, cleanup durably removes each marker before
its payload. If rollback has written original bytes but their flush fails,
byte equality alone cannot justify deleting the recovery records: every restored
source must flush successfully before any journal is cleared. A regression
injects that final flush failure and requires both journals to remain armed.

Recovery runs before detection and path selection in the explicit input scope.
This matters because a torn secret may no longer match a detector, and current
filters may exclude a file selected by the interrupted run. Valid armed records
restore and verify the original bytes, after which ordinary scanning and
redaction retry. A completed record already durably disarmed is only cleaned up;
its target remains intact. Invalid authentication, unexpected bytes, changed
identity/path/policy, competing locks and resource overruns fail closed without
discarding the affected record. ADS opens are relative to the pinned source
handle, and cleanup acts on those exact stream handles.

Per-file/ciphertext checks run before allocation and DPAPI. Fixed record caps
and aggregate journal budgets bound pending-record work. Recovery's unfiltered
enumeration obeys file/directory limits; configured per-file and total limits
also bound the current sources processed by recovery and the subsequent scan.
These bounds do not claim a historical-original total across already disarmed,
completed records, which need no undo write.

Regression tests kill real child processes after a flushed partial second-file
write, after source completion, during recovery and after durable disarming.
Fresh invocations must recover before scanning/filtering, produce exact final
bytes and retain original identities, security descriptors and unrelated ADS.
Corrupted/truncated/forged records, journal swaps, replay onto a replacement,
post-crash content/ACL changes, new hard links and active transactions must be
refused. The tests also run with the existing restricted Windows token; no
elevated privilege is enabled. They test process interruption, not physical
power loss. Durability assumes the original local NTFS objects and storage that
honors flush requests. The same Windows user must retain their DPAPI keys and
rerun the same input paths. A whole directory is not an atomic transaction;
keep it private and gate downstream access on exit status zero.
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

## WrongSecrets hardening

The repository case is pinned to OWASP WrongSecrets
`1b51b6fbcaaba5fd69389d551d2f41ec922a4135`: all 969 tracked files and
225,524,378 original bytes, including four roughly 42 MiB Swift binaries and
JAR contents. The application and its scripts are never executed. The acceptance
test requires positive ordinary findings, the same findings while editing,
zero ordinary findings afterward, positive scan metrics, no handler/read errors,
a pinned full-content manifest, unchanged inventory and Windows identities, and
byte-idempotence. The fixture
and these requirements describe the test target; passing evidence belongs to the
specific source revision's Linux and Windows CI results.

The fixes retain conservative limits and precise edits:

- Source/output and per-version Windows recovery caps are 64 MiB; cumulative
  decoded views and expanded archive data are bounded at 256 MiB. The default
  per-file CLI limit remains 16 MiB, requiring an explicit increase for this
  fixture. Previous v1 recovery records remain readable. Tests cover large
  unchanged inputs, EOF/chunk-boundary secrets, oversized refusal, and real
  termination during a large write and recovery under the restricted token.
- Classic Store/Deflate ZIP/JAR inputs are validated before member scanning.
  Unchanged containers retain their exact bytes; changed members are rebuilt
  and revalidated. Entry, nesting and expanded-byte bounds remain enforced.
  Mapping, residual auditing, metadata and all nested members share one finite
  detector-input budget of `(2 << 30) - 1` bytes. It combines the former separate
  phase allowances within a 32-bit-safe cap instead of resetting per member.
  Encryption, ZIP64, unsafe/ambiguous layouts, unsupported
  formats and detected secrets in archive metadata fail closed. Edits to
  recognized signed packages are refused. Container headers/compression can
  change while unrelated logical member contents remain intact.
- Source-mode Slack extraction includes the complete final webhook token.
  JDBC/Postgres marker checks inspect parsed password components, including
  duplicate parameters; a real password must not disappear behind another
  `REDACTED` value. Marker substrings, unfamiliar/malformed layouts and verified
  credentials are retained as candidates. Only reviewed password-free JDBC URL
  forms are connection metadata. Unknown query properties, fragments and vendor
  host-property/multi-host syntax do not qualify for harmless/marker-only
  classification: source mode refuses unsupported credential roles before
  normalization can discard them. This includes MySQL `password1/2/3` and
  pgJDBC `sslpassword`; the existing precisely parsed MySQL `tcp(host:port)`
  path remains supported. Ordinary extraction, verification and result controls
  remain available.
- Shortening an executable string can move an unrelated identifier into a
  detector's keyword window. Structurally recognized ELF, PE and thin Mach-O
  inputs therefore receive the exact encoded `REDACTED` replacement plus ASCII
  space padding only inside the original mapped secret extent. File length,
  offsets and neighboring bytes stay fixed; a replacement wider than its extent
  fails closed. NUL padding was insufficient: HTML decoding removed it and
  promoted unrelated public identifiers into new Box candidates. ASCII spaces
  avoid that observed cascade; all decoded views still undergo residual auditing
  and any remaining/new credential candidate blocks output. Structural
  recognition does not establish full executable validity,
  runtime behavior, checksum correctness or signature integrity. Java class
  files and fat Mach-O headers do not select this fixed-extent behavior.

Precisely mapped views apply the same identifier-boundary rule during edits and
residual checks, so unrelated identifier substrings stay intact. For HTML, a lazy
bounded provenance check can additionally prove that the full residual match
belongs to one unchanged contiguous ASCII source run in text, a quoted attribute
or a comment. Audit-only random sentinels track runs through tokenization/DOM
normalization; stripping them must reproduce the original canonical decoder bytes
exactly. Only a match with no credential boundary inside that single run can be
retained as part of a larger identifier. These sentinels never reach source
files or replace the complete post-edit detector input.

Entity decoding, invisible-character removal, cross-markup joins, partial matches
and malformed/unproved provenance keep strict residual treatment. A remaining
paired component joined to `REDACTED` cannot pass merely because the paired
detector stops firing. Ordinary HTML decoder output and full post-edit detector
checks remain unchanged; this is a source-ownership proof, not a result mask.

These changes do not suppress detector types or omit binary/archive files to
obtain a zero. Residual audits still refuse edits that leave actual credential
components or introduce an ambiguous candidate.

## Validation

The current corpus requires positive coverage for **901/901 registered scanner
instances**, with no detection or mapping gaps. This is one positive fixture per
scanner, supplemented by exact-source, structured-credential, encoding,
idempotence, failure, cancellation, resource-budget and confidentiality tests.

Linux validation requires actual in-place writes and a second unchanged pass for
all 901 scanner samples. The full production-registry command exercises a nested
902-file tree on two runs. Fifteen separate fixtures specify exact expected
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
- Windows storage must retain stable file identities and reserved ADS and honor
  flush requests. Use an exclusively owned local NTFS import with ordinary
  read/write access and the same user's DPAPI keys. Files with read-only
  attributes, hard-link aliases or conflicting access are rejected before the
  batch is edited. The command does not elevate or modify its token.
- Linux preserves uid/gid and readable extended attributes by copying them to
  replacements. Windows retains the existing file object and its owner/group/
  DACL/SACL, including audit rules and mandatory integrity labels. Unsupported
  metadata, unavailable access and other operating systems block in-place edits.
  Windows interrupted same-file writes recover on retry before scanning; until
  recovery succeeds, a file or batch can have mixed contents. Invalid recovery
  records remain in place and block completion. Linux individual renames remain
  atomic.
- Only file contents are redacted. Git history, filenames, alternate data
  streams, extended attributes and other metadata can retain credentials.
- The positive corpus covers the 901 registered scanner instances. Twenty-six
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

Tru provider context uses namespace boundaries, so ordinary `true`, `trust` or
`structure` text cannot turn public CSP nonces and script fragments into
credentials. The scanner remains enabled with its existing credential alphabet,
component fields and verification behavior. Synthetic mixed-source tests require
real Tru candidates to be redacted while public HTML remains byte exact; the
pinned WrongSecrets integration also requires its entire `chatgpt_dump.html`
file to remain unchanged. CI runs the complete Tru detector unit package.
