# Source-redaction security review

Reviewed on 2026-10-08 and 2026-10-19. The review covers the fork additions and their interaction
with the original detector results, decoders, filesystem command, and update CI.
Reproductions use synthetic local credentials; verification remains disabled.

## Findings and repairs

| Risk | Confirmed behavior | Repair and regression coverage |
| --- | --- | --- |
| Confidentiality: residual structured secrets | Returning the first URI password/SAS signature or the last JSON private key left other values in the source while the audit passed. GCP also normalized away duplicate fields before redaction. | Collect all password/signature/private-key values; request original GCP JSON only in source mode. Tests invoke real JDBC, Azure SAS and GCP detectors and compare exact edited source. |
| Confidentiality: expanded scanner output | Additive `SecretParts` entries were also serialized by the ordinary TruffleHog JSON printer. | Request extra components only with a source-redaction context. The full scanner corpus checks ordinary results omit each added field and source results contain it. |
| Confidentiality: diagnostics and temporary files | Detector panic payloads, context logs, invalid flag values, writer errors, and insufficient staging permissions could expose source information. Windows mode `0600` did not restrict ACLs. | Recover panics without payloads, discard detector context logs, sanitize command errors, and enforce private staging before writing bytes. Windows uses and verifies a protected process-user/LocalSystem DACL. |
| Integrity: filesystem substitutions | Staged bytes were not rechecked; file identity/mode substitutions and parent replacement could redirect or alter writes. Replacing files lost security metadata. | Pin filesystem roots; check canonical paths, identity, contents and security metadata; recheck staging and committed outputs; preserve supported security metadata and attempt bounded rollback on failure. Apply original security metadata before restoring mode bits. |
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

## Validation

The complete offline redaction corpus passes for **897/897 registered scanner
instances**, with no detection or mapping gaps. This is one positive fixture per
scanner, supplemented by exact-source, structured-credential, encoding,
idempotence, failure, cancellation, resource-budget and confidentiality tests.

The refactored Linux command passes actual in-place writes and a second unchanged
pass for all 897 scanner samples. The full production-registry command passes a
nested 898-file tree on two runs. Fifteen separate fixtures specify exact
expected source bytes independently; connection-parse failure and Box ambiguity
regressions preserve their entire original batches. Linux ownership, extended
attribute and POSIX ACL tests also pass on native Linux storage in WSL.

The CLI suite and private staging/canonical-path tests are exercised on Windows
NTFS. Full-descriptor preservation requires an enabled audit privilege; the local
token lacks it: 19 privilege-dependent checks skip, along with three unavailable
symlink checks. The native Windows CLI suite otherwise passes; missing-privilege
refusal verifies originals remain untouched. The rebuilt Windows executable also
passes exact UTF-8/CRLF source-stream redaction and idempotence, including both
passwords in the mixed JDBC DSN. Linux metadata tests execute in
existing WSL Ubuntu on native Linux storage. The decoder and GCP upstream unit
suites, static-audit and context tests, workflow lint, and diff whitespace checks
are also run.

## Remaining operating constraints

- Gate downstream access on exit status zero, and use an exclusively owned
  imported tree. A malicious concurrent writer cannot be excluded by a
  filesystem-wide compare-and-swap operation; a batch is not crash-atomic.
- Windows filesystems must retain protected ACLs and stable file identity.
  The local E: drive did not support those guarantees; the command rejects
  in-place writes there before source bytes are staged. NTFS tests use a
  private authorized C: test directory. Windows also requires an already-enabled
  `SeSecurityPrivilege` to retain per-file audit SACLs. The shipping command
  does not enable privileges; missing access blocks writes. Stdin mode remains
  available without that privilege.
  This follows Microsoft's [full-descriptor access requirements](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)
  and [SACL-setting requirements](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo).
- Linux preserves uid/gid and readable extended attributes. Windows preserves
  the full owner/group/DACL/SACL descriptor, including audit rules and mandatory
  integrity labels. Unsupported metadata,
  copy failures and other operating systems block in-place replacement.
- Only file contents are redacted. Git history, filenames, alternate data
  streams, extended attributes and other metadata can retain credentials.
- The positive corpus covers the 897 registered scanner instances. Twenty-six
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
