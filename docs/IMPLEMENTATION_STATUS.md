# Public companion validation

Date: 2026-10-12. Source snapshot: `c9fd0579b280dad65c41d6f631c6225b654fd834`.
Local environment: macOS arm64, Go 1.27.2, Python 3.14.3. A previously installed pinned Go
toolchain was read from outside the candidate; build caches and generated outputs stayed local
to this companion. No download, production credential or paid service was needed.

| Exact public command | Local result |
|---|---|
| `make test` | PASS: six tested Go packages and 23 Python checks |
| `make race` | PASS: all six tested core packages |
| `make demo` | PASS: real compiled CLI; structured simulated decisions |
| `make restart-demo` | PASS: separate processes accept sequence 12, reject 11, retain watermark 12 |
| `make bench-offline` | PASS: 81 schedules, 27 families, 3,159 rows, zero failed runs |
| `make report` | PASS: exact denominators, family summaries and all unsafe accepts retained |
| `make fuzz` | PASS: two bounded campaigns; 1,096,288 identity and 308,696 simulator executions |
| `go vet ./...` | PASS under the pinned toolchain, network module lookup disabled |
| `python3 scripts/verify_public_export.py` | PASS: finite source inventory and public-text checks |

The measured synthetic raw SHA-256 is
`72dfd2468e322168cb136d76b24a4751b8c3db58f5be3fdd828bc317bfa6b524`, identical to the original
reference. The fresh runner took 5.419632 seconds on this host; this single runtime is not a
general performance result. Default B3/120 still has 6/48 unsafe accepts and 51/66 correct
authorized accepts. Equal-budget B2/B3 ACCEPT parity and the zero-budget utility loss remain.

For the optional SPIFFE module, `go -C integration/spiffe test -run '^$' ./...` passed using the
previously cached pinned dependencies. This was compile-only: its real mTLS test suite was not
rerun for this public export. Tamarin was not run; the 15 formal-runner controls among the
23 Python checks use explicit stub outputs and are not proof evidence.

Six isolated export-admission controls passed: an intact copy was admitted; empty inventory,
changed README, unlisted source, escaping path and inconsistent unchanged-source provenance
were rejected. An initial check wrongly rejected an intact macOS temporary directory because
it inspected symlinks above the checkout. The guard now checks paths inside the checkout; the
original failure and corrected controls remain in the private publication ledger.

The public workflow uses the same verified official action revisions as the original workflow,
read-only permission, a standard Linux runner and a ten-minute cap. It runs only the offline
core. Hosted execution status is reported by the repository's actual Actions run; this local
record is not a claim that a future hosted run already passed.

This is a smaller source export, not the complete original integrity or experiment suite.
Private raw integration evidence and history remain preserved. See [scope](PUBLICATION.md),
[evidence](EVIDENCE.md), `PUBLIC_EXPORT_MANIFEST.json` and `PUBLIC_VALIDATION.json`.
