# Contributing and attribution

Start with the README, architecture, threat model and public-export manifest. Use `make check`,
`make race` and focused checks relevant to a change. Preserve frozen scenario inputs and record
negative results, timeouts, failures and changed assumptions. A new experiment or label change
requires versioned inputs; do not tune against inspected data and call it confirmatory.

Use maintained cryptographic libraries. Keep production secrets, customer telemetry, private host
paths and raw private CI archives out of this public repository. The unsafe B1 baseline remains
isolated in the diagnostic Python harness and is not a CLI policy mode.

This implementation was created with AI assistance. Human hypothesis conception, threat review,
labeling, interpretation and authorship have not been independently established. Git identity and
repository ownership are separate from scientific authorship. No contribution is automatically
attributed to Dr. Eleftherios Zacharioudakis.

Public source presentation has been authorized; original-code reuse licensing remains pending.
Do not infer a license grant from visibility. Upstream rights and notices remain applicable.
