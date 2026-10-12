# Evidence and limitations

This page separates results retained from the original research workspace from checks rerun on
the public companion. Origin: private source snapshot
`c9fd0579b280dad65c41d6f631c6225b654fd834`. The original workspace and its negative results remain
preserved privately. The public source selection and byte hashes are in `PUBLIC_EXPORT_MANIFEST.json`.

## Synthetic study: reproducible with this companion

The supplied frozen inputs contain 81 schedules, 27 families and three seeds per family. The
diagnostic grid pairs B1, B2 and B3 on the same schedules; B1 is a deliberately unsafe negative
control, not stock SPIRE. Three identical repeats check determinism and do not create independent
observations. F18's undefined truth remains excluded from rates and retained in raw records.

The original reference output has SHA-256
`72dfd2468e322168cb136d76b24a4751b8c3db58f5be3fdd828bc317bfa6b524`.
It includes B3/120's **6/48 unauthorized accepts** and **51/66 correct authorized accepts**.
B2 and B3 have equal ACCEPT sets at equal budgets. Budget zero produced zero valid accepts;
zero unsafe accepts in that setting does not establish useful protection. These limits are not
replaced by a claimed candidate improvement.

Run `make bench-offline report` to generate new local raw rows, exact denominators, paired family
bootstrap summaries and unsafe-accept records. The input freeze is retained unchanged. Any public
reproduction outcome is recorded separately in [implementation status](IMPLEMENTATION_STATUS.md).

## Broader original study: contextual summary, not a public rerun

The original workspace records real stock SPIRE and minimal-derived integration experiments,
including trust rotation, expiry, delivered empty bundles, durable toy effects and retained mTLS
sessions. Its latest local native-session experiment records 253 stages with no stage failures
for each of the two profiles. A configured handshake-only application continues an effect on
an existing session after trust removal reaches its source, while the request-validation controls
block effects. Recovery is explicitly administrator-assisted. This is an application policy
boundary, not a claimed TLS/SPIRE vulnerability or B3-specific security advantage.

The original Tamarin gate records 18 verified positive/helper checks and one expected
issuer-compromise counterexample under stated model assumptions. Its old failed attempts and
ten historical source-byte exceptions remain in the private archive. The public companion
includes current model/runner sources and tests the runner's software contract. It does not
publish the old proof archive or claim to have repeated those proofs.

Stock-binary vulnerability findings and narrower derived-package assessments remain unresolved
scope limits; neither functional success nor a public repository clears them. The full original
paired 27-family real-system comparison remains incomplete.

## Scientific boundaries

The studies are exploratory. Separate code implementations do not substitute for independent
human labels or scientific review. No novelty, universal security, population-level efficacy,
post-quantum authentication, production readiness or publication certification is established.
Preserve attribution to upstream standards and implementations; see `RESEARCH_AND_SOURCES.md`.
