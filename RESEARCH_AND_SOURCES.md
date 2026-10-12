# ProofMesh — Readings / Prior Art / Implementation References

Checked against public sources on 2026-10-11. All links are starting points, not proof of novelty or evergreen API stability. Verify installed versions and latest errata.

| Source | Type | Relevance / trap to avoid |
|---|---|---|
| https://nrat.ukrintei.ua/searchdoc/0418U001073/ | Official thesis repository | Father's 2018 distributed-user identification thesis; related but not identical to service workload identity. |
| https://spiffe.io/docs/latest/deploying/svids/ | Specification docs | SPIFFE SVID/workload API and mTLS; do not replace with homemade identity format. |
| https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/ | Standard | Cross-domain federation, key rotation and authenticated distribution; avoid key merge. |
| https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/ | Standard | Per-domain bundles, sequence and refresh; review no-sequence case. |
| https://github.com/spiffe/spire | Implementation | Actual release features / limitations; no unverified PQC issuing assumptions. |
| https://github.com/spiffe/go-spiffe | Official library | Real SVID/integration; pin dependency. |
| https://datatracker.ietf.org/doc/html/rfc10024 | IETF RFC, Aug 2026 | Three hybrid TLS key-exchange groups; NOT signature-based PQ authentication. |
| https://csrc.nist.gov/pubs/fips/203/final | NIST standard | ML-KEM; note 2025 errata / latest revisions. |
| https://csrc.nist.gov/pubs/fips/204/final | NIST standard | ML-DSA signatures and 2026 errata; distinct from ML-KEM. |
| https://openssl-library.org/news/openssl-3.5-notes/index.html | OpenSSL official | ML-KEM/ML-DSA and hybrid TLS; check runtime negotiated group. |
| https://tamarin-prover.com/manual/master/book/001_introduction.html | Formal tool manual | Symbolic security models; termination not assured. |
| https://tamarin-prover.com/manual/master/book/003_example.html | Formal tool manual | Actual `tamarin-prover model.spthy --prove` CLI and basic lemmas. |
| https://arxiv.org/abs/2607.20800 | 2026 preprint | Prior art on classical acceptance erroneously reported as hybrid auth. Compare, don't repackage as novel. |
| https://github.com/open-quantum-safe/liboqs | Research implementation | Explicit experimental/non-production warning. Prefer OpenSSL for local TLS benchmark. |
| https://cloud.google.com/blog/products/identity-security/pqc-in-plaintext-google-clouds-post-quantum-cryptography-roadmap | Industry engineering context, Aug 2026 | Emphasizes hybrid KEX vs authentication migration; roadmap is not already completed functionality. |
| https://docs.github.com/en/actions/reference/security/secure-use | GitHub documentation | Least-privilege CI and third-party action risk. |

## Read-first questions for the research lead

1. Do we want to focus on cross-domain rotation correctness, PQ migration claim semantics, or their interaction? The primary hypothesis should be one testable comparison, not all topics equally.
2. Which assumptions are realistic for identity lifecycle and incident response latency? Disallow unverifiable immediate revocation claims.
3. Who reviews the threat model and Tamarin proof independently? Are thesis/IP artifacts reused by permission?
4. Are the systems for **workloads** (services) or human users? Keep them distinct in abstracts and CV.
