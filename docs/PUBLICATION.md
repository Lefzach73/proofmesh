# Public companion and provenance

This is a curated source export for public inspection and local reproduction. The original
`proofmesh-research` repository remains the private provenance archive. Its source commit is
recorded in `PUBLIC_EXPORT_MANIFEST.json`; no original history was rewritten or exposed through this
companion.

Included: unchanged core Go sources/tests, original frozen simulator inputs and oracle,
the optional go-spiffe source module and its lockfiles, current formal models/runner, selected
software checks and upstream notices. New README, guides, CI and export checks describe this
smaller deliverable. Any modified original file is listed separately with both hashes.

Excluded: private execution host paths, raw CI/account receipts, full integration results,
historical proof archives, toolchains, caches, keys, binary artifacts, unevaluated confirmatory
packets, Docker orchestration and original Git history. Omissions do not turn negative or missing
original results into successes. The evidence guide retains the principal negative findings.

Generated local benchmark/report/checkpoint outputs are ignored. They are newly generated
evidence and are not hashed as immutable public source. The verifier checks every listed source
file, requires a nonempty inventory, and rejects unexpected files outside the declared generated
directories. `PUBLIC_EXPORT_MANIFEST.json` cannot include its own hash. Delivery metadata and validation
notes are included in the fixed inventory like every other public source file. Updating a source hash is a deliberate export revision, not proof of correctness.

Default GitHub Actions runs only the offline core, after installing the pinned language
toolchains. It has read-only repository permission, a finite timeout and no cloud provisioning,
Docker lab, paid model, deployment or formal-tool installation. Optional integrations require
explicit local commands and their prerequisites.

Public visibility is authorized. The original-code reuse license is still pending; contributor
authorship, third-party rights and independent scientific review are not inferred from that
visibility decision.
