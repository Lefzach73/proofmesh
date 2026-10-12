# Contributor guidance

This repository is the curated public ProofMesh companion. Read README.md, docs/ARCHITECTURE.md,
docs/EVIDENCE.md and docs/PUBLICATION.md before changes. The private study archive is not part of
this export, and this repository's checks do not certify that archive.

Preserve the simulation/cryptography distinction, exact trust-domain isolation, typed uncertainty,
frozen scenario hashes, negative results and attribution. Never treat hybrid key exchange as
post-quantum authentication, a stub as a proof, or repeated deterministic outputs as independent
samples. Run make check and the relevant targeted checks after changes. Optional integrations are
local and explicit; default CI must not provision resources, call paid services or contact targets.

Update public source hashes deliberately after reviewed edits. Original-code licensing remains
pending; do not invent a license grant or human scientific authorship. Record changed validation
scope and real outcomes in docs/IMPLEMENTATION_STATUS.md.
