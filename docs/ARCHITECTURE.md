# Architecture

The core is a Go standard-library module with no external runtime dependencies.

| Component | Responsibility |
|---|---|
| `internal/identity` | Canonical typed SPIFFE identifiers and exact trust-domain names |
| `internal/bundle` | Per-domain immutable snapshots, monotonic sequence knowledge and tombstones |
| `internal/policy` | Pure authorization evaluator returning typed decisions and evidence |
| `internal/sim` | Bounded strict-JSON parser, virtual time and deterministic event ordering |
| `internal/state` | Optional local durable checkpoints and process-level state ownership |
| `cmd/proofmesh` | Scenario validation, simulation, state commands and analysis wrappers |
| `experiments/scripts/oracle.py` | Separately implemented authoritative scenario truth |

A request binds claimed source, credential identity/issuer domain, target, audience, action and
transport profile. Identity, validity and policy checks precede trust-snapshot evaluation. B3
returns INDETERMINATE when evidence is uncertain; B2 returns REJECT at the same boundary. An
issuer known to be removed remains rejected even after its cache ages.

The simulator keeps authoritative bundles separate from the verifier's delivered cache.
Publication does not deliver notice, and a dropped fetch cannot refresh the cache. Scenario labels
are used by the evaluation harness, never by the policy evaluator. The oracle is a separate Python
implementation from the same AI engineering process, not independent human labeling.

Optional checkpoints preserve sequence, epoch, clock and tombstone knowledge. They rely on a
trusted local filesystem and do not defeat an owner rolling back the whole state. The default
simulator is ephemeral. See [persistent state](PERSISTENT_STATE.md).

`integration/spiffe` is a separate pinned module using maintained go-spiffe and Go X.509/TLS.
Its source includes real peer validation, retained-session and application-gate test controls.
It is not used by the offline policy simulator or default CI. Tamarin theories are another
separate layer; they do not prove source-code equivalence.

This companion excludes the original Docker/SPIRE orchestration, full formal history, private
CI receipts and raw integration archive. Those omissions are part of the public-export scope,
not deleted findings or a claim that all original experiments reran here.
