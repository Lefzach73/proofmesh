# Threat model

The subjects are workloads, not human users. Logical trust domains have distinct authority
namespaces. The verifier trusts its local configuration, authorization rules, clock and the
origin of evidence marked authenticated. The simulator's issuer fingerprints and signature-valid
flags are synthetic descriptors; they perform no cryptographic authentication.

Controlled schedules can delay/drop delivery, partition/heal the virtual network, replay older
bundles, submit foreign-domain or expired identities, replay request identifiers and model issuer
compromise. No external target is contacted by the offline core.

The policy enforces exact namespaces, deny-by-default rules, available sequence monotonicity,
explicit uncertainty and rejection after observed issuer removal. It cannot know that a cached
issuer was revoked remotely before notice arrives. Within the configured budget, unseen
revocation can therefore coexist with ACCEPT. A compromised authorized issuer can forge an
otherwise permitted identity; freshness checks do not solve that problem.

The optional durable state protects against tested process interruption and accidental corruption
under local filesystem assumptions. It does not resist malicious replacement by a trusted disk
owner. Request replay in the simulator is a laboratory rule, not an intrinsic X.509 property.

Hybrid TLS key exchange and certificate-signature authentication are distinct properties.
The simulator always records PQ authentication as false. Symbolic models assume ideal
cryptography and a bounded rotation abstraction; they do not prove memory safety, wire-protocol
equivalence, real-world liveness or computational cryptographic security.

Use synthetic inputs and disposable loopback integration credentials only. The separate optional
integration is experimental; the original broader research workspace retains dependency findings
and incomplete research gates. No production-security or whole-platform clearance is asserted.
