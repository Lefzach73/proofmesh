# Security

ProofMesh is a research prototype. Use only synthetic scenarios and disposable loopback lab
credentials. The simulator's signature flags do not authenticate real identities. INDETERMINATE
must not be promoted to ACCEPT. Do not expose the optional integration as a public service.

Known boundaries include unseen revocation within the freshness budget, compromised authorized
issuers, trusted local clocks and authenticated bundle origins. Whole-file rollback by a trusted
storage owner is outside the checkpoint guarantee. Formal models cover stated symbolic
assumptions; software tests and hashes do not certify production safety.

Do not put secrets or real telemetry in public issues. Send a minimized synthetic reproduction
through an established private channel with the maintainer. No monitored security mailbox or
response-time commitment is asserted. See docs/THREAT_MODEL.md for the complete public scope.
