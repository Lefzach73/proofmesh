# Symbolic model sources

This companion includes three current Tamarin theories and a 19-check runner contract. The
original private study recorded 18 positive/helper checks and an expected issuer-compromise
counterexample. Those old proof logs are not bundled or represented as fresh public verification.

Theories assume ideal signatures, trusted policy/domain bindings, serialized cache decisions and
a two-version rotation abstraction. They do not establish SPIFFE wire equivalence, implementation
memory safety, arbitrary integer sequence behavior, filesystem security, real credential expiry
or computational ML-KEM/ML-DSA security.

With Tamarin 1.12.0 and Maude 3.5.1 installed and available on PATH:

```sh
make formal
```

`TAMARIN` may select an installed prover. The runner records source snapshots, commands, status,
runtime and raw output under ignored generated directories. Missing tools, timeouts, unknown or
unexpected outcomes produce a failure. The negative control must produce an actual counterexample.

Default CI only tests the runner using stub outputs to exercise missing/changed source and
incomplete-check rejection. Those unit tests are software validation, not mathematical proofs.
