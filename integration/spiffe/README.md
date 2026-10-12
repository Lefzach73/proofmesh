# Optional real SPIFFE integration

This separate Go module uses pinned `go-spiffe/v2 v2.9.0` and Go's maintained X.509/TLS stack.
Its sources and tests are preserved from the original workspace; dependencies are pinned in
`go.mod` and `go.sum`. Root core code is referenced through the local module replacement.

```sh
make integration-spiffe
```

Run from the repository root. The first execution downloads pinned modules. The tests exercise
disposable certificates and local loopback endpoints, including exact peer authorization,
retained sessions and bounded application effects. Do not use production credentials or expose
test services. Default public CI excludes this opt-in integration.

The broader original Docker/SPIRE federation runner and its private raw evidence are omitted
from this companion. This source export does not certify current optional-dependency security
or reproduce all old laboratory stages. Upstream licenses are retained in
`../../docs/third_party_licenses/`; the original implementation's reuse license remains pending.
