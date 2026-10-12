# Dependencies and retained notices

The offline Go core and Python analysis use their language standard libraries. The optional
SPIFFE module pins the following dependencies. This inventory is copied from the original
source audit; it is not a fresh vulnerability scan or legal clearance.

| Module | Version | Retained license evidence |
|---|---|---|
| github.com/Microsoft/go-winio | v0.6.2 | [MIT](third_party_licenses/cf248820bf1178370bb4f1670a59f8748d46bc96d0f64080cd631511c6046409.txt) |
| github.com/go-jose/go-jose/v4 | v4.1.5 | [Apache-2.0](third_party_licenses/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt) |
| github.com/spiffe/go-spiffe/v2 | v2.9.0 | [Apache-2.0](third_party_licenses/c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4.txt) |
| golang.org/x/net | v0.60.0 | [BSD-3-Clause](third_party_licenses/911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad.txt) |
| golang.org/x/sys | v0.48.0 | [BSD-3-Clause](third_party_licenses/911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad.txt) |
| golang.org/x/text | v0.42.0 | [BSD-3-Clause](third_party_licenses/911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad.txt) |
| google.golang.org/genproto/googleapis/rpc | v0.0.0-20260526163538-3dc84a4a5aaa | [Apache-2.0](third_party_licenses/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt) |
| google.golang.org/grpc | v1.83.2 | [Apache-2.0](third_party_licenses/cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30.txt), [Apache-2.0](third_party_licenses/693ff28ec216d5112ac1bbfe64ef539005867d1c7bd427b57d579683293b947f.txt) |
| google.golang.org/protobuf | v1.36.12 | [BSD-3-Clause](third_party_licenses/4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20.txt) |

Go standard library notice: [BSD-3-Clause](third_party_licenses/911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad.txt).

The module source and binaries are not vendored. Dependencies keep their original terms.
The project itself has no original-code reuse license grant; see ../LICENSE_PENDING.md.
