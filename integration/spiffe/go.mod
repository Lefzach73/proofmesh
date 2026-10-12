module proofmesh.local/research/integration/spiffe

go 1.27.2

require github.com/spiffe/go-spiffe/v2 v2.9.0

require proofmesh.local/research v0.0.0

replace proofmesh.local/research => ../..

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	golang.org/x/net v0.60.0
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
