GO := $(if $(wildcard .tools/go/bin/go),$(CURDIR)/.tools/go/bin/go,go)
PYTHON ?= python3
export GOTOOLCHAIN := local
export GOCACHE := $(CURDIR)/.cache/go-build
export GOPATH := $(CURDIR)/.cache/gopath
export GOMODCACHE := $(CURDIR)/.cache/gomod
export PROOFMESH_PYTHON := $(PYTHON)
.PHONY: setup build test race demo restart-demo bench-offline report check fuzz formal integration-spiffe prepare
prepare:
	mkdir -p .cache experiments/manifests experiments/reports/progress-0.2 formal/proof_logs
setup: prepare
	$(PYTHON) scripts/setup_tools.py
	$(GO) version
build: prepare
	mkdir -p bin
	GOPROXY=off GOSUMDB=off $(GO) build -trimpath -o bin/proofmesh ./cmd/proofmesh
test: prepare
	GOPROXY=off GOSUMDB=off $(GO) test -count=1 ./cmd/... ./internal/...
	$(PYTHON) -m unittest discover -s tests -v
race: prepare
	GOPROXY=off GOSUMDB=off $(GO) test -race -count=1 ./cmd/... ./internal/...
demo: build
	./bin/proofmesh demo
restart-demo: build
	$(PYTHON) scripts/restart_demo.py
bench-offline: build
	$(PYTHON) experiments/scripts/compare.py
report:
	$(PYTHON) experiments/scripts/report.py
check: test
	GOPROXY=off GOSUMDB=off $(GO) vet ./...
	$(PYTHON) scripts/verify_public_export.py
fuzz: prepare
	GOPROXY=off GOSUMDB=off $(GO) test ./internal/identity -run='^$$' -fuzz=FuzzParser -fuzztime=5s -parallel=2
	GOPROXY=off GOSUMDB=off $(GO) test ./internal/sim -run='^$$' -fuzz=FuzzDecoder -fuzztime=5s -parallel=2
integration-spiffe: prepare
	$(GO) -C integration/spiffe test -race ./...
formal: prepare
	$(PYTHON) formal/run.py
