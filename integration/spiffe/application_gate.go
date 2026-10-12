package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	corebundle "proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	coreid "proofmesh.local/research/internal/identity"
)

// One cache and one lock serve ALL listener-bound arms. The lock serializes
// updates, current-chain/policy checks, and the protected counter effect. It is
// intentionally NOT held across network I/O. Optional disk commits precede
// visible updates and effects; both B2 and B3 share the same persistence option.
type applicationGate struct {
	mu              sync.Mutex
	cache           pairedCache
	own             spiffeid.ID
	allowed         map[spiffeid.ID]bool
	generation      uint64
	counters        map[string]uint64
	disk            *trustDisk
	stateError      error
	counterUnknown  bool
	requests        *requestJournal
	requestProtocol bool
}

func (g *applicationGate) enableRequestProtocol(arms []string) error {
	if g.disk == nil {
		return errors.New("request-v1 requires durable trust state and its process lease")
	}
	j, err := openRequestJournal(g.disk.path+".requests", g.own, g.cache.remote, arms)
	if err != nil {
		return err
	}
	g.requests, g.counters, g.requestProtocol = j, j.counters, true
	return nil
}

func (g *applicationGate) enablePersistence(ctx context.Context, path string, at time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	disk, cache, err := openTrustDisk(ctx, path, g.cache.remote, at.Unix())
	if err != nil {
		return err
	}
	g.disk, g.cache = disk, cache
	return nil
}

// Must be called only after all users of the gate have stopped.
func (g *applicationGate) close() {
	if g.disk != nil {
		g.disk.unlock()
		g.disk = nil
	}
}

func (g *applicationGate) persist(ctx context.Context, cache pairedCache, at time.Time) error {
	if g.stateError != nil {
		return g.stateError
	}
	if g.disk != nil {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := g.disk.save(ctx, cache, at.Unix()); err != nil {
			// A failed commit may have reached disk before a later sync failed.
			// Never continue accepting from a potentially older memory snapshot.
			g.stateError = fmt.Errorf("live security state unavailable: %w", err)
			return g.stateError
		}
	}
	return nil
}

func (g *applicationGate) removeTrust(ctx context.Context) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	domain, _ := coreid.ParseDomain(g.cache.remote.String())
	next := pairedCache{remote: g.cache.remote, store: g.cache.store.Remove(domain)}
	row := map[string]any{"event": "application-remove-trust", "success": false}
	if len(next.store.Records()) == 0 {
		// Explicit local removal before a first fetch must also disable future
		// bootstrap. Epoch is local policy metadata; no sequence is invented.
		var err error
		next.store, err = corebundle.Restore([]corebundle.Record{{Domain: domain.String(), HighEpoch: 1}})
		if err != nil {
			row["error"] = err.Error()
			return row
		}
	}
	if err := g.persist(ctx, next, time.Now()); err != nil {
		row["error"] = err.Error()
	} else {
		g.cache = next
		g.generation++
		row["success"] = true
	}
	row["generation"], row["security_records"], row["snapshot"] = g.generation, g.cache.store.Records(), g.cache.summary()
	return row
}

func newApplicationGate(own spiffeid.ID, allowed []spiffeid.ID, remote spiffeid.TrustDomain) *applicationGate {
	g := &applicationGate{cache: pairedCache{remote: remote, store: corebundle.New()}, own: own, allowed: map[spiffeid.ID]bool{}, counters: map[string]uint64{}}
	for _, id := range allowed {
		g.allowed[id] = true
	}
	return g
}

func (g *applicationGate) GetX509BundleForTrustDomain(domain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stateError != nil {
		return nil, g.stateError
	}
	if domain != g.cache.remote || g.cache.bundle == nil {
		return nil, errors.New("no admitted bundle for exact peer domain")
	}
	return g.cache.bundle.X509Bundle(), nil
}

func (g *applicationGate) authorize(id spiffeid.ID, _ [][]*x509.Certificate) error {
	if !g.allowed[id] {
		return errPeerPolicy
	}
	return nil
}

func (g *applicationGate) refresh(ctx context.Context, endpoint string, id spiffeid.ID, bootstrap x509bundle.Source) map[string]any {
	g.mu.Lock()
	if g.stateError != nil {
		err := g.stateError
		g.mu.Unlock()
		return map[string]any{"event": "application-refresh", "success": false, "error": err.Error()}
	}
	trust, generation := g.cache.trustForFetch(bootstrap), g.generation
	g.mu.Unlock()
	response, err := fetchAuthenticatedBundle(ctx, endpoint, id, trust)
	g.mu.Lock()
	defer g.mu.Unlock()
	row := map[string]any{"event": "application-refresh", "success": false, "fetch_generation": generation}
	if err != nil {
		row["error"] = err.Error()
	} else if g.stateError != nil {
		row["error"] = g.stateError.Error()
	} else if generation != g.generation {
		// Even a numerically higher response authenticated by an obsolete root
		// must not restore trust after a concurrent removal. Retry from current
		// anchors; no silent bootstrap fallback.
		row["error"] = "trust generation changed while fetch was in flight"
	} else {
		next := g.cache
		reason, applyErr := next.apply(response)
		if applyErr == nil && reason == evidence.Updated {
			applyErr = g.persist(ctx, next, time.Now())
		}
		row["update_reason"] = reason
		if applyErr != nil {
			row["error"] = applyErr.Error()
		}
		if applyErr == nil && reason == evidence.Updated {
			g.cache = next
			g.generation++
			row["success"] = true
		}
	}
	row["generation"], row["snapshot"] = g.generation, g.cache.summary()
	return row
}

func decisionOutcome(value any) string {
	switch d := value.(type) {
	case evidence.Decision:
		return string(d.Outcome)
	case map[string]any:
		result, _ := d["outcome"].(string)
		return result
	default:
		return "REJECT"
	}
}

// Called ONLY after successful mTLS and a fixed, valid application request.
// TLS establishes possession; cache.check independently revalidates the actual
// session certificate against the CURRENT bundle and metadata for EVERY request.
func (g *applicationGate) execute(certs []*x509.Certificate, arm string) map[string]any {
	return g.executeApplication(certs, arm, nil, nil)
}

func (g *applicationGate) executeRequest(certs []*x509.Certificate, arm string, raw []byte) map[string]any {
	r, err := decodeApplicationRequest(raw)
	return g.executeApplication(certs, arm, &r, err)
}

func (g *applicationGate) executeApplication(certs []*x509.Certificate, arm string, request *applicationRequest, parseErr error) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	before := g.counters[arm]
	row := map[string]any{"event": "application-request", "arm": arm, "generation": g.generation, "handler_before": before, "handler_after": before, "handler_executed": false, "outcome": "REJECT", "private_key_possession_verified": true, "pq_authenticated": false}
	if g.counterUnknown {
		// A prior commit may have advanced the durable counter beyond memory.
		// This request has no new effect, but absolute counts remain unknown.
		row["handler_before"], row["handler_after"] = nil, nil
		row["counter_unknown"], row["last_acknowledged_counter"] = true, before
	}
	if g.stateError != nil {
		row["error"], row["reason"] = g.stateError.Error(), "STATE_ERROR"
		return row
	}
	if len(certs) == 0 {
		row["error"] = "missing TLS peer chain"
		return row
	}
	id, err := x509svid.IDFromCert(certs[0])
	if err != nil || !g.allowed[id] {
		row["error"] = "exact peer identity policy denied"
		return row
	}
	row["authenticated_peer"], row["certificate_sha256"] = id.String(), certificateHash(certs[0])
	if parseErr != nil {
		row["reason"], row["error"] = "MALFORMED_REQUEST", parseErr.Error()
		return row
	}
	if (g.requests == nil) != (request == nil) {
		row["reason"], row["error"] = "PROTOCOL_MISMATCH", "explicit request-v1 and durable journal required together"
		return row
	}
	if request != nil {
		row["application_request"] = *request
		audience, err := spiffeid.FromString(request.Audience)
		if err != nil || audience != g.own || request.Action != "increment" {
			row["reason"] = "POLICY_DENIED"
			return row
		}
	}
	// This captured request timestamp is durable before evaluating or producing
	// any effect. Fsync latency is not claimed to be zero or a real-time bound.
	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := g.persist(ctx, g.cache, now); err != nil {
		row["error"] = err.Error()
		return row
	}
	check := g.cache.check(certs, g.own, id, now)
	row["chain_and_metadata"] = check
	decisions := check["decisions"].(map[string]any)
	decision, ok := decisions[arm]
	if !ok {
		row["error"] = fmt.Sprintf("no decision for configured arm %s", arm)
		row["reason"] = "UNKNOWN_VERIFIER_STATE"
		if g.cache.bundle == nil {
			row["reason"] = "MISSING_BUNDLE"
		}
		return row
	}
	row["decision"], row["outcome"] = decision, decisionOutcome(decision)
	if request != nil {
		row["metadata_decision"] = decision
		delete(row, "decision")
	}
	if row["outcome"] == "ACCEPT" {
		if request != nil {
			next, reason, err := g.requests.commit(arm, id, request.RequestID)
			row["reason"] = reason
			if err != nil {
				g.stateError = fmt.Errorf("request state unavailable: %w", err)
				row["outcome"], row["error"] = "REJECT", g.stateError.Error()
				if reason == "COMMIT_UNKNOWN" {
					// Rename may have committed the counter even when the later
					// directory sync failed. Never report that as zero effects.
					row["outcome"], row["commit_unknown"] = "INDETERMINATE", true
					row["handler_executed"], row["handler_after"] = nil, nil
					g.counterUnknown = true
					row["counter_unknown"], row["last_acknowledged_counter"] = true, before
				}
				return row
			}
			if reason != "AUTHORIZED" {
				row["outcome"] = "REJECT"
				return row
			}
			g.requests, g.counters = next, next.counters
			row["handler_executed"], row["handler_after"], row["effect_persistence"] = true, g.counters[arm], "durable-counter-and-request-id"
			return row
		}
		// This counter is the entire protected lab handler. Denied/indeterminate
		// requests cannot reach it. No business payload precedes this point.
		g.counters[arm]++
		row["handler_executed"], row["handler_after"] = true, g.counters[arm]
	}
	return row
}
