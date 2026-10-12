package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	corebundle "proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
)

func TestAuthenticatedPublisherRollbackPreservesAdmittedTrust(t *testing.T) {
	old, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	current, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := current.issue("spiffe://beta.local/publisher", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	fresh := spiffebundle.FromX509Authorities(current.domain, []*x509.Certificate{current.cert})
	fresh.SetSequenceNumber(12)
	stale := spiffebundle.FromX509Authorities(old.domain, []*x509.Certificate{old.cert})
	stale.SetSequenceNumber(11)
	freshBody, _ := fresh.Marshal()
	staleBody, _ := stale.Marshal()
	p := &bundlePublisher{domain: current.domain}
	if _, err = p.publish(freshBody); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(p)
	server.TLS = tlsconfig.TLSServerConfig(source{endpoint})
	// httptest inserts its DNS certificate unless Certificates is nonempty.
	server.TLS.Certificates = []tls.Certificate{{Certificate: [][]byte{endpoint.Certificates[0].Raw}, PrivateKey: endpoint.PrivateKey}}
	server.TLS.MinVersion = tls.VersionTLS13
	server.TLS.MaxVersion = tls.VersionTLS13
	server.StartTLS()
	defer server.Close()
	cache := pairedCache{remote: current.domain, store: corebundle.New()}
	fetched, err := fetchAuthenticatedBundle(context.Background(), server.URL, endpoint.ID, current.bundle())
	if err != nil {
		t.Fatal(err)
	}
	if reason, err := cache.apply(fetched); err != nil || reason != evidence.Updated {
		t.Fatal(reason, err)
	}
	baseline := cache.summary()
	if _, err = p.publish(staleBody); err != nil {
		t.Fatal(err)
	}
	// Fresh TLS authenticates the CURRENT publisher. Only the public BODY is old.
	replay, err := fetchAuthenticatedBundle(context.Background(), server.URL, endpoint.ID, cache.trustForFetch(nil))
	if err != nil {
		t.Fatal(err)
	}
	if reason, err := cache.apply(replay); err != nil || reason != evidence.Rollback {
		t.Fatal(reason, err)
	}
	if !reflect.DeepEqual(cache.summary(), baseline) {
		t.Fatal("rejected replay changed trust/age")
	}
	if _, err := fetchAuthenticatedBundle(context.Background(), server.URL, spiffeid.RequireFromString("spiffe://beta.local/wrong"), cache.trustForFetch(nil)); err == nil {
		t.Fatal("publisher identity not enforced")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.served) != 2 || p.served[0]["body_sha256"] == p.served[1]["body_sha256"] {
		t.Fatal("missing distinct authenticated bodies")
	}
}

func TestPublisherRefusesSecretAndInvalidPayloadWithoutReplacingState(t *testing.T) {
	p := &bundlePublisher{domain: spiffeid.RequireTrustDomainFromString("beta.local")}
	hash, err := p.publish([]byte(`{"keys":[],"spiffe_sequence":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"keys":[],"keys":[]}`, `{"keys":[{"kty":"EC","d":"forbidden"}]}`, `{"keys":null}`, `{"keys":[]} trailing`} {
		if _, err := p.publish([]byte(raw)); err == nil {
			t.Fatalf("accepted forbidden/malformed payload: %s", raw)
		}
		if p.hash != hash {
			t.Fatal("invalid publication replaced state")
		}
	}
}
