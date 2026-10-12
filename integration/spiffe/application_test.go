package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"proofmesh.local/research/internal/evidence"
)

func testGateUpdate(t *testing.T, gate *applicationGate, sequence uint64, observed time.Time, certs ...*x509.Certificate) {
	t.Helper()
	b := spiffebundle.FromX509Authorities(gate.cache.remote, certs)
	b.SetSequenceNumber(sequence)
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if reason, err := gate.cache.apply(authenticatedBundle{b, observed, "unit-test-public-bundle"}); err != nil || reason != evidence.Updated {
		t.Fatal(reason, err)
	}
	gate.generation++
}

func testAppListener(t *testing.T, gate *applicationGate, server *x509svid.SVID, arm string) (string, <-chan any) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	rows := make(chan any, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for connection := uint64(1); ; connection++ {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			serveApplicationConnection(ctx, raw, source{server}, gate, arm, connection, func(row any) { rows <- row })
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("application server did not stop")
		}
	})
	return listener.Addr().String(), rows
}

func nextAppRow(t *testing.T, rows <-chan any) map[string]any {
	t.Helper()
	select {
	case row := <-rows:
		return row.(map[string]any)
	case <-time.After(5 * time.Second):
		t.Fatal("application evidence timeout")
		return nil
	}
}

func TestApplicationGateRechecksExistingTLSSessions(t *testing.T) {
	for _, arm := range []string{"B0.direct", "B2/3", "B3/3"} {
		t.Run(arm, func(t *testing.T) {
			alpha, err := newAuthority("alpha.local")
			if err != nil {
				t.Fatal(err)
			}
			old, err := newAuthority("beta.local")
			if err != nil {
				t.Fatal(err)
			}
			next, err := newAuthority("beta.local")
			if err != nil {
				t.Fatal(err)
			}
			server, err := alpha.issue("spiffe://alpha.local/service", time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			client, err := old.issue("spiffe://beta.local/client", time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			newClient, err := next.issue(client.ID.String(), time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			gate := newApplicationGate(server.ID, []spiffeid.ID{client.ID}, old.domain)
			testGateUpdate(t, gate, 1, time.Now().Add(-5*time.Second), old.cert)
			address, rows := testAppListener(t, gate, server, arm)
			session := &applicationSession{}
			defer session.close()
			if o := session.connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); !o.Accepted || o.DidResume || o.PQAuthenticated {
				t.Fatal(o)
			}
			handshake := nextAppRow(t, rows)
			if !handshake["tls"].(tlsObservation).Accepted {
				t.Fatal(handshake)
			}
			check := func(want string, count uint64, reason string) {
				t.Helper()
				response := session.request()
				row := nextAppRow(t, rows)
				if response["transport_success"] != true || response["accepted"] != (want == "ACCEPT") || row["outcome"] != want || row["handler_after"] != count || row["handler_executed"] != (want == "ACCEPT") || row["connection_id"] != handshake["connection_id"] {
					t.Fatal(response, row)
				}
				if row["private_key_possession_verified"] != true || row["pq_authenticated"] != false {
					t.Fatal(row)
				}
				chain := row["chain_and_metadata"].(map[string]any)
				if reason != "" && chain["verification_result"] != reason {
					t.Fatal(chain)
				}
			}
			count := uint64(0)
			want := "REJECT"
			if arm == "B3/3" {
				want = "INDETERMINATE"
			}
			if arm == "B0.direct" {
				want = "ACCEPT"
				count++
			}
			check(want, count, "verified")
			testGateUpdate(t, gate, 1, time.Now(), old.cert)
			count++
			check("ACCEPT", count, "verified")
			// The TLS connection remains open with proof of the OLD private key.
			// Replacing the root prevents the next effect on that same connection.
			testGateUpdate(t, gate, 2, time.Now(), next.cert)
			check("REJECT", count, "unknown_authority")
			session.close()
			if o := session.connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); o.Accepted {
				t.Fatal("removed issuer opened new session")
			}
			if h := nextAppRow(t, rows)["tls"].(tlsObservation); h.Accepted || h.PeerVerification != "unknown_authority" {
				t.Fatal(h)
			}
			if o := session.connect(context.Background(), address, source{newClient}, alpha.bundle(), server.ID); !o.Accepted {
				t.Fatal(o)
			}
			handshake = nextAppRow(t, rows)
			count++
			check("ACCEPT", count, "verified")
			session.close()
			unpermitted, err := next.issue("spiffe://beta.local/unpermitted", time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if o := session.connect(context.Background(), address, source{unpermitted}, alpha.bundle(), server.ID); o.Accepted {
				t.Fatal("valid unpermitted identity accepted")
			}
			if h := nextAppRow(t, rows)["tls"].(tlsObservation); h.Accepted || h.PeerVerification != "peer_policy_denied" {
				t.Fatal(h)
			}
		})
	}
}

func TestApplicationRejectsFetchAuthenticatedBeforeConcurrentTrustReplacement(t *testing.T) {
	old, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	next, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := old.issue("spiffe://beta.local/spire/server", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	own, _ := spiffeid.FromString("spiffe://alpha.local/service")
	gate := newApplicationGate(own, []spiffeid.ID{endpoint.ID}, old.domain)
	testGateUpdate(t, gate, 11, time.Now(), old.cert)
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert, sequence := next.cert, uint64(12)
		if r.URL.Path == "/slow" {
			close(started)
			<-release
			cert, sequence = old.cert, 13
		}
		b := spiffebundle.FromX509Authorities(old.domain, []*x509.Certificate{cert})
		b.SetSequenceNumber(sequence)
		raw, _ := b.Marshal()
		_, _ = w.Write(raw)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{endpoint.Certificates[0].Raw}, PrivateKey: endpoint.PrivateKey}}}
	server.StartTLS()
	defer server.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	bootstrap := x509bundle.NewSet(old.bundle())
	slow := make(chan map[string]any, 1)
	go func() { slow <- gate.refresh(context.Background(), server.URL+"/slow", endpoint.ID, bootstrap) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("slow fetch did not start")
	}
	fast := gate.refresh(context.Background(), server.URL, endpoint.ID, bootstrap)
	if fast["success"] != true {
		t.Fatal(fast)
	}
	close(release)
	result := <-slow
	if result["success"] != false || result["error"] != "trust generation changed while fetch was in flight" || result["generation"] != fast["generation"] {
		t.Fatal(result)
	}
	if gate.cache.bodyHash != fast["snapshot"].(map[string]any)["response_sha256"] {
		t.Fatal("obsolete response replaced current trust")
	}
	if row := gate.refresh(context.Background(), server.URL, endpoint.ID, bootstrap); row["success"] != false {
		t.Fatal("stale bootstrap re-enabled removed endpoint key", row)
	}
}
