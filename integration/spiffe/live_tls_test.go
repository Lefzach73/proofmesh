package main

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func TestRetainedCredentialMTLSLifecycle(t *testing.T) {
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
	a, err := alpha.issue("spiffe://alpha.local/server", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	b, err := old.issue("spiffe://beta.local/client", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	c, err := next.issue("spiffe://beta.local/client", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	expired, err := old.issue("spiffe://beta.local/client", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	both := old.bundle()
	both.AddX509Authority(next.cert)
	bundles := x509bundle.NewSet(alpha.bundle(), both)
	clientBundles := x509bundle.NewSet(alpha.bundle(), old.bundle())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// One listener and the same retained b key/credential across every phase.
	probe := func(svid *x509svid.SVID, expectedServer, expectedClient spiffeid.ID) (tlsObservation, tlsObservation) {
		t.Helper()
		done := make(chan tlsObservation, 1)
		go func() {
			raw, e := listener.Accept()
			if e != nil {
				done <- tlsObservation{Error: e.Error()}
				return
			}
			done <- serveTLSConnection(raw, source{a}, bundles, expectedClient)
		}()
		client := dialTLS(context.Background(), listener.Addr().String(), source{svid}, clientBundles, expectedServer)
		select {
		case server := <-done:
			return client, server
		case <-time.After(5 * time.Second):
			t.Fatal("server deadline")
			return client, tlsObservation{}
		}
	}
	for _, svid := range []*x509svid.SVID{b, c} {
		client, server := probe(svid, a.ID, b.ID)
		if !client.Accepted || !server.Accepted || client.PeerVerification != "verified" || server.PeerVerification != "verified" {
			t.Fatalf("overlap: client=%+v server=%+v", client, server)
		}
		if client.TLSVersion != tls.VersionTLS13 || server.TLSVersion != tls.VersionTLS13 || client.DidResume || server.DidResume || client.PQAuthenticated || server.PQAuthenticated {
			t.Fatal("invalid transport claim")
		}
	}
	client, server := probe(b, a.ID, a.ID)
	if client.Accepted || server.Accepted || server.PeerVerification != "peer_policy_denied" {
		t.Fatalf("wrong client policy: %+v %+v", client, server)
	}
	client, server = probe(b, b.ID, b.ID)
	if client.Accepted || server.Accepted || client.PeerVerification != "peer_policy_denied" {
		t.Fatalf("wrong server policy: %+v %+v", client, server)
	}
	client, server = probe(expired, a.ID, b.ID)
	if client.Accepted || server.Accepted || server.PeerVerification != "certificate_expired" {
		t.Fatalf("expiry misclassified: %+v %+v", client, server)
	}
	// Replace the live trust view; never change the retained client credential.
	bundles.Add(next.bundle())
	client, server = probe(b, a.ID, b.ID)
	if client.Accepted || server.Accepted || server.PeerVerification != "unknown_authority" || server.PeerCertificateSHA256 != certificateHash(b.Certificates[0]) {
		t.Fatalf("removed root: %+v %+v", client, server)
	}
	client, server = probe(c, a.ID, b.ID)
	if !client.Accepted || !server.Accepted {
		t.Fatalf("legitimate rotation availability: %+v %+v", client, server)
	}
}

func TestLiveTLSRefusesMissingConfiguration(t *testing.T) {
	for _, role := range []string{"server", "client", "invalid"} {
		if liveTLS("tcp://remote:8081", "", "", role, "") == nil {
			t.Fatal("nonlocal socket accepted")
		}
	}
	if liveTLS("unix:///nonexistent", "spiffe://alpha.local", "spiffe://beta.local/c", "client", "127.0.0.1:1") == nil {
		t.Fatal("root identity allowed")
	}
	// No listening server is a transport failure, not revocation evidence.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	obs := dialTLS(context.Background(), address, nil, nil, spiffeid.ID{})
	if obs.Accepted || obs.PeerVerification != "not_reached" {
		t.Fatalf("transport failure: %+v", obs)
	}
}
