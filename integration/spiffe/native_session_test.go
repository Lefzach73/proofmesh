package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func nativeTestListener(t *testing.T, server *x509svid.SVID, peer spiffeid.ID, bundles x509bundle.Source) (string, *nativeSessionCounter, <-chan map[string]any) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	counter := &nativeSessionCounter{}
	rows := make(chan map[string]any, 32)
	cleanup := startNativeSessionListener(ctx, listener, source{server}, bundles, peer, counter, func(row map[string]any) { rows <- row })
	t.Cleanup(func() { cancel(); cleanup() })
	return listener.Addr().String(), counter, rows
}

func nativeTestRow(t *testing.T, rows <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case row := <-rows:
		return row
	case <-time.After(5 * time.Second):
		t.Fatal("native session evidence timeout")
		return nil
	}
}

func TestNativeSessionRetainsHandshakeAcrossEmptySource(t *testing.T) {
	alpha, err := newAuthority("alpha.local")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := alpha.issue("spiffe://alpha.local/native-server", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	client, err := beta.issue("spiffe://beta.local/native-client", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// This focused test uses the maintained mutable Set source. The executable
	// wires the same Source interface to its live Workload API X509Source.
	bundles := x509bundle.NewSet(beta.bundle())
	address, counter, rows := nativeTestListener(t, server, client.ID, bundles)
	retained := &applicationSession{}
	defer retained.close()
	if o := retained.connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); !o.Accepted || o.DidResume || o.TLSVersion != tls.VersionTLS13 {
		t.Fatal(o)
	}
	firstHandshake := nativeTestRow(t, rows)
	if o := firstHandshake["tls"].(tlsObservation); !o.Accepted || o.PeerVerification != "verified" || firstHandshake["connection_id"] != uint64(1) || firstHandshake["handshake_verifications"] != uint64(1) {
		t.Fatal(firstHandshake)
	}
	request := func(wantCount uint64, trustStatus string, verifications uint64) {
		t.Helper()
		if response := retained.request(); response["transport_success"] != true || response["accepted"] != true {
			t.Fatal(response)
		}
		row := nativeTestRow(t, rows)
		trust := row["current_trust"].(map[string]any)
		if row["handler_executed"] != true || row["handler_before"] != wantCount-1 || row["handler_after"] != wantCount || row["connection_id"] != uint64(1) || row["certificate_sha256"] != certificateHash(client.Certificates[0]) || row["authentication_scope"] != "handshake-historical" || row["per_request_chain_validation"] != false || row["handshake_verifications"] != verifications || trust["status"] != trustStatus {
			t.Fatal(row)
		}
	}
	request(1, "available", 1)
	bundles.Add(x509bundle.New(beta.domain))
	status := counter.status(bundles, client.ID)
	if trust := status["current_trust"].(map[string]any); trust["status"] != "empty" || trust["found"] != true || len(trust["root_certificate_sha256"].([]string)) != 0 || status["handshake_verifications"] != uint64(1) {
		t.Fatal(status)
	}
	request(2, "empty", 1) // Expected handshake-only control observation.
	fresh := &applicationSession{}
	defer fresh.close()
	if o := fresh.connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); o.Accepted {
		t.Fatal("fresh handshake succeeded with empty source", o)
	}
	failed := nativeTestRow(t, rows)
	if o := failed["tls"].(tlsObservation); o.Accepted || o.PeerVerification != "unknown_authority" || failed["connection_id"] != uint64(2) || failed["handshake_verifications"] != uint64(2) {
		t.Fatal(failed)
	}
	request(3, "empty", 2)
	// Explicit test-fixture trust restoration; no automatic rebootstrap occurs.
	bundles.Add(beta.bundle())
	if o := fresh.connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); !o.Accepted || o.DidResume {
		t.Fatal(o)
	}
	recovered := nativeTestRow(t, rows)
	if recovered["connection_id"] != uint64(3) || recovered["handshake_verifications"] != uint64(3) {
		t.Fatal(recovered)
	}
	if response := fresh.request(); response["accepted"] != true {
		t.Fatal(response)
	}
	if row := nativeTestRow(t, rows); row["handler_after"] != uint64(4) || row["connection_id"] != uint64(3) || row["handshake_verifications"] != uint64(3) || row["certificate_sha256"] != certificateHash(client.Certificates[0]) {
		t.Fatal(row)
	}
}

func TestNativeSessionWrongPeerMalformedAndReadErrorsHaveNoEffect(t *testing.T) {
	alpha, err := newAuthority("alpha.local")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := alpha.issue("spiffe://alpha.local/native-server", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	client, err := beta.issue("spiffe://beta.local/native-client", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := beta.issue("spiffe://beta.local/wrong", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	bundles := x509bundle.NewSet(beta.bundle())
	address, counter, rows := nativeTestListener(t, server, client.ID, bundles)
	session := &applicationSession{}
	defer session.close()
	if o := session.connect(context.Background(), address, source{wrong}, alpha.bundle(), server.ID); o.Accepted {
		t.Fatal(o)
	}
	if row := nativeTestRow(t, rows); row["tls"].(tlsObservation).PeerVerification != "peer_policy_denied" {
		t.Fatal(row)
	}
	if o := session.connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); !o.Accepted {
		t.Fatal(o)
	}
	nativeTestRow(t, rows)
	if response := session.sendApplication([]byte("!"), false); response["transport_success"] != true || response["accepted"] != false {
		t.Fatal(response)
	}
	if row := nativeTestRow(t, rows); row["reason"] != "MALFORMED_REQUEST" || row["handler_executed"] != false || row["handler_before"] != uint64(0) || row["handler_after"] != uint64(0) {
		t.Fatal(row)
	}
	session.close()
	raw, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Close() // EOF before a TLS handshake is not a request/effect.
	if row := nativeTestRow(t, rows); row["tls"].(tlsObservation).Accepted || row["handler_executed"] != false {
		t.Fatal(row)
	}
	if o := session.connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); !o.Accepted {
		t.Fatal(o)
	}
	nativeTestRow(t, rows)
	session.close() // EOF after a successful handshake also has no effect.
	if status := counter.status(bundles, client.ID); status["counter"] != uint64(0) {
		t.Fatal(status)
	}
}

type nativeErrorSource struct{ err error }

func (s nativeErrorSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return nil, s.err
}

func TestNativeTrustObservationDistinguishesMissingEmptyAndFailure(t *testing.T) {
	domain := spiffeid.RequireTrustDomainFromString("beta.local")
	set := x509bundle.NewSet()
	if row := nativeTrustObservation(set, domain); row["status"] != "missing_domain" || row["found"] != false || row["error"] == nil {
		t.Fatal(row)
	}
	set.Add(x509bundle.New(domain))
	if row := nativeTrustObservation(set, domain); row["status"] != "empty" || row["found"] != true || row["error"] != nil {
		t.Fatal(row)
	}
	if row := nativeTrustObservation(nativeErrorSource{errors.New("source is unavailable")}, domain); row["status"] != "source_error" || row["found"] != nil || row["error"] == nil {
		t.Fatal(row)
	}
}

func TestNativeSessionRejectsAmbiguousControlAndExternalAddress(t *testing.T) {
	for _, raw := range []string{`null`, `{"op":"request","op":"request"}`, `{"Op":"request"}`, `{"op":"request","payload":"?"}`, `{"op":"request"} {}`, `{"op":"status"}`, strings.Repeat(" ", 4097)} {
		if _, err := nativeSessionCommand([]byte(raw), "client"); err == nil {
			t.Fatal("accepted malformed client control", raw)
		}
	}
	for _, op := range []string{"connect", "request", "close"} {
		if got, err := nativeSessionCommand([]byte(`{"op":"`+op+`"}`), "client"); err != nil || got != op {
			t.Fatal(got, err)
		}
	}
	if op, err := nativeSessionCommand([]byte(`{"op":"status"}`), "server"); err != nil || op != "status" {
		t.Fatal(op, err)
	}
	for _, address := range []string{"example.com:443", "8.8.8.8:443", ":8443", "0.0.0.0:8443", "127.0.0.1:0"} {
		if nativeSessionAddress(address) == nil {
			t.Fatal("non-explicit lab address", address)
		}
	}
	for _, address := range []string{"127.0.0.1:8443", "172.28.0.3:8443", "[::1]:8443"} {
		if err := nativeSessionAddress(address); err != nil {
			t.Fatal(address, err)
		}
	}
}
