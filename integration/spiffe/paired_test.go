package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	corebundle "proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
)

func TestAuthenticatedBundleFetchRejectsWrongPeerAndMalformedBody(t *testing.T) {
	ca, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	svid, err := ca.issue("spiffe://beta.local/spire/server", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	b := spiffebundle.FromX509Authorities(ca.domain, []*x509.Certificate{ca.cert})
	b.SetSequenceNumber(12)
	body, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			_, _ = w.Write([]byte(`{"keys":[],"keys":[]}`))
			return
		}
		if r.URL.Path == "/noversion" {
			unversioned := spiffebundle.FromX509Authorities(ca.domain, []*x509.Certificate{ca.cert})
			raw, _ := unversioned.Marshal()
			_, _ = w.Write(raw)
			return
		}
		if r.URL.Path == "/empty" {
			// The standard requires an array, not null; an explicit empty array
			// revokes previously published keys (Trust Domain and Bundle 4.1.3).
			_, _ = w.Write([]byte(`{"keys":[],"spiffe_sequence":13}`))
			return
		}
		_, _ = w.Write(body)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{svid.Certificates[0].Raw}, PrivateKey: svid.PrivateKey}}}
	server.StartTLS()
	defer server.Close()
	trust := x509bundle.NewSet(ca.bundle())
	fetched, err := fetchAuthenticatedBundle(context.Background(), server.URL, svid.ID, trust)
	if err != nil {
		t.Fatal(err)
	}
	sequence, present := fetched.bundle.SequenceNumber()
	if !present || sequence != 12 {
		t.Fatal("optional sequence lost")
	}
	unversioned, err := fetchAuthenticatedBundle(context.Background(), server.URL+"/noversion", svid.ID, trust)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := unversioned.bundle.SequenceNumber(); present {
		t.Fatal("absent sequence invented")
	}
	cache := pairedCache{remote: ca.domain, store: corebundle.New()}
	if reason, err := cache.apply(unversioned); err != nil || reason != evidence.Updated {
		t.Fatal(reason, err)
	}
	if cache.store.Records()[0].HighSequence != nil {
		t.Fatal("absent sequence became zero")
	}
	// An authenticated higher-version empty bundle is a removal, not a failed
	// fetch that may keep old authorities usable until an age deadline.
	initialized := pairedCache{remote: ca.domain, store: corebundle.New()}
	if reason, err := initialized.apply(fetched); err != nil || reason != evidence.Updated {
		t.Fatal(reason, err)
	}
	empty, err := fetchAuthenticatedBundle(context.Background(), server.URL+"/empty", svid.ID, trust)
	if err != nil {
		t.Fatal("authenticated empty bundle discarded instead of removing trust", err)
	}
	if reason, err := initialized.apply(empty); err != nil || reason != evidence.Updated {
		t.Fatal(reason, err)
	}
	if len(initialized.store.Records()[0].Bundle.Issuers) != 0 {
		t.Fatal("old authorities retained after empty update")
	}
	own, _ := spiffeid.FromString("spiffe://alpha.local/service")
	result := initialized.check(svid.Certificates, own, svid.ID, time.Now())
	if result["cryptographically_validated"] != false {
		t.Fatal("old credential survived authenticated empty bundle")
	}
	if _, err := fetchAuthenticatedBundle(context.Background(), server.URL, svid.ID, initialized.trustForFetch(trust)); err == nil {
		t.Fatal("removed endpoint authority silently re-enabled through stale bootstrap roots")
	}
	wrong, _ := spiffeid.FromString("spiffe://beta.local/other")
	if _, err = fetchAuthenticatedBundle(context.Background(), server.URL, wrong, trust); err == nil {
		t.Fatal("wrong endpoint identity accepted")
	}
	if _, err = fetchAuthenticatedBundle(context.Background(), server.URL+"/bad", svid.ID, trust); err == nil {
		t.Fatal("duplicate bundle keys accepted")
	}
	if _, err = fetchAuthenticatedBundle(context.Background(), "http://127.0.0.1/", svid.ID, trust); err == nil {
		t.Fatal("plaintext endpoint accepted")
	}
}

func TestPairedRealChainsShareCacheAndPreserveCoreLabels(t *testing.T) {
	old, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	next, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	oldSVID, err := old.issue("spiffe://beta.local/workload", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	newSVID, err := next.issue("spiffe://beta.local/workload", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	own, _ := spiffeid.FromString("spiffe://alpha.local/service")
	cache := pairedCache{remote: old.domain, store: corebundle.New()}
	b := spiffebundle.FromX509Authorities(old.domain, []*x509.Certificate{old.cert})
	b.SetSequenceNumber(11)
	then := time.Now().Add(-5 * time.Second)
	if reason, err := cache.apply(authenticatedBundle{b, then, "old-body"}); err != nil || reason != evidence.Updated {
		t.Fatal(reason, err)
	}
	result := cache.check(oldSVID.Certificates, own, oldSVID.ID, time.Now())
	decisions := result["decisions"].(map[string]any)
	if decisions["B0.direct"].(map[string]any)["outcome"] != "ACCEPT" {
		t.Fatal("real chain rejected")
	}
	if decisions["B2/3"].(evidence.Decision).Outcome != evidence.Reject || decisions["B3/3"].(evidence.Decision).Outcome != evidence.Indeterminate {
		t.Fatal("freshness classification mismatch")
	}
	for _, arm := range []string{"B2/120", "B3/120"} {
		d := decisions[arm].(evidence.Decision)
		if d.Outcome != evidence.Accept || d.VerificationMode != "simulated" || d.PQAuthenticated {
			t.Fatal("metadata evaluator label or outcome changed", d)
		}
	}
	if result["private_key_possession_tested"] != false {
		t.Fatal("chain-only test claimed possession")
	}
	wrongPeer := cache.check(oldSVID.Certificates, own, own, time.Now())
	if wrongPeer["verification_result"] != "peer_policy_denied" {
		t.Fatal("wrong peer lost its rejection category", wrongPeer)
	}
	// Retain the profile checks of the existing real validator in this path too.
	invalidProfile := *oldSVID.Certificates[0]
	invalidProfile.KeyUsage = 0
	der, err := x509.CreateCertificate(rand.Reader, &invalidProfile, old.cert, invalidProfile.PublicKey, old.key)
	if err != nil {
		t.Fatal(err)
	}
	invalidCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cache.check([]*x509.Certificate{invalidCert}, own, oldSVID.ID, time.Now())["cryptographically_validated"] != false {
		t.Fatal("missing digitalSignature profile accepted")
	}
	newBundle := spiffebundle.FromX509Authorities(old.domain, []*x509.Certificate{next.cert})
	newBundle.SetSequenceNumber(12)
	if reason, err := cache.apply(authenticatedBundle{newBundle, time.Now(), "new-body"}); err != nil || reason != evidence.Updated {
		t.Fatal(reason, err)
	}
	previousTime := cache.fetched
	if reason, err := cache.apply(authenticatedBundle{b, time.Now(), "old-body"}); err != nil || reason != evidence.Rollback {
		t.Fatal(reason, err)
	}
	if !cache.fetched.Equal(previousTime) || cache.bodyHash != "new-body" {
		t.Fatal("rejected update refreshed cache")
	}
	b.ClearSequenceNumber()
	if reason, err := cache.apply(authenticatedBundle{b, time.Now(), "stripped-body"}); err != nil || reason != evidence.SequenceRequired {
		t.Fatal(reason, err)
	}
	if !cache.fetched.Equal(previousTime) {
		t.Fatal("stripped sequence refreshed cache")
	}
	oldResult := cache.check(oldSVID.Certificates, own, oldSVID.ID, time.Now())
	if oldResult["cryptographically_validated"] != false {
		t.Fatal("removed root accepted")
	}
	for _, decision := range oldResult["decisions"].(map[string]any) {
		if decision.(map[string]any)["outcome"] != "REJECT" {
			t.Fatal("crypto rejection bypassed")
		}
	}
	if cache.check(newSVID.Certificates, own, newSVID.ID, time.Now())["cryptographically_validated"] != true {
		t.Fatal("new issuer unavailable")
	}
}
