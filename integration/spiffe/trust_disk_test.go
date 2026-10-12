package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"proofmesh.local/research/internal/evidence"
	corestate "proofmesh.local/research/internal/state"
)

func persistedTestGate(t *testing.T, path string, own spiffeid.ID, peer spiffeid.ID) *applicationGate {
	t.Helper()
	g := newApplicationGate(own, []spiffeid.ID{peer}, peer.TrustDomain())
	if err := g.enablePersistence(context.Background(), path, time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.close)
	return g
}

func TestDurableGateRealHTTPSAndMTLSRestart(t *testing.T) {
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
	endpoint, err := old.issue("spiffe://beta.local/spire/server", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var body atomic.Value
	setBody := func(sequence uint64, cert *x509.Certificate) {
		b := spiffebundle.FromX509Authorities(old.domain, []*x509.Certificate{cert})
		b.SetSequenceNumber(sequence)
		raw, e := b.Marshal()
		if e != nil {
			t.Fatal(e)
		}
		body.Store(raw)
	}
	setBody(12, old.cert)
	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body.Load().([]byte)) }))
	web.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{endpoint.Certificates[0].Raw}, PrivateKey: endpoint.PrivateKey}}}
	web.StartTLS()
	defer web.Close()
	path := filepath.Join(t.TempDir(), "live", "state.json")
	g := persistedTestGate(t, path, server.ID, client.ID)
	if row := g.refresh(context.Background(), web.URL, endpoint.ID, old.bundle()); row["success"] != true {
		t.Fatal(row)
	}
	fetched := g.cache.fetched.Unix()
	// A real authenticated lower sequence must leave both file and observation
	// timestamp unchanged, including with persistence enabled.
	before, _ := os.ReadFile(path)
	setBody(11, old.cert)
	if row := g.refresh(context.Background(), web.URL, endpoint.ID, old.bundle()); row["success"] != false || row["update_reason"] != evidence.Rollback {
		t.Fatal(row)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("rejected rollback wrote state")
	}
	g.close()
	g = persistedTestGate(t, path, server.ID, client.ID)
	if g.cache.fetched.Unix() != fetched || g.cache.bodyHash != "" {
		t.Fatal("restart refreshed age or invented HTTP provenance")
	}
	setBody(13, next.cert)
	if row := g.refresh(context.Background(), web.URL, endpoint.ID, old.bundle()); row["success"] != true {
		t.Fatal(row)
	}
	g.close()
	g = persistedTestGate(t, path, server.ID, client.ID)
	defer g.close()
	if row := g.refresh(context.Background(), web.URL, endpoint.ID, old.bundle()); row["success"] != false {
		t.Fatal("restart fell back to removed endpoint authority", row)
	}
	address, rows := testAppListener(t, g, server, "B3/120")
	session := &applicationSession{}
	defer session.close()
	if o := session.connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); o.Accepted {
		t.Fatal("old issuer accepted after restart")
	}
	if h := nextAppRow(t, rows)["tls"].(tlsObservation); h.PeerVerification != "unknown_authority" {
		t.Fatal(h)
	}
	if o := session.connect(context.Background(), address, source{newClient}, alpha.bundle(), server.ID); !o.Accepted {
		t.Fatal(o)
	}
	nextAppRow(t, rows)
	if response := session.request(); response["accepted"] != true {
		t.Fatal(response)
	}
	row := nextAppRow(t, rows)
	checkpoint, err := corestate.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Clock < row["chain_and_metadata"].(map[string]any)["checked_at"].(int64) {
		t.Fatal("effect preceded durable request clock")
	}
	// Corruption after a successful handshake must stop that existing session's
	// next effect. Repairing the file does not clear the process's failure latch.
	saved, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if response := session.request(); response["accepted"] != false {
			t.Fatal(response)
		}
		row = nextAppRow(t, rows)
		if row["handler_after"] != uint64(1) || row["handler_executed"] != false || row["error"] == nil {
			t.Fatal(row)
		}
		if err := os.WriteFile(path, saved, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDurableTrustRemovalAndDamagedStateFailClosed(t *testing.T) {
	ca, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	own, _ := spiffeid.FromString("spiffe://alpha.local/service")
	peer, _ := spiffeid.FromString("spiffe://beta.local/client")
	for _, cold := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "live", "state.json")
		g := persistedTestGate(t, path, own, peer)
		if !cold {
			testGateUpdate(t, g, 12, time.Now().Add(-5*time.Second), ca.cert)
			if err := g.persist(context.Background(), g.cache, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if row := g.removeTrust(context.Background()); row["success"] != true {
			t.Fatal(row)
		}
		g.close()
		g = persistedTestGate(t, path, own, peer)
		records := g.cache.store.Records()
		if len(records) != 1 || records[0].Bundle != nil || (!cold && (records[0].HighSequence == nil || *records[0].HighSequence != 12)) || (cold && records[0].HighSequence != nil) {
			t.Fatal(records)
		}
		trust, err := g.cache.trustForFetch(ca.bundle()).GetX509BundleForTrustDomain(ca.domain)
		if err != nil || len(trust.X509Authorities()) != 0 {
			t.Fatal("tombstone restored bootstrap trust", err)
		}
		g.close()
	}
	for _, damage := range []string{"missing-checkpoint", "missing-blob", "corrupt-blob", "wrong-domain", "clock-rollback"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "live", "state.json")
			g := persistedTestGate(t, path, own, peer)
			testGateUpdate(t, g, 12, time.Now(), ca.cert)
			if err := g.persist(context.Background(), g.cache, time.Now()); err != nil {
				t.Fatal(err)
			}
			blob, _ := g.disk.certificatePath(certificateHash(ca.cert))
			at := time.Now()
			remote := peer.TrustDomain()
			switch damage {
			case "missing-checkpoint":
				err = os.Remove(path)
			case "missing-blob":
				err = os.Remove(blob)
			case "corrupt-blob":
				err = os.WriteFile(blob, []byte("corrupt"), 0600)
			case "wrong-domain":
				remote, _ = spiffeid.TrustDomainFromString("other.local")
			case "clock-rollback":
				at = time.Unix(g.disk.clock-1, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			g.close()
			d, _, err := openTrustDisk(context.Background(), path, remote, at.Unix())
			if err == nil {
				d.unlock()
				t.Fatal("damaged/inconsistent trust silently restored")
			}
		})
	}
}

func TestDurableCheckpointContainsOnlyPublicCertificates(t *testing.T) {
	ca, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	own, _ := spiffeid.FromString("spiffe://alpha.local/service")
	peer, _ := spiffeid.FromString("spiffe://beta.local/client")
	path := filepath.Join(t.TempDir(), "live", "state.json")
	g := persistedTestGate(t, path, own, peer)
	defer g.close()
	testGateUpdate(t, g, 12, time.Now(), ca.cert)
	if err := g.persist(context.Background(), g.cache, time.Now()); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(path + ".certificates")
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	raw, err := os.ReadFile(filepath.Join(path+".certificates", files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil || certificateHash(cert) != certificateHash(ca.cert) {
		t.Fatal("blob is not the actual public authority", err)
	}
	raw, _ = os.ReadFile(path)
	var checkpoint map[string]any
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if len(checkpoint) != 2 || checkpoint["payload_sha256"] == nil || checkpoint["payload"] == nil {
		t.Fatal("unexpected checkpoint schema")
	}
}
