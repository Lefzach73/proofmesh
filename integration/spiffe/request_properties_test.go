package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestRequestJournalCapacityAndMarkerAreFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "requests.json")
	j, err := openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms)
	if err != nil {
		t.Fatal(err)
	}
	p := j.payload
	for i := 1; i <= maxRequestEntries; i++ {
		p.Entries = append(p.Entries, requestEntry{"B3/120", requestTestPeer.String(), strconv.Itoa(i), uint64(i)})
	}
	j, err = checkedRequestJournal(path, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.save(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	next, reason, err := j.commit("B3/120", requestTestPeer, "beyond-limit")
	if err != nil || reason != "REQUEST_CAPACITY" || next.counters["B3/120"] != maxRequestEntries {
		t.Fatal(reason, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("capacity denial mutated durable state")
	}
	if err := os.Chmod(path+".initialized", 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.commit("B3/120", requestTestPeer, "1"); err == nil {
		t.Fatal("insecure marker accepted")
	}
	if _, err := openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms); err == nil {
		t.Fatal("insecure marker accepted on restart")
	}
}

func TestRequestProtocolRenewedCredentialCannotResetSeenIDs(t *testing.T) {
	alpha, err := newAuthority("alpha.local")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	newer, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := alpha.issue(requestTestOwn.String(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	old, err := beta.issue(requestTestPeer.String(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	current, err := newer.issue(requestTestPeer.String(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	g := persistedTestGate(t, filepath.Join(t.TempDir(), "private", "state.json"), server.ID, old.ID)
	testGateUpdate(t, g, 1, time.Now(), beta.cert)
	if err := g.enableRequestProtocol(requestTestArms); err != nil {
		t.Fatal(err)
	}
	if row := g.execute(old.Certificates, "B3/120"); row["reason"] != "PROTOCOL_MISMATCH" || row["handler_executed"] != false {
		t.Fatal("legacy bypass", row)
	}
	address, rows := testAppListener(t, g, server, "B3/120")
	session := &applicationSession{}
	defer session.close()
	if o := session.connect(context.Background(), address, source{old}, alpha.bundle(), server.ID); !o.Accepted {
		t.Fatal(o)
	}
	nextAppRow(t, rows)
	if r := session.requestJSON(string(requestJSON("retained-id", server.ID.String(), "increment"))); r["accepted"] != true {
		t.Fatal(r)
	}
	if row := nextAppRow(t, rows); row["handler_after"] != uint64(1) {
		t.Fatal(row)
	}
	testGateUpdate(t, g, 2, time.Now(), newer.cert)
	if r := session.requestJSON(string(requestJSON("revoked-attempt", server.ID.String(), "increment"))); r["accepted"] != false {
		t.Fatal("revoked existing connection executed", r)
	}
	if row := nextAppRow(t, rows); row["handler_after"] != uint64(1) || row["handler_executed"] != false {
		t.Fatal(row)
	}
	session.close()
	if o := session.connect(context.Background(), address, source{current}, alpha.bundle(), server.ID); !o.Accepted {
		t.Fatal(o)
	}
	if h := nextAppRow(t, rows)["tls"].(tlsObservation); !h.Accepted || h.PeerCertificateSHA256 != certificateHash(current.Certificates[0]) {
		t.Fatal(h)
	}
	if r := session.requestJSON(string(requestJSON("retained-id", server.ID.String(), "increment"))); r["accepted"] != false {
		t.Fatal("renewal reset request ID", r)
	}
	if row := nextAppRow(t, rows); row["reason"] != "REPLAY" || row["handler_after"] != uint64(1) {
		t.Fatal(row)
	}
	// A denied pre-revocation attempt did not consume its ID; with a newly valid
	// same-identity credential it can execute once. This is effect deduplication.
	if r := session.requestJSON(string(requestJSON("revoked-attempt", server.ID.String(), "increment"))); r["accepted"] != true {
		t.Fatal(r)
	}
	if row := nextAppRow(t, rows); row["handler_after"] != uint64(2) {
		t.Fatal(row)
	}
}

func TestRequestProtocolFreshnessDenialDoesNotConsumeID(t *testing.T) {
	beta, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	client, err := beta.issue(requestTestPeer.String(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	g := persistedTestGate(t, filepath.Join(t.TempDir(), "private", "state.json"), requestTestOwn, client.ID)
	if err := g.enableRequestProtocol(requestTestArms); err != nil {
		t.Fatal(err)
	}
	testGateUpdate(t, g, 1, time.Now().Add(-121*time.Second), beta.cert)
	for _, arm := range []string{"B2/120", "B3/120"} {
		row := g.executeRequest(client.Certificates, arm, requestJSON("retry-stale", requestTestOwn.String(), "increment"))
		want := "REJECT"
		if arm == "B3/120" {
			want = "INDETERMINATE"
		}
		if row["outcome"] != want || row["handler_executed"] != false || g.requests.seen[requestKey{arm, client.ID.String(), "retry-stale"}] {
			t.Fatal(row)
		}
	}
	testGateUpdate(t, g, 1, time.Now(), beta.cert)
	for _, arm := range []string{"B2/120", "B3/120"} {
		row := g.executeRequest(client.Certificates, arm, requestJSON("retry-stale", requestTestOwn.String(), "increment"))
		if row["outcome"] != "ACCEPT" || row["handler_after"] != uint64(1) {
			t.Fatal(row)
		}
	}
}

func FuzzApplicationRequest(f *testing.F) {
	f.Add(string(requestJSON("one", requestTestOwn.String(), "increment")))
	f.Add(`{"version":1,"version":1}`)
	f.Add("null")
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := decodeApplicationRequest([]byte(raw))
		if err != nil {
			return
		}
		if r.Version != 1 || !validRequestID(r.RequestID) || len(r.Audience) > 512 || r.Audience == "" || r.Action == "" {
			t.Fatal("accepted invalid request")
		}
		again, err := decodeApplicationRequest(requestJSON(r.RequestID, r.Audience, r.Action))
		if err != nil || r != again {
			t.Fatal("unstable accepted request", err)
		}
	})
}
