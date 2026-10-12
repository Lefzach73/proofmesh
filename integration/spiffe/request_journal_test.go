package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var requestTestArms = []string{"B0.direct", "B2/120", "B3/120"}
var requestTestOwn = spiffeid.RequireFromString("spiffe://alpha.local/service")
var requestTestPeer = spiffeid.RequireFromString("spiffe://beta.local/client")

func requestJSON(id, audience, action string) []byte {
	raw, _ := json.Marshal(applicationRequest{1, id, audience, action})
	return raw
}

func TestRequestJournalRoundtripIdentityAndMissingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "requests.json")
	j, err := openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms)
	if err != nil {
		t.Fatal(err)
	}
	next, reason, err := j.commit("B3/120", requestTestPeer, "same-id")
	if err != nil || reason != "AUTHORIZED" || next.counters["B3/120"] != 1 {
		t.Fatal(reason, err, next)
	}
	j, err = openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms)
	if err != nil {
		t.Fatal(err)
	}
	if _, reason, err = j.commit("B3/120", requestTestPeer, "same-id"); err != nil || reason != "REPLAY" {
		t.Fatal(reason, err)
	}
	other := spiffeid.RequireFromString("spiffe://beta.local/another-client")
	next, reason, err = j.commit("B3/120", other, "same-id")
	if err != nil || reason != "AUTHORIZED" || next.counters["B3/120"] != 2 {
		t.Fatal(reason, err)
	}
	if _, err := openRequestJournal(path, spiffeid.RequireFromString("spiffe://alpha.local/different"), requestTestPeer.TrustDomain(), requestTestArms); err == nil {
		t.Fatal("changed audience accepted persisted state")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms); err == nil {
		t.Fatal("missing acknowledged state silently reset")
	}
}

func TestRequestJournalBoundsAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "requests.json")
	j, err := openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "bad/id", strings.Repeat("x", 65), "invalid\xff"} {
		if _, _, err := j.commit("B3/120", requestTestPeer, id); err == nil {
			t.Fatal("invalid request ID", id)
		}
	}
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(raw, byte(' ')), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.commit("B3/120", requestTestPeer, "new"); err == nil {
		t.Fatal("external journal mutation ignored")
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms); err == nil {
		t.Fatal("corrupt state reset")
	}
}

func TestRequestDecoderCriticalFields(t *testing.T) {
	valid := string(requestJSON("id-1", requestTestOwn.String(), "increment"))
	if _, err := decodeApplicationRequest([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"null", valid + " {}", strings.Replace(valid, `"version":1`, `"VERSION":1`, 1), strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1), strings.Replace(valid, `"version":1`, `"version":1,"peer":"spiffe://beta.local/spoof"`, 1), strings.Replace(valid, `"request_id":"id-1"`, `"request_id":""`, 1)} {
		if _, err := decodeApplicationRequest([]byte(raw)); err == nil {
			t.Fatal("malformed/ambiguous request accepted", raw)
		}
	}
}

func TestRequestProtocolConcurrentRealTLSAndUnknownCommit(t *testing.T) {
	alpha, err := newAuthority("alpha.local")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	server, err := alpha.issue(requestTestOwn.String(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	client, err := beta.issue(requestTestPeer.String(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	g := persistedTestGate(t, filepath.Join(t.TempDir(), "private", "state.json"), server.ID, client.ID)
	testGateUpdate(t, g, 1, time.Now(), beta.cert)
	if err := g.enableRequestProtocol(requestTestArms); err != nil {
		t.Fatal(err)
	}
	sessions := []*applicationSession{{}, {}}
	channels := make([]<-chan any, 2)
	for i := range sessions {
		address, rows := testAppListener(t, g, server, "B3/120")
		channels[i] = rows
		if o := sessions[i].connect(context.Background(), address, source{client}, alpha.bundle(), server.ID); !o.Accepted {
			t.Fatal(o)
		}
		if h := nextAppRow(t, rows)["tls"].(tlsObservation); !h.Accepted || h.TLSVersion != tls.VersionTLS13 {
			t.Fatal(h)
		}
		defer sessions[i].close()
	}
	var wg sync.WaitGroup
	responses := make([]map[string]any, 2)
	for i := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			responses[i] = sessions[i].requestJSON(string(requestJSON("duplicate", server.ID.String(), "increment")))
		}()
	}
	wg.Wait()
	accepted, replays := 0, 0
	for i := range sessions {
		row := nextAppRow(t, channels[i])
		if responses[i]["transport_success"] != true {
			t.Fatal(responses[i])
		}
		if row["handler_executed"] == true {
			accepted++
		}
		if row["reason"] == "REPLAY" {
			replays++
		}
		if row["handler_after"] != uint64(1) || row["authenticated_peer"] != client.ID.String() {
			t.Fatal(row)
		}
	}
	if accepted != 1 || replays != 1 {
		t.Fatal("duplicate effects", accepted, replays)
	}
	// Incorrect authorization does not consume an ID or change the counter.
	bad := sessions[0].requestJSON(string(requestJSON("retry", "spiffe://alpha.local/wrong", "increment")))
	row := nextAppRow(t, channels[0])
	if bad["accepted"] != false || row["reason"] != "POLICY_DENIED" || row["handler_after"] != uint64(1) {
		t.Fatal(bad, row)
	}
	good := sessions[0].requestJSON(string(requestJSON("retry", server.ID.String(), "increment")))
	row = nextAppRow(t, channels[0])
	if good["accepted"] != true || row["handler_after"] != uint64(2) {
		t.Fatal(good, row)
	}
	// An error AFTER rename is not a known zero-effect reject. The wire marks it
	// unknown and the process latches; the complete counter+ID survives reload.
	g.mu.Lock()
	g.requests.fault = func(phase string) error {
		if phase == "after-rename" {
			return errors.New("test injected directory-sync interruption")
		}
		return nil
	}
	g.mu.Unlock()
	response := sessions[0].requestJSON(string(requestJSON("uncertain", server.ID.String(), "increment")))
	row = nextAppRow(t, channels[0])
	if response["commit_unknown"] != true || row["outcome"] != "INDETERMINATE" || row["handler_executed"] != nil || row["handler_after"] != nil {
		t.Fatal(response, row)
	}
	persisted, err := loadRequestJournal(g.disk.path + ".requests")
	if err != nil || persisted.counters["B3/120"] != 3 || !persisted.seen[requestKey{"B3/120", client.ID.String(), "uncertain"}] {
		t.Fatal("atomic effect/ID missing", err)
	}
	response = sessions[0].requestJSON(string(requestJSON("next", server.ID.String(), "increment")))
	row = nextAppRow(t, channels[0])
	if response["accepted"] != false || row["handler_executed"] != false || row["error"] == nil {
		t.Fatal("state failure not latched", response, row)
	}
	if row["handler_before"] != nil || row["handler_after"] != nil || row["counter_unknown"] != true || row["last_acknowledged_counter"] != uint64(2) {
		t.Fatalf("latched unknown commit reports stale counter evidence: before=%v after=%v unknown=%v last_acknowledged=%v persisted=%d", row["handler_before"], row["handler_after"], row["counter_unknown"], row["last_acknowledged_counter"], persisted.counters["B3/120"])
	}
}

func TestRequestProtocolKnownStateErrorKeepsCounterEvidence(t *testing.T) {
	beta, err := newAuthority("beta.local")
	if err != nil {
		t.Fatal(err)
	}
	client, err := beta.issue(requestTestPeer.String(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	g := persistedTestGate(t, filepath.Join(t.TempDir(), "private", "state.json"), requestTestOwn, client.ID)
	testGateUpdate(t, g, 1, time.Now(), beta.cert)
	if err := g.enableRequestProtocol(requestTestArms); err != nil {
		t.Fatal(err)
	}
	if row := g.executeRequest(client.Certificates, "B3/120", requestJSON("first", requestTestOwn.String(), "increment")); row["handler_after"] != uint64(1) {
		t.Fatal(row)
	}
	// A known error before any new commit cannot have incremented the counter.
	if err := os.WriteFile(g.disk.path+".requests", []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"failure", "latched"} {
		row := g.executeRequest(client.Certificates, "B3/120", requestJSON(id, requestTestOwn.String(), "increment"))
		if row["outcome"] != "REJECT" || row["reason"] != "STATE_ERROR" || row["handler_executed"] != false || row["handler_before"] != uint64(1) || row["handler_after"] != uint64(1) || row["counter_unknown"] != nil {
			t.Fatal("known state error changed counter evidence", row)
		}
	}
}

func TestRequestJournalActualCrashBoundaries(t *testing.T) {
	if phase := os.Getenv("PROOFMESH_REQUEST_CRASH_PHASE"); phase != "" {
		j, err := openRequestJournal(os.Getenv("PROOFMESH_REQUEST_CRASH_PATH"), requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms)
		if err != nil {
			t.Fatal(err)
		}
		j.fault = func(at string) error {
			if at == phase {
				p, _ := os.FindProcess(os.Getpid())
				_ = p.Kill()
				select {}
			}
			return nil
		}
		_, _, _ = j.commit("B3/120", requestTestPeer, "crash-id")
		t.Fatal("child did not terminate")
	}
	for _, phase := range []string{"before-rename", "after-rename"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private", "requests.json")
			if _, err := openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRequestJournalActualCrashBoundaries$")
			c.Env = append(os.Environ(), "PROOFMESH_REQUEST_CRASH_PHASE="+phase, "PROOFMESH_REQUEST_CRASH_PATH="+path)
			out, err := c.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || ctx.Err() != nil || exit.ExitCode() != -1 {
				t.Fatalf("not actual self-kill: %v %s", err, out)
			}
			j, err := openRequestJournal(path, requestTestOwn, requestTestPeer.TrustDomain(), requestTestArms)
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(0)
			if phase == "after-rename" {
				want = 1
			}
			if j.counters["B3/120"] != want {
				t.Fatal("partial effect state", j.counters)
			}
			next, reason, err := j.commit("B3/120", requestTestPeer, "crash-id")
			if err != nil {
				t.Fatal(err)
			}
			expected := "AUTHORIZED"
			if want == 1 {
				expected = "REPLAY"
			}
			if reason != expected || next.counters["B3/120"] != 1 {
				t.Fatal("restart duplicate effect", reason, next.counters)
			}
		})
	}
}
