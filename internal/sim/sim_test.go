package sim

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"proofmesh.local/research/internal/evidence"
	"reflect"
	"strings"
	"testing"
)

func TestFrozenScenarios(t *testing.T) {
	files, _ := filepath.Glob("../../scenarios/*/*.json")
	if len(files) != 81 {
		t.Fatalf("need 81 fixtures, got %d", len(files))
	}
	for _, p := range files {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			s, err := Decode(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(s)
			a, err := Run(s, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Run(s, false, nil)
			if err != nil || !reflect.DeepEqual(a, b) {
				t.Fatal("nondeterminism")
			}
			after, _ := json.Marshal(s)
			if !bytes.Equal(before, after) {
				t.Fatal("scenario mutated")
			}
			accepts := 0
			for _, l := range a {
				if l.Decision == nil {
					continue
				}
				w := s.Events[l.EventIndex].Expected
				if w != nil && (l.Decision.Outcome != w.Outcome || l.Decision.Reason != w.Reason) {
					t.Fatalf("event %d expected %+v got %+v", l.EventIndex, w, l.Decision)
				}
				if l.Decision.PQAuthenticated {
					t.Fatal("synthetic PQ claim")
				}
				if l.Decision.Outcome == evidence.Accept {
					accepts++
				}
			}
			_ = accepts
		})
	}
}
func TestRejectInput(t *testing.T) {
	if _, err := Decode(strings.NewReader(strings.Repeat("[", 100) + strings.Repeat("]", 100))); err == nil {
		t.Fatal("unbounded JSON nesting accepted")
	}
	for _, raw := range []string{`{"schema_version":"a","schema_version":"b"}`, `{"critical_unrecognized":true}`, `{} {}`, `{"events":[{"type":"EXEC_SHELL"}]}`} {
		if _, err := Decode(strings.NewReader(raw)); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}
func FuzzDecoder(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"x":1,"x":2}`)
	f.Fuzz(func(t *testing.T, raw string) {
		s, err := Decode(strings.NewReader(raw))
		if err == nil {
			if _, err = Run(s, false, nil); err != nil {
				t.Log(err)
			}
		}
	})
}

// No omniscient revocation oracle is present in the evaluator's input contract.
func TestHiddenRemoteMutationDoesNotEnterPolicyInput(t *testing.T) {
	raw, err := os.ReadFile("../../scenarios/dev/F01_s17.json")
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	healthy.Events[0].At = 10
	healthy.Events[0].RequestID = "same-request"
	partitioned := healthy
	partitioned.Events = append([]Event{{At: 2, Type: "REVOKE_ISSUER", Domain: "alpha.local", Issuer: "a1"}}, healthy.Events...)
	authorized := true
	unauthorized := false
	healthy.Events[0].OracleAuthorized = &authorized
	partitioned.Events[1].OracleAuthorized = &unauthorized
	a, err := Run(healthy, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(partitioned, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a[0].Decision, b[1].Decision) || a[0].Decision.Outcome != evidence.Accept {
		t.Fatal("hidden world state was incorrectly supplied to verifier")
	}
}
