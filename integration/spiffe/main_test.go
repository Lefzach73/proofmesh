package main

import (
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"testing"
	"time"
)

func TestRealLab(t *testing.T) {
	records, e := lab()
	if e != nil {
		t.Fatal(e)
	}
	if len(records) != 7 {
		t.Fatal("missing lab cases")
	}
}
func TestRotationRealChains(t *testing.T) {
	old, e := newAuthority("alpha.local")
	if e != nil {
		t.Fatal(e)
	}
	next, e := newAuthority("alpha.local")
	if e != nil {
		t.Fatal(e)
	}
	first, e := old.issue("spiffe://alpha.local/a", time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	second, e := next.issue("spiffe://alpha.local/a", time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	overlap := old.bundle()
	overlap.AddX509Authority(next.cert)
	both := x509bundle.NewSet(overlap)
	if validate(first, both, first.ID, time.Now()) != nil || validate(second, both, second.ID, time.Now()) != nil {
		t.Fatal("overlap failed")
	}
	onlyNew := x509bundle.NewSet(next.bundle())
	if validate(first, onlyNew, first.ID, time.Now()) == nil || validate(second, onlyNew, second.ID, time.Now()) != nil {
		t.Fatal("rotation failed")
	}
}
func TestLocalSocketOnly(t *testing.T) {
	if workload("tcp://example.com:8081") == nil {
		t.Fatal("external endpoint accepted")
	}
}
