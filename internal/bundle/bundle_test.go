package bundle

import (
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
	"testing"
)

func ptr(n uint64) *uint64 { return &n }
func TestStoreWatermarkIsolationAndImmutability(t *testing.T) {
	a, _ := identity.ParseDomain("a")
	b, _ := identity.ParseDomain("b")
	original := Snapshot{Domain: a, Sequence: ptr(12), Epoch: 1, Issuers: []string{"k"}, Authenticated: true}
	empty := New()
	s, r := empty.Update(a, original, 0, true)
	if r != evidence.Updated {
		t.Fatal(r)
	}
	original.Issuers[0] = "evil"
	*original.Sequence = 0
	if _, ok := empty.Get(a); ok {
		t.Fatal("mutated old store")
	}
	v, _ := s.Get(a)
	if v.Issuers[0] != "k" || *v.Sequence != 12 {
		t.Fatal("aliased input")
	}
	v.Issuers[0] = "evil"
	*v.Sequence = 0
	v, _ = s.Get(a)
	if v.Issuers[0] != "k" || *v.Sequence != 12 {
		t.Fatal("aliased output")
	}
	for _, tc := range []struct {
		snap   Snapshot
		domain identity.Domain
		fresh  bool
		want   evidence.Reason
	}{
		{Snapshot{Domain: a, Sequence: ptr(11), Epoch: 1, Issuers: []string{"k"}, Authenticated: true}, a, true, evidence.Rollback},
		{Snapshot{Domain: a, Epoch: 1, Issuers: []string{"k"}, Authenticated: true}, a, true, evidence.SequenceRequired},
		{Snapshot{Domain: a, Sequence: ptr(12), Epoch: 1, Issuers: []string{"other"}, Authenticated: true}, a, true, evidence.SequenceConflict},
		{Snapshot{Domain: b, Sequence: ptr(13), Epoch: 1, Issuers: []string{"k"}, Authenticated: true}, a, true, evidence.WrongDomain},
		{Snapshot{Domain: a, Sequence: ptr(13), Epoch: 1, Issuers: []string{"k"}, Authenticated: false}, a, true, evidence.Unauthenticated},
		{Snapshot{Domain: a, Sequence: ptr(12), Epoch: 1, Issuers: []string{"k"}, Authenticated: true}, a, false, evidence.Replay},
	} {
		n, r := s.Update(tc.domain, tc.snap, 10, tc.fresh)
		if r != tc.want {
			t.Fatalf("want %s got %s", tc.want, r)
		}
		v, _ = n.Get(a)
		if v.FetchedAt != 0 || v.Issuers[0] != "k" {
			t.Fatal("failed update poisoned state")
		}
	}
	n, r := s.Remove(a).Update(a, Snapshot{Domain: a, Sequence: ptr(11), Epoch: 1, Issuers: []string{"k"}, Authenticated: true}, 10, true)
	if r != evidence.Rollback {
		t.Fatal(r)
	}
	if _, ok := n.Get(a); ok {
		t.Fatal("resurrected tombstone")
	}
}
func TestUnversionedAndIdenticalRefresh(t *testing.T) {
	a, _ := identity.ParseDomain("a")
	s, r := New().Update(a, Snapshot{Domain: a, Issuers: []string{}, Authenticated: true}, 0, true)
	if r != evidence.Updated {
		t.Fatal(r)
	}
	b, _ := s.Get(a)
	if b.Sequence != nil {
		t.Fatal("invented version")
	}
	s, r = s.Update(a, Snapshot{Domain: a, Sequence: ptr(0), Authenticated: true}, 1, true)
	if r != evidence.Updated {
		t.Fatal(r)
	}
	b, _ = s.Get(a)
	s, r = s.Update(a, b, 2, true)
	v, _ := s.Get(a)
	if r != evidence.Updated || v.FetchedAt != 2 {
		t.Fatal(r)
	}
}
