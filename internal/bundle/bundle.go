// Package bundle implements persistent (copy-on-write) per-domain snapshots.
package bundle

import (
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
	"slices"
)

type Snapshot struct {
	Domain        identity.Domain
	Sequence      *uint64
	Epoch         uint64
	Issuers       []string
	Authenticated bool
	FetchedAt     int64
}

func clone(b Snapshot) Snapshot {
	b.Issuers = slices.Clone(b.Issuers)
	if b.Sequence != nil {
		x := *b.Sequence
		b.Sequence = &x
	}
	return b
}
func (b Snapshot) Has(issuer string) bool { return slices.Contains(b.Issuers, issuer) }

type watermark struct {
	Sequence *uint64
	Epoch    uint64
}
type Store struct {
	snapshots  map[identity.Domain]Snapshot
	watermarks map[identity.Domain]watermark
}

func New() Store                                       { return Store{map[identity.Domain]Snapshot{}, map[identity.Domain]watermark{}} }
func (s Store) Get(d identity.Domain) (Snapshot, bool) { b, ok := s.snapshots[d]; return clone(b), ok }
func (s Store) copy() Store {
	n := New()
	for d, b := range s.snapshots {
		n.snapshots[d] = b
	}
	for d, w := range s.watermarks {
		n.watermarks[d] = w
	}
	return n
}
func sameContents(a, b Snapshot) bool {
	return a.Epoch == b.Epoch && slices.Equal(a.Issuers, b.Issuers)
}

// authenticatedFreshFetch must only be true for a fresh authenticated channel response.
// A replay with identical content is not a new freshness observation.
func (s Store) Update(expected identity.Domain, b Snapshot, at int64, authenticatedFreshFetch bool) (Store, evidence.Reason) {
	if !expected.Valid() || b.Domain != expected {
		return s, evidence.WrongDomain
	}
	if !b.Authenticated {
		return s, evidence.Unauthenticated
	}
	if at < 0 {
		return s, evidence.UnknownState
	}
	b = clone(b)
	slices.Sort(b.Issuers)
	b.Issuers = slices.Compact(b.Issuers)
	for _, issuer := range b.Issuers {
		if issuer == "" {
			return s, evidence.UnknownState
		}
	}
	w := s.watermarks[expected]
	if b.Epoch < w.Epoch {
		return s, evidence.Rollback
	}
	if w.Sequence != nil {
		if b.Sequence == nil {
			return s, evidence.SequenceRequired
		}
		if *b.Sequence < *w.Sequence {
			return s, evidence.Rollback
		}
		if *b.Sequence == *w.Sequence {
			old, ok := s.snapshots[expected]
			if !ok {
				return s, evidence.Replay
			} // tombstone: cannot resurrect a deleted relationship
			if !sameContents(old, b) {
				return s, evidence.SequenceConflict
			}
			if !authenticatedFreshFetch {
				return s, evidence.Replay
			}
		}
	}
	old, ok := s.snapshots[expected]
	if ok && at < old.FetchedAt {
		return s, evidence.UnknownState
	}
	if !authenticatedFreshFetch {
		return s, evidence.Replay
	}
	b.FetchedAt = at
	n := s.copy()
	n.snapshots[expected] = b
	n.watermarks[expected] = watermark{b.Sequence, b.Epoch}
	return n, evidence.Updated
}
func (s Store) Remove(d identity.Domain) Store { n := s.copy(); delete(n.snapshots, d); return n }
