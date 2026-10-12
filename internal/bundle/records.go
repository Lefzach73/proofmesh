package bundle

import (
	"fmt"
	"slices"
	"sort"

	"proofmesh.local/research/internal/identity"
)

// Record includes tombstones: removing a cached bundle must not erase its watermark.
type Record struct {
	Domain       string        `json:"domain"`
	HighSequence *uint64       `json:"high_sequence"`
	HighEpoch    uint64        `json:"high_epoch"`
	Bundle       *StoredBundle `json:"bundle"`
}
type StoredBundle struct {
	Sequence      *uint64  `json:"sequence"`
	Epoch         uint64   `json:"epoch"`
	Issuers       []string `json:"issuers"`
	FetchedAt     int64    `json:"fetched_at"`
	Authenticated bool     `json:"authenticated"`
}

func pointer(p *uint64) *uint64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func (s Store) Records() []Record {
	rows := []Record{}
	for d, w := range s.watermarks {
		r := Record{Domain: d.String(), HighSequence: pointer(w.Sequence), HighEpoch: w.Epoch}
		if b, ok := s.Get(d); ok {
			r.Bundle = &StoredBundle{Sequence: pointer(b.Sequence), Epoch: b.Epoch, Issuers: slices.Clone(b.Issuers), FetchedAt: b.FetchedAt, Authenticated: b.Authenticated}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Domain < rows[j].Domain })
	return rows
}
func Restore(rows []Record) (Store, error) {
	s := New()
	if len(rows) > 1024 {
		return s, fmt.Errorf("too many persisted domains")
	}
	for _, r := range rows {
		d, e := identity.ParseDomain(r.Domain)
		if e != nil {
			return New(), e
		}
		if _, ok := s.watermarks[d]; ok {
			return New(), fmt.Errorf("duplicate persisted domain")
		}
		if r.Bundle != nil {
			b := r.Bundle
			if !b.Authenticated || b.FetchedAt < 0 || b.Epoch != r.HighEpoch || len(b.Issuers) > 4096 {
				return New(), fmt.Errorf("invalid persisted snapshot")
			}
			if (b.Sequence == nil) != (r.HighSequence == nil) || (b.Sequence != nil && *b.Sequence != *r.HighSequence) {
				return New(), fmt.Errorf("snapshot/watermark inconsistency")
			}
			keys := slices.Clone(b.Issuers)
			for _, v := range keys {
				if v == "" || len(v) > 1024 {
					return New(), fmt.Errorf("invalid persisted issuer")
				}
			}
			slices.Sort(keys)
			if len(slices.Compact(slices.Clone(keys))) != len(keys) {
				return New(), fmt.Errorf("duplicate persisted issuer")
			}
			s.snapshots[d] = Snapshot{Domain: d, Sequence: pointer(b.Sequence), Epoch: b.Epoch, Issuers: keys, FetchedAt: b.FetchedAt, Authenticated: true}
		}
		s.watermarks[d] = watermark{Sequence: pointer(r.HighSequence), Epoch: r.HighEpoch}
	}
	return s, nil
}
