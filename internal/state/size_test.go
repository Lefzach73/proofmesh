package state

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
)

// Exercise the actual serialized file boundary, not just record/string counts.
// Save must never acknowledge bytes that the next process cannot load.
func TestCheckpointSerializedSizeBoundary(t *testing.T) {
	for _, offset := range []int{-1, 0} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if _, reason, err := Commit(context.Background(), path, 10, update(1, 10)); err != nil || reason != evidence.Updated {
				t.Fatal(reason, err)
			}
			original, _ := os.ReadFile(path)
			keys := make([]string, 4096)
			for i := range keys {
				keys[i] = fmt.Sprintf("%04d:", i) + strings.Repeat("x", 1019)
			}
			domain, _ := identity.ParseDomain("alpha.local")
			sequence := uint64(2)
			candidate := func() bundle.Store {
				store, reason := bundle.New().Update(domain, bundle.Snapshot{Domain: domain, Sequence: &sequence, Epoch: 1, Issuers: keys, Authenticated: true}, 11, true)
				if reason != evidence.Updated {
					t.Fatal(reason)
				}
				return store
			}
			size := func(store bundle.Store) int {
				p := payload{Schema: schema, Clock: 11, Records: store.Records()}
				checksum, err := digest(p)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(envelope{Payload: p, Checksum: checksum})
				if err != nil {
					t.Fatal(err)
				}
				return len(raw)
			}
			target := 4*1024*1024 + offset
			excess := size(candidate()) - target
			for i := len(keys) - 1; i >= 0 && excess > 0; i-- {
				remove := min(excess, len(keys[i])-5)
				keys[i] = keys[i][:len(keys[i])-remove]
				excess -= remove
			}
			store := candidate()
			if excess != 0 || size(store) != target {
				t.Fatal("boundary fixture did not reach exact size")
			}
			_, reason, err := Commit(context.Background(), path, 11, func(bundle.Store) (bundle.Store, evidence.Reason) { return store, evidence.Updated })
			if offset == -1 {
				if err != nil || reason != evidence.Updated {
					t.Fatal("maximum loadable checkpoint rejected", reason, err)
				}
				if _, err := Load(path); err != nil {
					t.Fatal("acknowledged boundary checkpoint cannot load", err)
				}
				info, _ := os.Stat(path)
				if info.Size() != 4*1024*1024 {
					t.Fatal("wrong serialized file size", info.Size())
				}
			} else {
				if err == nil {
					_, loadErr := Load(path)
					t.Fatalf("oversized checkpoint acknowledged: reason=%s subsequent load=%v", reason, loadErr)
				}
				after, _ := os.ReadFile(path)
				if !bytes.Equal(original, after) {
					t.Fatal("failed save altered prior checkpoint")
				}
				if _, err := Load(path); err != nil {
					t.Fatal("prior checkpoint no longer loads", err)
				}
				if _, reason, err := Commit(context.Background(), path, 12, update(3, 12)); err != nil || reason != evidence.Updated {
					t.Fatal("valid recovery failed", reason, err)
				}
			}
		})
	}
}

func TestCheckpointRejectsInvalidUTF8Identifiers(t *testing.T) {
	for _, keys := range [][]string{{"\xff"}, {"\xfe", "\xff"}} {
		path := filepath.Join(t.TempDir(), "state.json")
		if _, reason, err := Commit(context.Background(), path, 10, update(1, 10)); err != nil || reason != evidence.Updated {
			t.Fatal(reason, err)
		}
		before, _ := os.ReadFile(path)
		domain, _ := identity.ParseDomain("alpha.local")
		sequence := uint64(2)
		_, _, err := Commit(context.Background(), path, 11, func(s bundle.Store) (bundle.Store, evidence.Reason) {
			return s.Update(domain, bundle.Snapshot{Domain: domain, Sequence: &sequence, Epoch: 1, Issuers: keys, Authenticated: true}, 11, true)
		})
		if err == nil {
			t.Error("acknowledged issuer identifiers that JSON replaces or collapses")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Error("invalid identifier altered prior checkpoint")
		}
		if _, err := Load(path); err != nil {
			t.Error("prior checkpoint no longer loadable", err)
		}
	}
}
