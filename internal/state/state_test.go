package state

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
	"strings"
	"sync"
	"testing"
	"time"
)

func update(n uint64, at int64) func(bundle.Store) (bundle.Store, evidence.Reason) {
	d, _ := identity.ParseDomain("alpha.local")
	return func(s bundle.Store) (bundle.Store, evidence.Reason) {
		return s.Update(d, bundle.Snapshot{Domain: d, Sequence: &n, Epoch: 1, Issuers: []string{"key"}, Authenticated: true}, at, true)
	}
}
func TestRestartAndRemovalWatermark(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	c, r, e := Commit(context.Background(), p, 10, update(12, 10))
	if e != nil || r != evidence.Updated {
		t.Fatal(r, e)
	}
	_ = c
	// Load into a new store as a new verifier process would do.
	c, e = Load(p)
	if e != nil {
		t.Fatal(e)
	}
	d, _ := identity.ParseDomain("alpha.local")
	_, r = c.Store.Update(d, bundle.Snapshot{Domain: d, Sequence: new(uint64(11)), Epoch: 1, Issuers: []string{"key"}, Authenticated: true}, 11, true)
	if r != evidence.Rollback {
		t.Fatal("rollback survived restart", r)
	}
	_, r, e = Commit(context.Background(), p, 12, func(s bundle.Store) (bundle.Store, evidence.Reason) { return s.Remove(d), evidence.Updated })
	if e != nil {
		t.Fatal(e)
	}
	c, e = Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := c.Store.Get(d); ok {
		t.Fatal("tombstone lost")
	}
	_, r, e = Commit(context.Background(), p, 13, update(11, 13))
	if e != nil || r != evidence.Rollback {
		t.Fatal(r, e)
	}
}
func TestCorruptionMissingStateAndClock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if _, _, e := Commit(context.Background(), p, 10, update(12, 10)); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Commit(context.Background(), p, 9, update(13, 9)); e == nil {
		t.Fatal("clock rollback accepted")
	}
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, []byte("corrupt"), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = Commit(context.Background(), p, 11, update(13, 11)); e == nil {
		t.Fatal("corruption failed open")
	}
	if e = os.WriteFile(p, raw, 0o600); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if _, _, e = Commit(context.Background(), p, 11, update(13, 11)); e == nil {
		t.Fatal("missing initialized state reset trust")
	}
}
func TestConcurrentWritersDoNotLoseHigherVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if _, _, e := Commit(context.Background(), p, 0, update(1, 0)); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for n := uint64(2); n <= 30; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, e := Commit(ctx, p, 0, update(n, 0))
			if e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	d, _ := identity.ParseDomain("alpha.local")
	b, ok := c.Store.Get(d)
	if !ok || *b.Sequence != 30 {
		t.Fatal("lost concurrent high watermark", b.Sequence)
	}
}
func TestPermissionsAndInterruptedTemporaryWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if _, _, e := Commit(context.Background(), p, 1, update(12, 1)); e != nil {
		t.Fatal(e)
	}
	// A failed writer's unpublished temporary content does not replace committed state.
	if e := os.WriteFile(filepath.Join(dir, ".proofmesh-state-aborted"), []byte("partial"), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(p); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0o644); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(p); e == nil {
		t.Fatal("insecure state permissions accepted")
	}
}

func TestCommitRejectsUnloadableCheckpointWithoutReplacingState(t *testing.T) {
	for _, kind := range []string{"long-issuer", "many-issuers", "future-fetch"} {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "state.json")
			if _, _, err := Commit(context.Background(), p, 10, update(12, 10)); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			change := func(s bundle.Store) (bundle.Store, evidence.Reason) {
				d, _ := identity.ParseDomain("alpha.local")
				keys, fetchedAt := []string{"key"}, int64(11)
				switch kind {
				case "long-issuer":
					keys = []string{strings.Repeat("x", 1025)}
				case "many-issuers":
					keys = make([]string, 4097)
					for i := range keys {
						keys[i] = fmt.Sprintf("key-%d", i)
					}
				case "future-fetch":
					fetchedAt = 12
				}
				return s.Update(d, bundle.Snapshot{Domain: d, Sequence: new(uint64(13)), Epoch: 1, Issuers: keys, Authenticated: true}, fetchedAt, true)
			}
			_, reason, err := Commit(context.Background(), p, 11, change)
			if err == nil || reason != evidence.UnknownState {
				t.Fatalf("unloadable checkpoint committed: reason=%s error=%v", reason, err)
			}
			after, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid mutation replaced acknowledged state", err)
			}
			c, err := Load(p)
			if err != nil || c.Clock != 10 {
				t.Fatal("previous checkpoint no longer usable", err)
			}
			if _, reason, err = Commit(context.Background(), p, 11, update(13, 11)); err != nil || reason != evidence.Updated {
				t.Fatal("valid recovery update failed", reason, err)
			}
		})
	}
}

func TestExistingDanglingInitializedMarkerCannotResetState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.Symlink("missing-target", p+".initialized"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Commit(context.Background(), p, 1, update(1, 1)); err == nil {
		t.Fatal("existing dangling initialized marker treated as virgin state")
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("failed initialization wrote trust state", err)
	}
}
