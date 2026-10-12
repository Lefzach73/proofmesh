// Package state is an opt-in local persistence adapter, outside the pure simulator.
// The checksum detects corruption, not malicious replacement/rollback by a disk owner.
package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/jsoncheck"
)

const schema = "proofmesh-security-state-1"
const maxCheckpointBytes = 4 * 1024 * 1024

type Checkpoint struct {
	Store bundle.Store
	Clock int64
}
type payload struct {
	Schema  string          `json:"schema"`
	Clock   int64           `json:"clock_high_water"`
	Records []bundle.Record `json:"records"`
}
type envelope struct {
	Payload  payload `json:"payload"`
	Checksum string  `json:"payload_sha256"`
}

func digest(p payload) (string, error) {
	raw, e := json.Marshal(p)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), e
}
func strictDecode(raw []byte, v any) error {
	if err := jsoncheck.Check(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing state data")
	}
	return nil
}
func Load(path string) (Checkpoint, error) {
	empty := Checkpoint{Store: bundle.New()}
	info, e := os.Lstat(path)
	if e != nil {
		return empty, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return empty, fmt.Errorf("state must be a regular owner-only file")
	}
	if info.Size() > maxCheckpointBytes {
		return empty, fmt.Errorf("state exceeds size bound")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return empty, e
	}
	var v envelope
	if e = strictDecode(raw, &v); e != nil {
		return empty, e
	}
	h, e := digest(v.Payload)
	if e != nil {
		return empty, e
	}
	if h != v.Checksum {
		return empty, fmt.Errorf("invalid state checksum")
	}
	return restorePayload(v.Payload)
}

// Read and write paths share validation. A successful commit must never publish
// a checkpoint that the next process cannot load.
func restorePayload(p payload) (Checkpoint, error) {
	empty := Checkpoint{Store: bundle.New()}
	if p.Schema != schema || p.Clock < 0 {
		return empty, fmt.Errorf("invalid state schema/clock")
	}
	s, e := bundle.Restore(p.Records)
	if e != nil {
		return empty, e
	}
	for _, r := range p.Records {
		if r.Bundle != nil && r.Bundle.FetchedAt > p.Clock {
			return empty, fmt.Errorf("snapshot newer than trusted clock checkpoint")
		}
		if r.Bundle != nil {
			for _, issuer := range r.Bundle.Issuers {
				// encoding/json replaces invalid UTF-8. Refuse identifiers that
				// would change or collapse during an acknowledged round trip.
				if !utf8.ValidString(issuer) {
					return empty, fmt.Errorf("invalid UTF-8 persisted issuer")
				}
			}
		}
	}
	return Checkpoint{Store: s, Clock: p.Clock}, nil
}
func save(path string, c Checkpoint) error {
	p := payload{Schema: schema, Clock: c.Clock, Records: c.Store.Records()}
	if _, e := restorePayload(p); e != nil {
		return e
	}
	h, e := digest(p)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{Payload: p, Checksum: h})
	if e != nil {
		return e
	}
	raw = append(raw, '\n')
	if len(raw) > maxCheckpointBytes {
		return fmt.Errorf("checkpoint exceeds size bound")
	}
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".proofmesh-state-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0o600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// Commit serializes writers, loads the current watermark under the lock, and
// atomically persists accepted mutations before returning success. Corruption
// and missing state after initialization never cause a fallback to empty trust.
func Commit(ctx context.Context, path string, at int64, change func(bundle.Store) (bundle.Store, evidence.Reason)) (Checkpoint, evidence.Reason, error) {
	empty := Checkpoint{Store: bundle.New()}
	if at < 0 {
		return empty, evidence.UnknownState, fmt.Errorf("negative clock")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return empty, evidence.UnknownState, e
	}
	unlock, e := lock(ctx, path+".lock")
	if e != nil {
		return empty, evidence.UnknownState, e
	}
	defer unlock()
	c, e := Load(path)
	if os.IsNotExist(e) {
		// The initialized marker survives deletion of the data file.
		if _, marker := os.Lstat(path + ".initialized"); marker == nil {
			return empty, evidence.UnknownState, fmt.Errorf("initialized state file missing; refusing reset")
		} else if !os.IsNotExist(marker) {
			return empty, evidence.UnknownState, fmt.Errorf("cannot inspect initialization marker: %w", marker)
		}
		c = empty
		e = nil
	}
	if e != nil {
		return empty, evidence.UnknownState, e
	}
	if at < c.Clock {
		return c, evidence.UnknownState, fmt.Errorf("clock checkpoint rollback")
	}
	next, reason := change(c.Store)
	if reason != evidence.Updated {
		return c, reason, nil
	}
	n := Checkpoint{Store: next, Clock: at}
	if e = save(path, n); e != nil {
		return c, evidence.UnknownState, e
	}
	marker, e := os.OpenFile(path+".initialized", os.O_CREATE|os.O_WRONLY, 0o600)
	if e != nil {
		return c, evidence.UnknownState, e
	}
	if e = marker.Sync(); e != nil {
		marker.Close()
		return c, evidence.UnknownState, e
	}
	if e = marker.Close(); e != nil {
		return c, evidence.UnknownState, e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return c, evidence.UnknownState, e
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return c, evidence.UnknownState, e
	}
	return n, reason, nil
}
