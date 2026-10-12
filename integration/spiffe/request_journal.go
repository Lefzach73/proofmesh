// Durable toy application effects and request deduplication. The counter IS the
// complete protected effect; this is not a transaction over an external service.
// The caller holds applicationGate.mu and the existing trustDisk process lease.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"proofmesh.local/research/internal/jsoncheck"
)

const requestJournalSchema = "proofmesh-request-journal-1"
const maxRequestEntries = 1024
const maxRequestJournalBytes = 1024 * 1024

type applicationRequest struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	Audience  string `json:"audience"`
	Action    string `json:"action"`
}

type requestEntry struct {
	Arm       string `json:"arm"`
	Peer      string `json:"peer"`
	RequestID string `json:"request_id"`
	Counter   uint64 `json:"counter"`
}

type requestPayload struct {
	Schema  string         `json:"schema"`
	Own     string         `json:"own"`
	Remote  string         `json:"remote"`
	Arms    []string       `json:"arms"`
	Entries []requestEntry `json:"entries"`
}

type requestEnvelope struct {
	Payload  requestPayload `json:"payload"`
	Checksum string         `json:"payload_sha256"`
}

type requestKey struct{ Arm, Peer, ID string }

type requestJournal struct {
	path     string
	payload  requestPayload
	counters map[string]uint64
	seen     map[requestKey]bool
	fileHash string
	// Only tests set this hook, for actual child-process crashes around rename.
	fault func(string) error
}

func requestDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func validRequestID(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for _, b := range []byte(id) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == ':') {
			return false
		}
	}
	return true
}

func decodeApplicationRequest(raw []byte) (applicationRequest, error) {
	var r applicationRequest
	if len(raw) > 4096 {
		return r, errors.New("application request exceeds 4096 bytes")
	}
	if err := jsoncheck.Check(raw); err != nil {
		return r, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return r, err
	}
	if len(fields) != 4 {
		return r, errors.New("exact request fields required")
	}
	for name := range fields {
		if name != "version" && name != "request_id" && name != "audience" && name != "action" {
			return r, errors.New("unknown request field")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	if d.Decode(new(any)) != io.EOF {
		return r, errors.New("trailing application data")
	}
	if r.Version != 1 || !validRequestID(r.RequestID) || len(r.Audience) > 512 || r.Audience == "" || r.Action == "" {
		return r, errors.New("invalid request version/id/audience/action")
	}
	return r, nil
}

func checkedRequestJournal(path string, p requestPayload) (*requestJournal, error) {
	j := &requestJournal{path: path, payload: p, counters: map[string]uint64{}, seen: map[requestKey]bool{}}
	own, err := spiffeid.FromString(p.Own)
	if err != nil || own.Path() == "" || len(p.Own) > 512 || p.Schema != requestJournalSchema || len(p.Entries) > maxRequestEntries {
		return nil, errors.New("invalid request journal identity/schema/size")
	}
	remote, err := spiffeid.TrustDomainFromString(p.Remote)
	if err != nil {
		return nil, err
	}
	if len(p.Arms) != 3 || p.Arms[0] != "B0.direct" {
		return nil, errors.New("invalid journal arms")
	}
	validArms := false
	for _, budget := range []string{"0", "3", "120"} {
		if p.Arms[1] == "B2/"+budget && p.Arms[2] == "B3/"+budget {
			validArms = true
		}
	}
	if !validArms {
		return nil, errors.New("inconsistent journal budgets")
	}
	for _, arm := range p.Arms {
		j.counters[arm] = 0
	}
	for _, e := range p.Entries {
		_, ok := j.counters[e.Arm]
		peer, err := spiffeid.FromString(e.Peer)
		key := requestKey{e.Arm, e.Peer, e.RequestID}
		if !ok || err != nil || peer.Path() == "" || peer.TrustDomain() != remote || len(e.Peer) > 512 || !validRequestID(e.RequestID) || j.seen[key] || e.Counter != j.counters[e.Arm]+1 {
			return nil, errors.New("invalid/duplicate journal entry or counter discontinuity")
		}
		j.seen[key] = true
		j.counters[e.Arm] = e.Counter
	}
	return j, nil
}

func readJournalBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxRequestJournalBytes {
		return nil, errors.New("request journal must be bounded regular owner-only file")
	}
	return os.ReadFile(path)
}

func loadRequestJournal(path string) (*requestJournal, error) {
	raw, err := readJournalBytes(path)
	if err != nil {
		return nil, err
	}
	if err := jsoncheck.Check(raw); err != nil {
		return nil, err
	}
	var e requestEnvelope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing request journal data")
	}
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, err
	}
	if requestDigest(payload) != e.Checksum {
		return nil, errors.New("request journal checksum mismatch")
	}
	j, err := checkedRequestJournal(path, e.Payload)
	if err != nil {
		return nil, err
	}
	j.fileHash = requestDigest(raw)
	return j, nil
}

func (j *requestJournal) save() error {
	if _, err := checkedRequestJournal(j.path, j.payload); err != nil {
		return err
	}
	payload, err := json.Marshal(j.payload)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(requestEnvelope{j.payload, requestDigest(payload)})
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > maxRequestJournalBytes {
		return errors.New("request journal exceeds byte bound")
	}
	f, err := os.CreateTemp(filepath.Dir(j.path), ".proofmesh-request-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if j.fault != nil {
		if err := j.fault("before-rename"); err != nil {
			return err
		}
	}
	if err = os.Rename(f.Name(), j.path); err != nil {
		return err
	}
	if j.fault != nil {
		if err := j.fault("after-rename"); err != nil {
			return err
		}
	}
	if err = syncDirectory(filepath.Dir(j.path)); err != nil {
		return err
	}
	j.fileHash = requestDigest(raw)
	return nil
}

func ensureRequestMarker(path string) error {
	marker := path + ".initialized"
	if info, err := os.Lstat(marker); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("invalid request initialization marker")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func openRequestJournal(path string, own spiffeid.ID, remote spiffeid.TrustDomain, arms []string) (*requestJournal, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute clean journal path required")
	}
	if err := privateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	j, err := loadRequestJournal(path)
	if os.IsNotExist(err) {
		if _, marker := os.Lstat(path + ".initialized"); !os.IsNotExist(marker) {
			return nil, errors.New("initialized request journal missing; refusing reset")
		}
		j, err = checkedRequestJournal(path, requestPayload{requestJournalSchema, own.String(), remote.String(), append([]string{}, arms...), []requestEntry{}})
		if err == nil {
			err = j.save()
		}
	}
	if err != nil {
		return nil, err
	}
	if j.payload.Own != own.String() || j.payload.Remote != remote.String() || !reflect.DeepEqual(j.payload.Arms, arms) {
		return nil, errors.New("journal does not match server identity/domain/arms")
	}
	if err := ensureRequestMarker(path); err != nil {
		return nil, err
	}
	return j, nil
}

// The returned counter is the durable effect. A duplicate is rejected even on
// another connection or after restart; distinct authenticated peers have separate
// request-ID namespaces. Errors after rename have unknown commit status, and the
// caller MUST latch fail-closed until restart rather than assert zero effects.
func (j *requestJournal) commit(arm string, peer spiffeid.ID, id string) (*requestJournal, string, error) {
	raw, err := readJournalBytes(j.path)
	if err != nil {
		return nil, "STATE_ERROR", err
	}
	if requestDigest(raw) != j.fileHash {
		return nil, "STATE_ERROR", errors.New("request journal changed outside owner process")
	}
	if info, err := os.Lstat(j.path + ".initialized"); err != nil {
		return nil, "STATE_ERROR", err
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, "STATE_ERROR", errors.New("invalid request initialization marker")
	}
	if _, ok := j.counters[arm]; !ok || !validRequestID(id) {
		return nil, "INVALID_REQUEST", errors.New("invalid journal commit arguments")
	}
	if j.seen[requestKey{arm, peer.String(), id}] {
		return j, "REPLAY", nil
	}
	if len(j.payload.Entries) >= maxRequestEntries {
		return j, "REQUEST_CAPACITY", nil
	}
	p := j.payload
	p.Entries = append(append([]requestEntry{}, p.Entries...), requestEntry{arm, peer.String(), id, j.counters[arm] + 1})
	next, err := checkedRequestJournal(j.path, p)
	if err != nil {
		return nil, "INVALID_REQUEST", err
	}
	next.fault = j.fault
	if err := next.save(); err != nil {
		return nil, "COMMIT_UNKNOWN", fmt.Errorf("request effect commit not acknowledged: %w", err)
	}
	return next, "AUTHORIZED", nil
}
