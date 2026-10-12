// Controlled faulty publisher for an explicit local research profile. It serves
// public bundle snapshots over a genuine stock-issued SPIFFE TLS identity. This
// is an authenticated publisher rollback, NOT replay of TLS network ciphertext.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/net/netutil"
	"proofmesh.local/research/internal/jsoncheck"
)

type bundlePublisher struct {
	mu     sync.Mutex
	domain spiffeid.TrustDomain
	body   []byte
	hash   string
	served []map[string]any
}

func (p *bundlePublisher) publish(raw []byte) (string, error) {
	if len(raw) > 1024*1024 {
		return "", errors.New("public bundle exceeds 1 MiB")
	}
	if err := jsoncheck.Check(raw); err != nil {
		return "", err
	}
	var public struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &public); err != nil {
		return "", err
	}
	for _, key := range public.Keys {
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"} {
			if _, ok := key[private]; ok {
				return "", errors.New("private JWK material forbidden")
			}
		}
	}
	if _, err := spiffebundle.Parse(p.domain, raw); err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.body, p.hash = bytes.Clone(raw), hex.EncodeToString(h[:])
	return p.hash, nil
}

func (p *bundlePublisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RequestURI() != "/" {
		http.Error(w, "GET / required", http.StatusBadRequest)
		return
	}
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
		http.Error(w, "TLS 1.3 required", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.body) == 0 || len(p.served) >= 128 {
		http.Error(w, "publisher unavailable or exhausted", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	n, err := w.Write(p.body)
	row := map[string]any{"body_sha256": p.hash, "bytes_written": n, "completed": err == nil && n == len(p.body), "tls_version": r.TLS.Version, "did_resume": r.TLS.DidResume, "remote_address": r.RemoteAddr, "served_at": time.Now().UnixNano()}
	p.served = append(p.served, row)
}

func (p *bundlePublisher) stats() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Encoder runs after unlock; copy the slice. Rows never mutate afterward.
	return map[string]any{"event": "publisher-stats", "body_sha256": p.hash, "served": append([]map[string]any{}, p.served...)}
}

func publisherLab(socket, selected, address string) error {
	if !strings.HasPrefix(socket, "unix:///") {
		return errors.New("explicit local Workload API required")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return errors.New("explicit lab listen IP:port required")
	}
	id, err := spiffeid.FromString(selected)
	if err != nil || id.Path() == "" {
		return errors.New("exact publisher identity required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	init, stopInit := context.WithTimeout(ctx, 5*time.Second)
	defer stopInit()
	live, err := workloadapi.NewX509Source(init, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)), workloadapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
		for _, s := range svids {
			if s.ID == id {
				return s
			}
		}
		return nil
	}))
	if err != nil {
		return err
	}
	defer live.Close()
	svid, err := live.GetX509SVID()
	if err != nil {
		return err
	}
	if err := validate(svid, live, id, time.Now()); err != nil {
		return err
	}
	config := tlsconfig.TLSServerConfig(source{svid})
	config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	config.CurvePreferences, config.SessionTicketsDisabled = []tls.CurveID{tls.X25519}, true
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	p := &bundlePublisher{domain: id.TrustDomain()}
	server := &http.Server{Handler: p, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(netutil.LimitListener(listener, 16), config)); cancel() }()
	defer server.Close()
	stopInput := context.AfterFunc(ctx, func() { os.Stdin.Close(); server.Close() })
	defer stopInput()
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(map[string]any{"event": "ready", "role": "controlled-public-bundle-publisher", "id": id.String(), "certificate_sha256": certificateHash(svid.Certificates[0]), "not_after": svid.Certificates[0].NotAfter.Unix(), "pq_authenticated": false, "retained_credential": true}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1024*1024+4096)
	for n := 0; scanner.Scan(); n++ {
		if n >= 32 {
			return errors.New("publisher command bound exceeded")
		}
		raw := scanner.Bytes()
		if err := jsoncheck.Check(raw); err != nil {
			return err
		}
		var command struct {
			Op   string          `json:"op"`
			Body json.RawMessage `json:"body"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&command); err != nil {
			return err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("trailing publisher command")
		}
		switch command.Op {
		case "publish":
			hash, err := p.publish(command.Body)
			if err != nil {
				return err
			}
			if err := out.Encode(map[string]any{"event": "published", "body_sha256": hash}); err != nil {
				return err
			}
		case "stats":
			if err := out.Encode(p.stats()); err != nil {
				return err
			}
		default:
			return errors.New("unknown publisher operation")
		}
	}
	select {
	case err := <-done:
		return err
	default:
	}
	return scanner.Err()
}
