//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"proofmesh.local/research/internal/evidence"
	corestate "proofmesh.local/research/internal/state"
)

func TestLiveTrustCrashWorker(t *testing.T) {
	phase := os.Getenv("PROOFMESH_LIVE_CRASH_PHASE")
	if phase == "" {
		return
	}
	path := os.Getenv("PROOFMESH_LIVE_CRASH_PATH")
	own, _ := spiffeid.FromString("spiffe://alpha.local/service")
	peer, _ := spiffeid.FromString("spiffe://beta.local/client")
	g := persistedTestGate(t, path, own, peer)
	initial, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(initial)
	if phase == "after-tombstone" {
		if row := g.removeTrust(context.Background()); row["success"] != true {
			t.Fatal(row)
		}
	} else {
		ca, err := newAuthority("beta.local")
		if err != nil {
			t.Fatal(err)
		}
		b := spiffebundle.FromX509Authorities(ca.domain, []*x509.Certificate{ca.cert})
		b.SetSequenceNumber(13)
		next := g.cache
		if reason, err := next.apply(authenticatedBundle{b, time.Now(), "controlled-crash-fixture"}); err != nil || reason != evidence.Updated {
			t.Fatal(reason, err)
		}
		switch phase {
		case "blob-before-checkpoint":
			if err := g.disk.writeCertificate(ca.cert); err != nil {
				t.Fatal(err)
			}
		case "after-checkpoint":
			if err := g.persist(context.Background(), next, time.Now()); err != nil {
				t.Fatal(err)
			}
			g.cache = next
		default:
			t.Fatal("unknown crash boundary")
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"ready": true, "clock": g.disk.clock, "baseline_sha256": hex.EncodeToString(hash[:])}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	t.Fatal("crash worker resumed instead of being killed")
}

func TestLiveTrustSIGKILLBoundaries(t *testing.T) {
	for _, phase := range []string{"blob-before-checkpoint", "after-checkpoint", "after-tombstone"} {
		t.Run(phase, func(t *testing.T) {
			ca, err := newAuthority("beta.local")
			if err != nil {
				t.Fatal(err)
			}
			own, _ := spiffeid.FromString("spiffe://alpha.local/service")
			peer, _ := spiffeid.FromString("spiffe://beta.local/client")
			path := filepath.Join(t.TempDir(), "live", "state.json")
			g := persistedTestGate(t, path, own, peer)
			testGateUpdate(t, g, 12, time.Now(), ca.cert)
			if err := g.persist(context.Background(), g.cache, time.Now()); err != nil {
				t.Fatal(err)
			}
			g.close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLiveTrustCrashWorker$")
			child.Env = append(os.Environ(), "PROOFMESH_LIVE_CRASH_PHASE="+phase, "PROOFMESH_LIVE_CRASH_PATH="+path)
			var stderr bytes.Buffer
			child.Stderr = &stderr
			input, err := child.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = child.Process.Kill()
					_ = child.Wait()
				}
			}()
			ready := make(chan string, 1)
			go func() { line, _ := bufio.NewReader(output).ReadString('\n'); ready <- line }()
			var boundary struct {
				Ready       bool   `json:"ready"`
				Clock       int64  `json:"clock"`
				BaselineSHA string `json:"baseline_sha256"`
			}
			select {
			case line := <-ready:
				if err := json.Unmarshal([]byte(line), &boundary); err != nil || !boundary.Ready {
					t.Fatal("worker boundary missing", line, err, stderr.String())
				}
			case <-ctx.Done():
				t.Fatal("crash readiness timeout")
			}
			if competing, _, err := openTrustDisk(ctx, path, peer.TrustDomain(), time.Now().Unix()); err == nil {
				competing.unlock()
				t.Fatal("two processes acquired same live trust lease")
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = child.Wait()
			waited = true
			var exited *exec.ExitError
			if !errors.As(err, &exited) {
				t.Fatal("expected actual SIGKILL", err, stderr.String())
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("wrong termination", err)
			}
			checkpoint, err := corestate.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if checkpoint.Clock != boundary.Clock {
				t.Fatal("acknowledged clock lost")
			}
			if phase == "blob-before-checkpoint" {
				raw, _ := os.ReadFile(path)
				hash := sha256.Sum256(raw)
				if hex.EncodeToString(hash[:]) != boundary.BaselineSHA {
					t.Fatal("orphan certificate publication altered checkpoint")
				}
			}
			g = persistedTestGate(t, path, own, peer)
			record := g.cache.store.Records()[0]
			want := uint64(12)
			if phase == "after-checkpoint" {
				want = 13
			}
			if record.HighSequence == nil || *record.HighSequence != want || (record.Bundle == nil) != (phase == "after-tombstone") {
				t.Fatal(record)
			}
			if phase == "blob-before-checkpoint" && certificateHash(g.cache.bundle.X509Authorities()[0]) != certificateHash(ca.cert) {
				t.Fatal("orphan blob became trusted")
			}
			b := spiffebundle.FromX509Authorities(ca.domain, []*x509.Certificate{ca.cert})
			b.SetSequenceNumber(want - 1)
			if reason, err := g.cache.apply(authenticatedBundle{b, time.Now(), "replayed-test-observation"}); err != nil || reason != evidence.Rollback {
				t.Fatal("rollback survived crash", reason, err)
			}
			g.close()
			t.Log(fmt.Sprintf("SIGKILL %s: sequence=%d, tombstone=%t, lease released, rollback rejected", phase, want, record.Bundle == nil))
		})
	}
}
