//go:build darwin || linux

package state

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
)

// TestCrashWorker runs only in the specifically launched child test process.
// The parent owns the child and its pipes; no production process is signalled.
func TestCrashWorker(t *testing.T) {
	phase := os.Getenv("PROOFMESH_TEST_CRASH_PHASE")
	if phase == "" {
		return
	}
	path := os.Getenv("PROOFMESH_TEST_CRASH_FILE")
	waitForKill := func() {
		fmt.Fprintln(os.Stdout, "ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		t.Fatal("worker resumed instead of being killed")
	}
	change := update(13, 11)
	switch phase {
	case "before-save":
		change = func(s bundle.Store) (bundle.Store, evidence.Reason) {
			next, reason := update(13, 11)(s)
			waitForKill() // The transaction holds its OS lock, but has not saved.
			return next, reason
		}
	case "after-commit":
	case "after-remove":
		change = func(s bundle.Store) (bundle.Store, evidence.Reason) {
			d, _ := identity.ParseDomain("alpha.local")
			return s.Remove(d), evidence.Updated
		}
	default:
		t.Fatal("unknown controlled crash phase")
	}
	if _, reason, err := Commit(context.Background(), path, 11, change); err != nil || reason != evidence.Updated {
		t.Fatal(reason, err)
	}
	waitForKill() // Commit has returned success, including file/directory fsync.
}

func TestProcessCrashPreservesAcknowledgedSecurityState(t *testing.T) {
	for _, phase := range []string{"before-save", "after-commit", "after-remove"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if _, reason, err := Commit(context.Background(), path, 10, update(12, 10)); err != nil || reason != evidence.Updated {
				t.Fatal(reason, err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashWorker$")
			child.Env = append(os.Environ(), "PROOFMESH_TEST_CRASH_PHASE="+phase, "PROOFMESH_TEST_CRASH_FILE="+path)
			var stderr bytes.Buffer
			child.Stderr = &stderr
			stdin, err := child.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stdout, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = child.Start(); err != nil {
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
			go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
			select {
			case line := <-ready:
				if line != "ready\n" {
					t.Fatalf("worker did not reach controlled boundary: %q", line)
				}
			case <-ctx.Done():
				t.Fatal("worker readiness deadline")
			}
			if phase == "before-save" {
				contender, stop := context.WithTimeout(context.Background(), 80*time.Millisecond)
				_, _, err = Commit(contender, path, 11, update(99, 11))
				stop()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("second process bypassed held writer lock: %v", err)
				}
			}
			if err = child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = child.Wait()
			waited = true
			var exited *exec.ExitError
			if !errors.As(err, &exited) {
				t.Fatalf("expected actual killed process, got %v (%s)", err, stderr.String())
			}
			status, ok := exited.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong termination: %v", err)
			}
			c, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			wantSequence, wantClock := uint64(12), int64(10)
			if phase == "after-commit" {
				wantSequence = 13
			}
			if phase != "before-save" {
				wantClock = 11
			}
			rows := c.Store.Records()
			if len(rows) != 1 || rows[0].HighSequence == nil || *rows[0].HighSequence != wantSequence || c.Clock != wantClock {
				t.Fatalf("lost acknowledged state: %+v clock=%d", rows, c.Clock)
			}
			if (rows[0].Bundle == nil) != (phase == "after-remove") {
				t.Fatal("incorrect tombstone restoration")
			}
			if phase == "before-save" {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("uncommitted transaction replaced checkpoint", err)
				}
			}
			recovery, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if _, reason, err := Commit(recovery, path, 12, update(wantSequence-1, 12)); err != nil || reason != evidence.Rollback {
				t.Fatal("rollback protection lost or dead writer lock survived", reason, err)
			}
			if _, reason, err := Commit(recovery, path, 12, update(wantSequence+1, 12)); err != nil || reason != evidence.Updated {
				t.Fatal("post-crash valid recovery failed", reason, err)
			}
			t.Logf("SIGKILL at %s: retained sequence=%d clock=%d tombstone=%t; rollback rejected and recovery committed", phase, wantSequence, wantClock, phase == "after-remove")
		})
	}
}
