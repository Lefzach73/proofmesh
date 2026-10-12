//go:build darwin || linux

package state

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"
)

func lock(ctx context.Context, path string) (func(), error) {
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("lock is not a regular file")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if e != nil {
		return nil, e
	}
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			f.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
