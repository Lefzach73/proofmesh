//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// A lifetime lease, separate from corestate's short transaction lock. Kernel
// release on process death prevents competing stale in-memory gate instances.
func leaseTrustFile(path string) (func(), error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("live trust lease must be an owner-only regular file")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("live trust lease unavailable: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
