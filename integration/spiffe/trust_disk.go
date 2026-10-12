package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	corebundle "proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	corestate "proofmesh.local/research/internal/state"
)

// The existing core checkpoint is the sole authority. Public certificate blobs
// are content-addressed and synced BEFORE it references them. Orphan blobs from
// an interrupted write grant no trust. Never serialize SVID/private key material.
type trustDisk struct {
	path    string
	remote  spiffeid.TrustDomain
	current corebundle.Store
	clock   int64
	unlock  func()
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("live trust directory must be an owner-only non-symlink directory")
	}
	return nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func sameStore(a, b corebundle.Store) bool {
	x, _ := json.Marshal(a.Records())
	y, _ := json.Marshal(b.Records())
	return bytes.Equal(x, y)
}

func (d *trustDisk) certificatePath(hash string) (string, error) {
	decoded, err := hex.DecodeString(hash)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != hash {
		return "", errors.New("invalid public certificate digest in checkpoint")
	}
	return filepath.Join(d.path+".certificates", hash+".der"), nil
}

func (d *trustDisk) readCertificate(hash string) (*x509.Certificate, error) {
	path, err := d.certificatePath(hash)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return nil, errors.New("invalid public certificate blob type, permissions or size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	if certificateHash(cert) != hash {
		return nil, errors.New("public certificate digest mismatch")
	}
	return cert, nil
}

func (d *trustDisk) writeCertificate(cert *x509.Certificate) error {
	if len(cert.Raw) > 65536 {
		return errors.New("public certificate exceeds live lab bound")
	}
	hash := certificateHash(cert)
	path, err := d.certificatePath(hash)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		_, err = d.readCertificate(hash)
		return err // Existing corrupt objects are never silently repaired.
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(d.path+".certificates", ".public-cert-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(cert.Raw); err != nil {
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
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(d.path + ".certificates")
}

func (d *trustDisk) restore(store corebundle.Store) (pairedCache, error) {
	cache := pairedCache{remote: d.remote, store: store}
	records := store.Records()
	if len(records) > 1 {
		return cache, errors.New("live checkpoint must contain only its configured remote domain")
	}
	for _, record := range records {
		if record.Domain != d.remote.String() {
			return cache, errors.New("live checkpoint remote domain mismatch")
		}
		if record.Bundle == nil {
			continue
		} // Persistent removal tombstone.
		if record.Bundle.Epoch != 1 || len(record.Bundle.Issuers) > 128 {
			return cache, errors.New("unsupported live checkpoint epoch/authority count")
		}
		certs := []*x509.Certificate{}
		for _, hash := range record.Bundle.Issuers {
			cert, err := d.readCertificate(hash)
			if err != nil {
				return cache, fmt.Errorf("cannot restore public trust: %w", err)
			}
			certs = append(certs, cert)
		}
		cache.bundle = spiffebundle.FromX509Authorities(d.remote, certs)
		if record.Bundle.Sequence != nil {
			cache.bundle.SetSequenceNumber(*record.Bundle.Sequence)
		}
		cache.fetched = time.Unix(record.Bundle.FetchedAt, 0)
	}
	// Original HTTP body hash / refresh hint are not in the security checkpoint.
	// Do not invent them or replace the original observation time with load time.
	return cache, nil
}

func openTrustDisk(ctx context.Context, path string, remote spiffeid.TrustDomain, at int64) (*trustDisk, pairedCache, error) {
	empty := pairedCache{}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, empty, errors.New("absolute clean live checkpoint path required")
	}
	if err := privateDirectory(filepath.Dir(path)); err != nil {
		return nil, empty, err
	}
	unlock, err := leaseTrustFile(path + ".lease")
	if err != nil {
		return nil, empty, err
	}
	d := &trustDisk{path: path, remote: remote, unlock: unlock}
	fail := func(err error) (*trustDisk, pairedCache, error) { unlock(); return nil, empty, err }
	if err := privateDirectory(path + ".certificates"); err != nil {
		return fail(err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return fail(err)
	}
	var restored pairedCache
	var restoreErr error
	checkpoint, reason, err := corestate.Commit(ctx, path, at, func(store corebundle.Store) (corebundle.Store, evidence.Reason) {
		restored, restoreErr = d.restore(store)
		if restoreErr != nil {
			return store, evidence.UnknownState
		}
		return store, evidence.Updated // Atomically initialize/check the clock too.
	})
	if err != nil {
		return fail(err)
	}
	if restoreErr != nil {
		return fail(restoreErr)
	}
	if reason != evidence.Updated {
		return fail(errors.New("live trust startup checkpoint rejected"))
	}
	d.current, d.clock = checkpoint.Store, checkpoint.Clock
	return d, restored, nil
}

func (d *trustDisk) save(ctx context.Context, cache pairedCache, at int64) error {
	if at < d.clock {
		return errors.New("live verifier clock rollback")
	}
	if cache.bundle != nil {
		certs := cache.bundle.X509Authorities()
		if len(certs) > 128 {
			return errors.New("too many live lab authorities")
		}
		for _, cert := range certs {
			if err := d.writeCertificate(cert); err != nil {
				return err
			}
		}
	}
	if _, err := d.restore(cache.store); err != nil {
		return err
	}
	checkpoint, reason, err := corestate.Commit(ctx, d.path, at, func(current corebundle.Store) (corebundle.Store, evidence.Reason) {
		if !sameStore(current, d.current) {
			return current, evidence.UnknownState
		}
		return cache.store, evidence.Updated
	})
	if err != nil {
		return err
	}
	if reason != evidence.Updated {
		return errors.New("live checkpoint changed outside its owner process")
	}
	d.current, d.clock = checkpoint.Store, checkpoint.Clock
	return nil
}
