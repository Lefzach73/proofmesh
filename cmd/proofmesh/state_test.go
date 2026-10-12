package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStateCLIRejectsRollbackAfterReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	input := filepath.Join(dir, "bundle.json")
	raw := `{"synthetic_only":true,"domain":"alpha.local","sequence":12,"epoch":1,"issuers":["key"],"authenticated":true}`
	if e := os.WriteFile(input, []byte(raw), 0o600); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e := run([]string{"state", "update", "--file", path, "--bundle", input, "--domain", "alpha.local", "--at", "1"}, &out); e != nil {
		t.Fatal(e)
	}
	raw = `{"synthetic_only":true,"domain":"alpha.local","sequence":11,"epoch":1,"issuers":["key"],"authenticated":true}`
	if e := os.WriteFile(input, []byte(raw), 0o600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	if e := run([]string{"state", "update", "--file", path, "--bundle", input, "--domain", "alpha.local", "--at", "2"}, &out); e == nil {
		t.Fatal("restart rollback accepted")
	}
	if !bytes.Contains(out.Bytes(), []byte("BUNDLE_ROLLBACK")) {
		t.Fatal(out.String())
	}
	out.Reset()
	if e := run([]string{"state", "show", "--file", path}, &out); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"high_sequence":12`)) {
		t.Fatal("watermark lost", out.String())
	}
}
