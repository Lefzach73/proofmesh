package main

import (
	"bytes"
	"testing"
)

func TestCLI(t *testing.T) {
	var b bytes.Buffer
	if err := run([]string{"validate", "--scenario", "../../examples/federation_basic.scenario.json"}, &b); err != nil {
		t.Fatal(err)
	}
	if b.Len() == 0 {
		t.Fatal("missing output")
	}
	if err := run([]string{"no-such-command"}, &b); err == nil {
		t.Fatal("unknown command accepted")
	}
	if err := run([]string{"simulate", "--scenario", "missing.json"}, &b); err == nil {
		t.Fatal("missing input accepted")
	}
}
