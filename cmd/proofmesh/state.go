package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"proofmesh.local/research/internal/bundle"
	"proofmesh.local/research/internal/evidence"
	"proofmesh.local/research/internal/identity"
	"proofmesh.local/research/internal/jsoncheck"
	"proofmesh.local/research/internal/state"
	"time"
)

type stateInput struct {
	SyntheticOnly bool     `json:"synthetic_only"`
	Domain        string   `json:"domain"`
	Sequence      *uint64  `json:"sequence"`
	Epoch         uint64   `json:"epoch"`
	Issuers       []string `json:"issuers"`
	Authenticated bool     `json:"authenticated"`
}

func stateCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("state {show|update|remove} --file PATH [--domain DOMAIN --at SECONDS --bundle FILE]")
	}
	f := flag.NewFlagSet("state "+args[0], flag.ContinueOnError)
	path := f.String("file", "", "local security checkpoint")
	domain := f.String("domain", "", "exact source domain")
	at := f.Int64("at", -1, "absolute trusted lab time")
	input := f.String("bundle", "", "synthetic bundle JSON")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if *path == "" || f.NArg() != 0 {
		return fmt.Errorf("state file required; no positional arguments")
	}
	if args[0] == "show" {
		c, e := state.Load(*path)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(map[string]any{"clock_high_water": c.Clock, "records": c.Store.Records(), "scope": "local persisted trust metadata; no cryptographic claim"})
	}
	if args[0] != "update" && args[0] != "remove" {
		return fmt.Errorf("unknown state operation")
	}
	if *at < 0 || *at > 1_000_000_000_000 {
		return fmt.Errorf("valid absolute lab time required")
	}
	d, e := identity.ParseDomain(*domain)
	if e != nil {
		return e
	}
	var change func(bundle.Store) (bundle.Store, evidence.Reason)
	if args[0] == "remove" {
		change = func(s bundle.Store) (bundle.Store, evidence.Reason) { return s.Remove(d), evidence.Updated }
	} else {
		file, e := os.Open(*input)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(file, 4*1024*1024+1))
		file.Close()
		if e != nil {
			return e
		}
		if len(raw) > 4*1024*1024 {
			return fmt.Errorf("bundle input too large")
		}
		if e = jsoncheck.Check(raw); e != nil {
			return e
		}
		var v stateInput
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if e = dec.Decode(&v); e != nil {
			return e
		}
		if e = dec.Decode(new(any)); e != io.EOF {
			return fmt.Errorf("trailing bundle input")
		}
		if !v.SyntheticOnly {
			return fmt.Errorf("CLI state inputs require synthetic_only=true; real validation belongs to integration adapter")
		}
		source, e := identity.ParseDomain(v.Domain)
		if e != nil {
			return e
		}
		b := bundle.Snapshot{Domain: source, Sequence: v.Sequence, Epoch: v.Epoch, Issuers: v.Issuers, Authenticated: v.Authenticated}
		change = func(s bundle.Store) (bundle.Store, evidence.Reason) { return s.Update(d, b, *at, true) }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, reason, e := state.Commit(ctx, *path, *at, change)
	if e != nil {
		return e
	}
	if e = json.NewEncoder(out).Encode(map[string]any{"reason": reason, "clock_high_water": c.Clock, "verification_mode": "simulated-bundle-metadata", "persisted": reason == evidence.Updated}); e != nil {
		return e
	}
	if reason != evidence.Updated {
		return fmt.Errorf("state mutation rejected: %s", reason)
	}
	return nil
}
