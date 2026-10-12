package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"proofmesh.local/research/internal/sim"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: proofmesh {demo|simulate|validate|state|bench|report|proof} [options]")
	}
	switch args[0] {
	case "state":
		return stateCommand(args[1:], out)
	case "demo", "simulate", "validate":
		f := flag.NewFlagSet(args[0], flag.ContinueOnError)
		path := f.String("scenario", "examples/federation_basic.scenario.json", "scenario path")
		strict := f.Bool("strict", false, "B2 fail-closed uncertainty")
		budget := f.Int64("budget", -1, "freshness budget override seconds")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		file, err := os.Open(*path)
		if err != nil {
			return err
		}
		defer file.Close()
		s, err := sim.Decode(file)
		if err != nil {
			return err
		}
		if args[0] == "validate" {
			return json.NewEncoder(out).Encode(map[string]any{"valid": true, "scenario_id": s.ScenarioID, "events": len(s.Events), "synthetic_only": true})
		}
		var b *int64
		if *budget >= 0 {
			b = budget
		}
		logs, err := sim.Run(s, *strict, b)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(out)
		for _, l := range logs {
			if err = enc.Encode(l); err != nil {
				return err
			}
		}
		return nil
	case "bench", "report", "proof":
		script := map[string]string{"bench": "experiments/scripts/compare.py", "report": "experiments/scripts/report.py", "proof": "formal/run.py"}[args[0]]
		if _, err := os.Stat(script); err != nil {
			return fmt.Errorf("run from repository root: %w", err)
		}
		python := os.Getenv("PROOFMESH_PYTHON")
		if python == "" {
			python = "python3"
		}
		cmd := exec.Command(python, append([]string{filepath.Clean(script)}, args[1:]...)...)
		cmd.Stdout = out
		cmd.Stderr = os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
