package main

// `agentctl trace verify [--remote <file>] [--json]`
//
// Walks the hash-chain in the trace store and reports OK or the exact record
// where it breaks. Works on the local store (~/.agentctl/traces.jsonl) or on a
// fetched remote store passed with --remote. Exit code: 0 = verified and
// complete, 1 = a chain is broken or has a sequence gap (missing record).

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/chocks/agentctl/pkg/config"
	"github.com/chocks/agentctl/pkg/trace"
)

func cmdTraceVerify(paths config.Paths) {
	source := paths.Traces
	if remote := stringFlagValue("--remote", ""); remote != "" {
		source = remote
	}
	asJSON := hasFlag("--json")

	records, err := trace.ReadRecords(source, trace.TraceFilter{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading trace store: %v\n", err)
		os.Exit(1)
	}

	report := trace.Verify(records)
	report.Source = source

	if asJSON {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error encoding report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
	} else {
		printVerifyReport(report)
	}

	if !report.Verified {
		os.Exit(1)
	}
}

func printVerifyReport(report trace.VerifyReport) {
	fmt.Printf("trace store: %s\n", report.Source)
	if len(report.Chains) == 0 {
		fmt.Println("no chained records found")
	}
	for _, c := range report.Chains {
		if c.Integrity.OK {
			fmt.Printf("chain %s: OK  %d records  root %s head %s\n",
				c.ChainID, c.Integrity.Records, shortHash(c.Integrity.Root), shortHash(c.Integrity.Head))
		} else {
			fmt.Printf("chain %s: BROKEN at seq %d: %s\n",
				c.ChainID, c.Integrity.BreakSeq, c.Integrity.Reason)
		}
	}

	comp := report.Completeness
	fmt.Printf("completeness: %d/%d records, %d gap(s)\n", comp.Observed, comp.Expected, len(comp.Gaps))
	for _, g := range comp.Gaps {
		fmt.Printf("  gap: chain %s missing seq %d\n", g.ChainID, g.MissingSeq)
	}

	if report.Verified {
		fmt.Println("VERIFIED")
	} else {
		fmt.Println("FAILED")
	}
}

// shortHash trims "sha256:" hashes to a readable prefix for human output.
func shortHash(h string) string {
	const prefix = "sha256:"
	body := h
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		body = h[len(prefix):]
	}
	if len(body) > 12 {
		body = body[:12]
	}
	if body == "" {
		return "(none)"
	}
	return "sha256:" + body
}
