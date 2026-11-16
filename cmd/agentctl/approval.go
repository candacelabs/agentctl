package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chocks/agentctl/pkg/approval"
	"github.com/chocks/agentctl/pkg/config"
)

func cmdApproval(paths config.Paths) {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: agentctl approval [list|approve|deny]")
		os.Exit(1)
	}

	switch os.Args[2] {
	case "list":
		cmdApprovalList(paths.Approvals)
	case "approve":
		cmdApprovalResolve(paths.Approvals, approval.StatusApproved)
	case "deny":
		cmdApprovalResolve(paths.Approvals, approval.StatusDenied)
	default:
		fmt.Fprintf(os.Stderr, "unknown approval command: %s\n", os.Args[2])
		os.Exit(1)
	}
}

func cmdApprovalList(approvalPath string) {
	status := approval.Status(stringFlagValue("--status", ""))
	records, err := approval.List(approval.NewFileStore(approvalPath), status)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%-36s %-18s %-18s %-10s %s\n", "APPROVAL ID", "SESSION", "ACTION", "STATUS", "REASON")
	fmt.Println(strings.Repeat("-", 100))
	for _, record := range records {
		fmt.Printf("%-36s %-18s %-18s %-10s %s\n",
			record.ApprovalID,
			truncate(record.SessionID, 18),
			record.Action,
			record.Status,
			truncate(record.Reason, 40),
		)
	}
	fmt.Printf("\n%d approvals shown\n", len(records))
}

// resolveApprovalByStatus settles an approval as approved or denied, stamped now.
func resolveApprovalByStatus(s approval.Store, approvalID string, status approval.Status, resolvedBy string) (approval.Record, error) {
	if status == approval.StatusApproved {
		return approval.Approve(s, approvalID, resolvedBy, time.Now())
	}
	return approval.Deny(s, approvalID, resolvedBy, time.Now())
}

func cmdApprovalResolve(approvalPath string, status approval.Status) {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: agentctl approval %s <approval_id> [--by name]\n", status)
		os.Exit(1)
	}

	record, err := resolveApprovalByStatus(approval.NewFileStore(approvalPath), os.Args[3], status, stringFlagValue("--by", "local-operator"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding approval: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
