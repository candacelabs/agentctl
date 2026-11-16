package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/chocks/agentctl/pkg/approval"
	"github.com/chocks/agentctl/pkg/schema"
)

func TestRecordAndResolveApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.jsonl")
	decision := &schema.Decision{
		TraceID:          "trace-1",
		Timestamp:        time.Now(),
		Reason:           "needs approval",
		ApprovalRequired: true,
		Request: schema.ActionRequest{
			Action: schema.ActionAccessSecret,
			Context: schema.RequestContext{
				SessionID: "session-1",
			},
		},
	}

	if err := approval.RecordForDecision(approval.NewFileStore(path), decision); err != nil {
		t.Fatalf("RecordForDecision() error = %v", err)
	}

	records, err := approval.List(approval.NewFileStore(path), approval.StatusPending)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 pending approval, got %d", len(records))
	}

	resolved, err := resolveApprovalByStatus(approval.NewFileStore(path), "trace-1", approval.StatusApproved, "alice")
	if err != nil {
		t.Fatalf("resolveApprovalByStatus() error = %v", err)
	}
	if resolved.Status != approval.StatusApproved {
		t.Fatalf("expected approved status, got %s", resolved.Status)
	}
	if resolved.ResolvedBy != "alice" {
		t.Fatalf("expected resolved_by alice, got %q", resolved.ResolvedBy)
	}
}
