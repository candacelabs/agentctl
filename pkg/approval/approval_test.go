package approval

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chocks/agentctl/pkg/schema"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func escalation(id string, at time.Time) *schema.Decision {
	return &schema.Decision{
		TraceID:          id,
		Verdict:          schema.VerdictEscalate,
		ApprovalRequired: true,
		Timestamp:        at,
		Reason:           "needs a human",
		Request: schema.ActionRequest{
			Action:  schema.ActionAccessSecret,
			Context: schema.RequestContext{SessionID: "s1"},
		},
	}
}

func stores(t *testing.T) map[string]Store {
	return map[string]Store{
		"file":   NewFileStore(filepath.Join(t.TempDir(), "sub", "approvals.jsonl")),
		"memory": &MemoryStore{},
	}
}

func TestRecordForDecision(t *testing.T) {
	allow := &schema.Decision{TraceID: "a", Verdict: schema.VerdictAllow}
	tests := []struct {
		name     string
		decision *schema.Decision
		want     int
	}{
		{name: "nil decision", decision: nil, want: 0},
		{name: "no approval required", decision: allow, want: 0},
		{name: "escalation recorded pending", decision: escalation("e1", t0), want: 1},
	}
	for _, tc := range tests {
		for kind, s := range stores(t) {
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				if err := RecordForDecision(s, tc.decision); err != nil {
					t.Fatalf("RecordForDecision: %v", err)
				}
				got, err := List(s, "")
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if len(got) != tc.want {
					t.Fatalf("got %d records, want %d", len(got), tc.want)
				}
				if tc.want == 1 && (got[0].Status != StatusPending || got[0].ApprovalID != "e1" || got[0].SessionID != "s1" || !got[0].RequestedAt.Equal(t0)) {
					t.Fatalf("unexpected record %+v", got[0])
				}
			})
		}
	}
}

func TestListFiltersAndOrders(t *testing.T) {
	for kind, s := range stores(t) {
		t.Run(kind, func(t *testing.T) {
			for _, d := range []*schema.Decision{escalation("old", t0), escalation("new", t0.Add(time.Hour)), escalation("mid", t0.Add(time.Minute))} {
				if err := RecordForDecision(s, d); err != nil {
					t.Fatalf("RecordForDecision: %v", err)
				}
			}
			if _, err := Approve(s, "mid", "alice", t0.Add(2*time.Hour)); err != nil {
				t.Fatalf("Approve: %v", err)
			}
			tests := []struct {
				name   string
				status Status
				want   []string
			}{
				{name: "all, newest request first", status: "", want: []string{"new", "mid", "old"}},
				{name: "pending only", status: StatusPending, want: []string{"new", "old"}},
				{name: "approved only", status: StatusApproved, want: []string{"mid"}},
				{name: "denied none", status: StatusDenied, want: []string{}},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					got, err := List(s, tc.status)
					if err != nil {
						t.Fatalf("List: %v", err)
					}
					if len(got) != len(tc.want) {
						t.Fatalf("got %d, want %d", len(got), len(tc.want))
					}
					for i, id := range tc.want {
						if got[i].ApprovalID != id {
							t.Fatalf("index %d = %s, want %s", i, got[i].ApprovalID, id)
						}
					}
				})
			}
		})
	}
}

func TestApproveAndDeny(t *testing.T) {
	resolvers := map[string]struct {
		fn   func(Store, string, string, time.Time) (Record, error)
		want Status
	}{
		"approve": {fn: Approve, want: StatusApproved},
		"deny":    {fn: Deny, want: StatusDenied},
	}
	tests := []struct {
		name    string
		id      string
		prior   string // resolve this id first, to make the next attempt a double resolution
		wantErr string
	}{
		{name: "pending resolves", id: "e1"},
		{name: "unknown id", id: "nope", wantErr: "not found"},
		{name: "already resolved", id: "e1", prior: "e1", wantErr: "already"},
	}
	at := t0.Add(time.Hour)
	for rname, r := range resolvers {
		for _, tc := range tests {
			for kind, s := range stores(t) {
				t.Run(rname+"/"+tc.name+"/"+kind, func(t *testing.T) {
					if err := RecordForDecision(s, escalation("e1", t0)); err != nil {
						t.Fatalf("RecordForDecision: %v", err)
					}
					if tc.prior != "" {
						if _, err := Approve(s, tc.prior, "first", t0); err != nil {
							t.Fatalf("prior Approve: %v", err)
						}
					}
					got, err := r.fn(s, tc.id, "alice", at)
					if tc.wantErr != "" {
						if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
							t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
						}
						return
					}
					if err != nil {
						t.Fatalf("resolve: %v", err)
					}
					if got.Status != r.want || got.ResolvedBy != "alice" || got.ResolvedAt == nil || !got.ResolvedAt.Equal(at) {
						t.Fatalf("unexpected record %+v", got)
					}
					pending, err := List(s, StatusPending)
					if err != nil || len(pending) != 0 {
						t.Fatalf("pending = %d, %v; want none", len(pending), err)
					}
				})
			}
		}
	}
}

func TestFileStoreMissingFileAndMalformedLines(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "approvals.jsonl"))
	got, err := s.Read()
	if err != nil || len(got) != 0 {
		t.Fatalf("missing file: %v, %d records", err, len(got))
	}
}
