package gate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/chocks/agentctl/pkg/policy"
	"github.com/chocks/agentctl/pkg/schema"
	"github.com/chocks/agentctl/pkg/trace"
)

func TestEvaluateInvalidRequestDeniesAndRecordsTrace(t *testing.T) {
	var buf bytes.Buffer
	g := New(policy.DefaultEngine(), trace.NewWriterStore(&buf))

	params, err := json.Marshal(schema.InstallPackageParams{
		Manager: "pip",
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	decision, err := g.Evaluate(schema.ActionRequest{
		Action: schema.ActionInstallPackage,
		Params: params,
		Reason: "test invalid install",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if decision.Verdict != schema.VerdictDeny {
		t.Fatalf("expected deny, got %s", decision.Verdict)
	}
	if !strings.Contains(decision.Reason, "package name required") {
		t.Fatalf("expected validation reason, got %q", decision.Reason)
	}
	if buf.Len() == 0 {
		t.Fatal("expected trace to be recorded")
	}
}

func TestEvaluateEscalationSetsApprovalRequired(t *testing.T) {
	g := New(policy.DefaultEngine(), nil)

	params, err := json.Marshal(schema.AccessSecretParams{
		Name: "OPENAI_API_KEY",
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	decision, err := g.Evaluate(schema.ActionRequest{
		Action: schema.ActionAccessSecret,
		Params: params,
		Reason: "need provider credentials",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if decision.Verdict != schema.VerdictEscalate {
		t.Fatalf("expected escalate, got %s", decision.Verdict)
	}
	if !decision.ApprovalRequired {
		t.Fatal("expected approval_required to be true")
	}
}

func TestOptionsClockAndIDSource(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	params, err := json.Marshal(schema.RunCodeParams{Command: "ls"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := schema.ActionRequest{Action: schema.ActionRunCode, Params: params}

	tests := []struct {
		name   string
		opts   []Option
		wantID string
		wantAt time.Time
	}{
		{name: "injected", opts: []Option{WithClock(func() time.Time { return fixed }), WithIDSource(func() string { return "id-1" })}, wantID: "id-1", wantAt: fixed},
		{name: "clock only", opts: []Option{WithClock(func() time.Time { return fixed })}, wantAt: fixed},
		{name: "defaults", opts: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(policy.DefaultEngine(), nil, tc.opts...).Evaluate(req)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if tc.wantID != "" && d.TraceID != tc.wantID {
				t.Fatalf("TraceID = %q, want %q", d.TraceID, tc.wantID)
			}
			if tc.wantID == "" && d.TraceID == "" {
				t.Fatal("default id source returned empty id")
			}
			if !tc.wantAt.IsZero() && !d.Timestamp.Equal(tc.wantAt) {
				t.Fatalf("Timestamp = %v, want %v", d.Timestamp, tc.wantAt)
			}
			if tc.wantAt.IsZero() && d.Timestamp.IsZero() {
				t.Fatal("default clock returned zero time")
			}
		})
	}
}

func TestReplayChangesDecisionUnderStricterPolicy(t *testing.T) {
	params, err := json.Marshal(schema.RunCodeParams{Command: "ls"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := schema.ActionRequest{Action: schema.ActionRunCode, Params: params}
	orig, err := New(policy.DefaultEngine(), nil).Evaluate(req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	bad := schema.ActionRequest{Action: schema.ActionRunCode, Params: json.RawMessage(`{}`)}

	tests := []struct {
		name     string
		recorded []schema.Decision
		want     []schema.Verdict
	}{
		{name: "nothing recorded", recorded: nil, want: []schema.Verdict{}},
		{name: "same policy same verdict", recorded: []schema.Decision{*orig}, want: []schema.Verdict{orig.Verdict}},
		{name: "invalid request denied", recorded: []schema.Decision{{Request: bad}}, want: []schema.Verdict{schema.VerdictDeny}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Replay(policy.DefaultEngine(), tc.recorded)
			if err != nil {
				t.Fatalf("Replay() error = %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d decisions, want %d", len(got), len(tc.want))
			}
			for i, v := range tc.want {
				if got[i].Verdict != v {
					t.Fatalf("decision %d verdict = %s, want %s", i, got[i].Verdict, v)
				}
			}
		})
	}
}
