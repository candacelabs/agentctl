package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/chocks/agentctl/pkg/policy"
	"github.com/chocks/agentctl/pkg/schema"
	"github.com/chocks/agentctl/pkg/trace"
)

const testKind schema.Action = "write_state"

var errNoTable = errors.New("table required")

func validateTable(params json.RawMessage) error {
	var p struct {
		Table string `json:"table"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return err
	}
	if p.Table == "" {
		return errNoTable
	}
	return nil
}

const kindPolicy = `actions:
  write_state:
    block_param: table
    block_patterns: [secrets]
`

func kindRequest(action schema.Action, params string) schema.ActionRequest {
	return schema.ActionRequest{
		Action: action,
		Params: json.RawMessage(params),
		Reason: "test",
		Context: schema.RequestContext{
			SessionID: "s1",
		},
	}
}

func TestEvaluateRegisteredKind(t *testing.T) {
	tests := []struct {
		name        string
		opts        []Option
		req         schema.ActionRequest
		wantVerdict schema.Verdict
		wantRisk    int
		wantReason  string
	}{
		{
			name:        "registered kind is allowed at its default risk",
			opts:        []Option{WithKind(testKind, validateTable)},
			req:         kindRequest(testKind, `{"table":"tasks"}`),
			wantVerdict: schema.VerdictAllow,
			wantRisk:    25,
		},
		{
			name:        "registered kind with nil validator accepts any params",
			opts:        []Option{WithKind(testKind, nil)},
			req:         kindRequest(testKind, `{}`),
			wantVerdict: schema.VerdictAllow,
			wantRisk:    25,
		},
		{
			name:        "registered kind failing validation is denied at 100",
			opts:        []Option{WithKind(testKind, validateTable)},
			req:         kindRequest(testKind, `{}`),
			wantVerdict: schema.VerdictDeny,
			wantRisk:    100,
			wantReason:  "table required",
		},
		{
			name:        "registered kind matching a policy block is denied",
			opts:        []Option{WithKind(testKind, validateTable)},
			req:         kindRequest(testKind, `{"table":"app_secrets"}`),
			wantVerdict: schema.VerdictDeny,
			wantRisk:    100,
			wantReason:  "blocked pattern",
		},
		{
			name:        "unregistered unknown kind is denied at 100",
			req:         kindRequest(testKind, `{"table":"tasks"}`),
			wantVerdict: schema.VerdictDeny,
			wantRisk:    100,
			wantReason:  "unknown action",
		},
		{
			name:        "registration is per gate, a different kind stays unknown",
			opts:        []Option{WithKind(testKind, validateTable)},
			req:         kindRequest("other_kind", `{}`),
			wantVerdict: schema.VerdictDeny,
			wantRisk:    100,
			wantReason:  "unknown action",
		},
		{
			name:        "built-in kinds cannot be overridden",
			opts:        []Option{WithKind(schema.ActionRunCode, nil)},
			req:         kindRequest(schema.ActionRunCode, `{}`),
			wantVerdict: schema.VerdictDeny,
			wantRisk:    100,
			wantReason:  "command required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := policy.LoadFromBytes([]byte(kindPolicy), policy.WithKindRisk(testKind, 25))
			if err != nil {
				t.Fatalf("LoadFromBytes: %v", err)
			}
			var buf bytes.Buffer
			g := New(engine, trace.NewWriterStore(&buf), tt.opts...)

			got, err := g.Evaluate(tt.req)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got.Verdict != tt.wantVerdict || got.RiskScore != tt.wantRisk {
				t.Errorf("got %s risk %d, want %s risk %d (%s)", got.Verdict, got.RiskScore, tt.wantVerdict, tt.wantRisk, got.Reason)
			}
			if !strings.Contains(got.Reason, tt.wantReason) {
				t.Errorf("reason %q does not contain %q", got.Reason, tt.wantReason)
			}

			recorded, err := trace.ReadTracesFrom(&buf, trace.TraceFilter{})
			if err != nil {
				t.Fatalf("ReadTracesFrom: %v", err)
			}
			if len(recorded) != 1 || recorded[0].TraceID != got.TraceID || recorded[0].Request.Action != tt.req.Action {
				t.Errorf("recorded = %+v, want the one decision %s", recorded, got.TraceID)
			}
		})
	}
}

func TestReplayRegisteredKind(t *testing.T) {
	loose, err := policy.LoadFromBytes([]byte("actions: {}\n"), policy.WithKindRisk(testKind, 25))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	strict, err := policy.LoadFromBytes([]byte(kindPolicy), policy.WithKindRisk(testKind, 25))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}

	var buf bytes.Buffer
	opt := WithKind(testKind, validateTable)
	g := New(loose, trace.NewWriterStore(&buf), opt)
	first, err := g.Evaluate(kindRequest(testKind, `{"table":"app_secrets"}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if first.Verdict != schema.VerdictAllow {
		t.Fatalf("recorded verdict = %s, want allow", first.Verdict)
	}
	recorded, err := trace.ReadTracesFrom(&buf, trace.TraceFilter{})
	if err != nil {
		t.Fatalf("ReadTracesFrom: %v", err)
	}

	tests := []struct {
		name        string
		engine      *policy.Engine
		opts        []Option
		wantVerdict schema.Verdict
		wantReason  string
	}{
		{name: "same policy replays allow", engine: loose, opts: []Option{opt}, wantVerdict: schema.VerdictAllow},
		{name: "stricter policy replays deny", engine: strict, opts: []Option{opt}, wantVerdict: schema.VerdictDeny, wantReason: "blocked pattern"},
		{name: "replay without the kind registered denies as unknown", engine: loose, wantVerdict: schema.VerdictDeny, wantReason: "unknown action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Replay(tt.engine, recorded, tt.opts...)
			if err != nil {
				t.Fatalf("Replay: %v", err)
			}
			if len(got) != 1 || got[0].Verdict != tt.wantVerdict || !strings.Contains(got[0].Reason, tt.wantReason) {
				t.Errorf("got %+v, want %s containing %q", got, tt.wantVerdict, tt.wantReason)
			}
		})
	}
}
