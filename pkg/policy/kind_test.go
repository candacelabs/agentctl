package policy

import (
	"encoding/json"
	"testing"

	"github.com/chocks/agentctl/pkg/schema"
)

func TestEvaluateRegisteredKind(t *testing.T) {
	const kind schema.Action = "write_state"

	tests := []struct {
		name        string
		policy      string
		opts        []Option
		params      map[string]any
		wantVerdict schema.Verdict
		wantRisk    int
		wantRule    string
	}{
		{
			name:        "no policy allows at the registered default risk",
			policy:      "actions: {}\n",
			opts:        []Option{WithKindRisk(kind, 25)},
			params:      map[string]any{"table": "tasks"},
			wantVerdict: schema.VerdictAllow,
			wantRisk:    25,
		},
		{
			name:        "no policy and no default risk allows at zero",
			policy:      "actions: {}\n",
			params:      map[string]any{"table": "tasks"},
			wantVerdict: schema.VerdictAllow,
		},
		{
			name:        "base_risk in the file wins over the option",
			policy:      "actions:\n  write_state:\n    base_risk: 40\n",
			opts:        []Option{WithKindRisk(kind, 25)},
			params:      map[string]any{"table": "tasks"},
			wantVerdict: schema.VerdictAllow,
			wantRisk:    40,
		},
		{
			name:        "block_patterns match the named param",
			policy:      "actions:\n  write_state:\n    block_param: table\n    block_patterns: [secrets]\n",
			params:      map[string]any{"table": "app_secrets"},
			wantVerdict: schema.VerdictDeny,
			wantRisk:    100,
			wantRule:    "block_pattern:secrets",
		},
		{
			name:        "block_patterns ignore other params",
			policy:      "actions:\n  write_state:\n    block_param: table\n    block_patterns: [secrets]\n",
			params:      map[string]any{"table": "tasks", "note": "secrets"},
			wantVerdict: schema.VerdictAllow,
		},
		{
			name:        "block_patterns without block_param do nothing",
			policy:      "actions:\n  write_state:\n    block_patterns: [secrets]\n",
			params:      map[string]any{"table": "secrets"},
			wantVerdict: schema.VerdictAllow,
		},
		{
			name:        "missing named param does not match",
			policy:      "actions:\n  write_state:\n    block_param: table\n    block_patterns: [secrets]\n",
			params:      map[string]any{"other": "secrets"},
			wantVerdict: schema.VerdictAllow,
		},
		{
			name:        "require_approval always escalates",
			policy:      "actions:\n  write_state:\n    require_approval: always\n",
			opts:        []Option{WithKindRisk(kind, 25)},
			params:      map[string]any{"table": "tasks"},
			wantVerdict: schema.VerdictEscalate,
			wantRisk:    25,
			wantRule:    "require_approval",
		},
		{
			name:        "block wins over approval, first match",
			policy:      "actions:\n  write_state:\n    block_param: table\n    block_patterns: [secrets]\n    require_approval: always\n",
			params:      map[string]any{"table": "secrets"},
			wantVerdict: schema.VerdictDeny,
			wantRisk:    100,
			wantRule:    "block_pattern:secrets",
		},
		{
			name:        "high_risk escalates at the registered risk",
			policy:      "actions:\n  write_state:\n    require_approval: high_risk\n",
			opts:        []Option{WithKindRisk(kind, 70)},
			params:      map[string]any{"table": "tasks"},
			wantVerdict: schema.VerdictEscalate,
			wantRisk:    70,
			wantRule:    "high_risk_escalation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := LoadFromBytes([]byte(tt.policy), tt.opts...)
			if err != nil {
				t.Fatalf("LoadFromBytes: %v", err)
			}
			params, err := json.Marshal(tt.params)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got := e.Evaluate(schema.ActionRequest{Action: kind, Params: params})
			if got.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %s, want %s (%s)", got.Verdict, tt.wantVerdict, got.Reason)
			}
			if got.RiskScore != tt.wantRisk {
				t.Errorf("risk = %d, want %d", got.RiskScore, tt.wantRisk)
			}
			if tt.wantRule != "" && (len(got.MatchedRules) == 0 || got.MatchedRules[len(got.MatchedRules)-1] != tt.wantRule) {
				t.Errorf("matched rules = %v, want %q", got.MatchedRules, tt.wantRule)
			}
		})
	}
}

func TestBlockParamIgnoredForBuiltInKinds(t *testing.T) {
	e := makeEngine(t, "actions:\n  run_code:\n    block_param: command\n    block_patterns: [rm]\n")
	got := e.Evaluate(schema.ActionRequest{
		Action: schema.ActionRunCode,
		Params: mustMarshal(t, schema.RunCodeParams{Command: "ls"}),
	})
	if got.Verdict != schema.VerdictAllow || got.RiskScore != 50 {
		t.Fatalf("got %s risk %d, want allow at the built-in risk 50", got.Verdict, got.RiskScore)
	}
}
