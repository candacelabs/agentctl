package trace

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/chocks/agentctl/pkg/schema"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func chainLines(t *testing.T, ds ...*schema.Decision) (string, []Record) {
	t.Helper()
	var buf bytes.Buffer
	s := NewWriterStore(&buf)
	for _, d := range ds {
		if err := s.Record(d); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	recs, err := ReadRecordsFrom(strings.NewReader(buf.String()), TraceFilter{})
	if err != nil {
		t.Fatalf("ReadRecordsFrom: %v", err)
	}
	return buf.String(), recs
}

func TestReadFromReaders(t *testing.T) {
	text, _ := chainLines(t,
		&schema.Decision{TraceID: "a", Verdict: schema.VerdictAllow},
		&schema.Decision{TraceID: "b", Verdict: schema.VerdictDeny},
		&schema.Decision{TraceID: "c", Verdict: schema.VerdictDeny},
	)
	text += "not json\n\n"

	tests := []struct {
		name    string
		filter  TraceFilter
		wantIDs []string
	}{
		{name: "all, malformed lines skipped", filter: TraceFilter{}, wantIDs: []string{"a", "b", "c"}},
		{name: "verdict filter", filter: TraceFilter{Verdict: schema.VerdictDeny}, wantIDs: []string{"b", "c"}},
		{name: "limit keeps the tail", filter: TraceFilter{Limit: 1}, wantIDs: []string{"c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ds, err := ReadTracesFrom(strings.NewReader(text), tc.filter)
			if err != nil {
				t.Fatalf("ReadTracesFrom: %v", err)
			}
			rs, err := ReadRecordsFrom(strings.NewReader(text), tc.filter)
			if err != nil {
				t.Fatalf("ReadRecordsFrom: %v", err)
			}
			if len(ds) != len(tc.wantIDs) || len(rs) != len(tc.wantIDs) {
				t.Fatalf("got %d decisions, %d records, want %d", len(ds), len(rs), len(tc.wantIDs))
			}
			for i, id := range tc.wantIDs {
				if ds[i].TraceID != id || rs[i].Decision.TraceID != id {
					t.Fatalf("index %d: got %s/%s, want %s", i, ds[i].TraceID, rs[i].Decision.TraceID, id)
				}
			}
		})
	}
}

func TestRecordReturnsWriteError(t *testing.T) {
	tests := []struct {
		name    string
		store   *Store
		wantErr bool
	}{
		{name: "healthy writer", store: NewWriterStore(&bytes.Buffer{}), wantErr: false},
		{name: "failing writer", store: NewWriterStore(failWriter{}), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.store.Record(&schema.Decision{TraceID: "x"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Record error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestFailedWriteDoesNotAdvanceChain(t *testing.T) {
	var buf bytes.Buffer
	s := NewChainStore(failWriter{}, "c1", 0, "")
	if err := s.Record(&schema.Decision{TraceID: "lost"}); err == nil {
		t.Fatal("expected write error")
	}
	s.writer = &buf
	if err := s.Record(&schema.Decision{TraceID: "kept"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	recs, err := ReadRecordsFrom(&buf, TraceFilter{})
	if err != nil || len(recs) != 1 || recs[0].Seq != 1 {
		t.Fatalf("got %+v, %v; want one record at seq 1", recs, err)
	}
}

func TestNewChainStoreContinuesChain(t *testing.T) {
	tests := []struct {
		name     string
		lastSeq  uint64
		lastHash string
		wantSeq  uint64
	}{
		{name: "fresh chain", lastSeq: 0, lastHash: "", wantSeq: 1},
		{name: "continues after seq 7", lastSeq: 7, lastHash: "sha256:abc", wantSeq: 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			s := NewChainStore(&buf, "chain-x", tc.lastSeq, tc.lastHash)
			if err := s.Record(&schema.Decision{TraceID: "n"}); err != nil {
				t.Fatalf("Record: %v", err)
			}
			recs, err := ReadRecordsFrom(&buf, TraceFilter{})
			if err != nil || len(recs) != 1 {
				t.Fatalf("ReadRecordsFrom: %v, %d records", err, len(recs))
			}
			r := recs[0]
			if r.ChainID != "chain-x" || r.Seq != tc.wantSeq || r.PrevHash != tc.lastHash {
				t.Fatalf("got chain %q seq %d prev %q", r.ChainID, r.Seq, r.PrevHash)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	_, recs := chainLines(t,
		&schema.Decision{TraceID: "a"},
		&schema.Decision{TraceID: "b"},
		&schema.Decision{TraceID: "c"},
	)
	tampered := append([]Record(nil), recs...)
	tampered[1].Decision.Reason = "edited"
	gapped := []Record{recs[0], recs[2]}

	tests := []struct {
		name         string
		records      []Record
		wantVerified bool
		wantChains   int
		wantBreakSeq uint64
		wantGaps     int
	}{
		{name: "empty verifies", records: nil, wantVerified: true, wantChains: 0},
		{name: "intact chain", records: recs, wantVerified: true, wantChains: 1},
		{name: "tampered record reported at its seq", records: tampered, wantVerified: false, wantChains: 1, wantBreakSeq: 2},
		{name: "deleted record is a gap", records: gapped, wantVerified: false, wantChains: 1, wantBreakSeq: 3, wantGaps: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := Verify(tc.records)
			if rep.Verified != tc.wantVerified || len(rep.Chains) != tc.wantChains {
				t.Fatalf("verified=%v chains=%d, want %v/%d", rep.Verified, len(rep.Chains), tc.wantVerified, tc.wantChains)
			}
			if tc.wantChains == 1 && rep.Chains[0].Integrity.BreakSeq != tc.wantBreakSeq {
				t.Fatalf("break seq = %d, want %d", rep.Chains[0].Integrity.BreakSeq, tc.wantBreakSeq)
			}
			if len(rep.Completeness.Gaps) != tc.wantGaps {
				t.Fatalf("gaps = %d, want %d", len(rep.Completeness.Gaps), tc.wantGaps)
			}
		})
	}
}
