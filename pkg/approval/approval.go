// Package approval records and resolves escalations: decisions whose verdict
// needs a human. The log is append-only; a record's latest line wins.
package approval

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/chocks/agentctl/pkg/schema"
)

// Status is where an approval stands.
type Status string

// Approval statuses.
const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
)

// Record is one approval line in the log.
type Record struct {
	ApprovalID  string        `json:"approval_id"`
	TraceID     string        `json:"trace_id"`
	SessionID   string        `json:"session_id"`
	Action      schema.Action `json:"action"`
	Status      Status        `json:"status"`
	Reason      string        `json:"reason"`
	RequestedAt time.Time     `json:"requested_at"`
	ResolvedAt  *time.Time    `json:"resolved_at,omitempty"`
	ResolvedBy  string        `json:"resolved_by,omitempty"`
}

// Store is an append-only log of approval records.
type Store interface {
	// Append adds one record to the end of the log.
	Append(Record) error
	// Read returns every record in append order; an absent log is empty.
	Read() ([]Record, error)
}

// FileStore is a Store over a JSON lines file.
type FileStore struct {
	path string
}

// NewFileStore returns a Store over the JSON lines file at path. The file and
// its directory are created on the first Append.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Append writes record as one line, creating the file if needed.
func (s *FileStore) Append(record Record) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("creating approval directory: %w", err)
	}

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening approval file: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encoding approval record: %w", err)
	}

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("writing approval record: %w", err)
	}

	return nil
}

// Read returns every well-formed record in file order. Malformed lines are
// skipped; a missing file yields no records.
func (s *FileStore) Read() ([]Record, error) {
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Record{}, nil
		}
		return nil, fmt.Errorf("opening approval file: %w", err)
	}
	defer func() { _ = f.Close() }()

	records := []Record{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024) // allow lines up to 4 MB
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning approvals: %w", err)
	}
	return records, nil
}

// MemoryStore is a Store held in memory, for tests and embedders.
type MemoryStore struct {
	mu      sync.Mutex
	records []Record
}

// Append adds record to the log.
func (s *MemoryStore) Append(record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, record)
	return nil
}

// Read returns a copy of the log.
func (s *MemoryStore) Read() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record{}, s.records...), nil
}

// RecordForDecision appends a pending approval for decision when it requires
// one. A nil decision, or one that needs no approval, records nothing.
func RecordForDecision(s Store, decision *schema.Decision) error {
	if decision == nil || !decision.ApprovalRequired {
		return nil
	}

	return s.Append(Record{
		ApprovalID:  decision.TraceID,
		TraceID:     decision.TraceID,
		SessionID:   decision.Request.Context.SessionID,
		Action:      decision.Request.Action,
		Status:      StatusPending,
		Reason:      decision.Reason,
		RequestedAt: decision.Timestamp,
	})
}

// List returns the latest record of each approval, newest request first. A
// non-empty status keeps only approvals in that status.
func List(s Store, status Status) ([]Record, error) {
	all, err := s.Read()
	if err != nil {
		return nil, err
	}

	latest := map[string]Record{}
	for _, record := range all {
		latest[record.ApprovalID] = record
	}

	records := make([]Record, 0, len(latest))
	for _, record := range latest {
		if status != "" && record.Status != status {
			continue
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].RequestedAt.After(records[j].RequestedAt)
	})

	return records, nil
}

// Approve settles a pending approval as approved by resolvedBy at now.
func Approve(s Store, approvalID, resolvedBy string, now time.Time) (Record, error) {
	return resolve(s, approvalID, StatusApproved, resolvedBy, now)
}

// Deny settles a pending approval as denied by resolvedBy at now.
func Deny(s Store, approvalID, resolvedBy string, now time.Time) (Record, error) {
	return resolve(s, approvalID, StatusDenied, resolvedBy, now)
}

func resolve(s Store, approvalID string, status Status, resolvedBy string, now time.Time) (Record, error) {
	records, err := List(s, "")
	if err != nil {
		return Record{}, err
	}

	for _, record := range records {
		if record.ApprovalID != approvalID {
			continue
		}
		if record.Status != StatusPending {
			return Record{}, fmt.Errorf("approval %q is already %s", approvalID, record.Status)
		}

		record.Status = status
		record.ResolvedBy = resolvedBy
		record.ResolvedAt = &now
		if err := s.Append(record); err != nil {
			return Record{}, err
		}
		return record, nil
	}

	return Record{}, fmt.Errorf("approval %q not found", approvalID)
}
