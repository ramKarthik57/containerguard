package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/mitigation"
	"cg-smoke-test/internal/telemetry"
)

// SQLiteStorage provides persistent relational querying for events, alerts, and mitigations.
type SQLiteStorage struct {
	mu sync.Mutex
	db *sql.DB
}

// NewSQLiteStorage opens or creates a structured SQLite evidence database.
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil && filepath.Dir(dbPath) != "." {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db %s: %w", dbPath, err)
	}

	// Enable WAL mode for high concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("setting sqlite pragma: %w", err)
	}

	s := &SQLiteStorage{db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initializing sqlite schema: %w", err)
	}

	return s, nil
}

func (s *SQLiteStorage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		seq_num INTEGER PRIMARY KEY,
		timestamp_ns INTEGER NOT NULL,
		captured_at TEXT NOT NULL,
		cgroup_id INTEGER NOT NULL,
		parent_cgroup_id INTEGER,
		container_id TEXT,
		container_name TEXT,
		tgid INTEGER NOT NULL,
		parent_tgid INTEGER,
		start_time_ns INTEGER NOT NULL,
		comm TEXT NOT NULL,
		filename TEXT NOT NULL,
		exit_code INTEGER,
		uid INTEGER,
		euid INTEGER,
		state TEXT NOT NULL,
		flags INTEGER,
		raw_json TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_events_container ON events(container_id);
	CREATE INDEX IF NOT EXISTS idx_events_tgid ON events(tgid, start_time_ns);

	CREATE TABLE IF NOT EXISTS alerts (
		id TEXT PRIMARY KEY,
		seq_num INTEGER NOT NULL,
		rule_id TEXT NOT NULL,
		title TEXT NOT NULL,
		severity TEXT NOT NULL,
		action TEXT,
		container_id TEXT,
		container_name TEXT,
		tgid INTEGER NOT NULL,
		filename TEXT NOT NULL,
		mitre_techniques TEXT,
		lineage TEXT,
		timestamp TEXT NOT NULL,
		raw_json TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
	CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

	CREATE TABLE IF NOT EXISTS mitigations (
		id TEXT PRIMARY KEY,
		alert_id TEXT NOT NULL,
		rule_id TEXT NOT NULL,
		action_taken TEXT NOT NULL,
		mode TEXT NOT NULL,
		container_id TEXT,
		container_name TEXT,
		tgid INTEGER NOT NULL,
		success INTEGER NOT NULL,
		message TEXT NOT NULL,
		timestamp TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_mitigations_container ON mitigations(container_id);
	`
	_, err := s.db.Exec(schema)
	return err
}

// WriteEvent stores a security event into SQLite.
func (s *SQLiteStorage) WriteEvent(event *telemetry.SecurityEvent) error {
	if event == nil {
		return nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	query := `
	INSERT OR REPLACE INTO events (
		seq_num, timestamp_ns, captured_at, cgroup_id, parent_cgroup_id,
		container_id, container_name, tgid, parent_tgid, start_time_ns,
		comm, filename, exit_code, uid, euid, state, flags, raw_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err = s.db.Exec(query,
		event.SeqNum,
		event.KernelTimeNS,
		event.CapturedAt.Format(time.RFC3339Nano),
		event.CgroupID,
		event.ParentCgroupID,
		event.ContainerID,
		event.ContainerName,
		event.TGID,
		event.ParentTGID,
		event.StartTimeNS,
		event.Comm,
		event.Filename,
		event.ExitCode,
		event.UID,
		event.EUID,
		string(event.State),
		event.Raw.Flags,
		string(data),
	)
	return err
}

// WriteAlert stores an alert into SQLite.
func (s *SQLiteStorage) WriteAlert(alert *detection.Alert) error {
	if alert == nil {
		return nil
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	query := `
	INSERT OR REPLACE INTO alerts (
		id, seq_num, rule_id, title, severity, action,
		container_id, container_name, tgid, filename, mitre_techniques,
		lineage, timestamp, raw_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	seqNum := uint64(0)
	cID := ""
	cName := ""
	tgid := uint32(0)
	filename := ""
	if alert.Event != nil {
		seqNum = alert.Event.SeqNum
		cID = alert.Event.ContainerID
		cName = alert.Event.ContainerName
		tgid = alert.Event.TGID
		filename = alert.Event.Filename
	}

	mitreStr := strings.Join(alert.MitreTechniques, ",")

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err = s.db.Exec(query,
		alert.ID,
		seqNum,
		alert.RuleID,
		alert.Title,
		string(alert.Severity),
		alert.MitigationAction,
		cID,
		cName,
		tgid,
		filename,
		mitreStr,
		alert.Lineage,
		alert.Timestamp.Format(time.RFC3339Nano),
		string(data),
	)
	return err
}

// WriteMitigation stores a containment record into SQLite.
func (s *SQLiteStorage) WriteMitigation(rec *mitigation.Record) error {
	if rec == nil {
		return nil
	}

	query := `
	INSERT OR REPLACE INTO mitigations (
		id, alert_id, rule_id, action_taken, mode,
		container_id, container_name, tgid, success, message, timestamp
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	succInt := 0
	if rec.Success {
		succInt = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(query,
		rec.ID,
		rec.AlertID,
		rec.RuleID,
		string(rec.ActionTaken),
		rec.Mode,
		rec.ContainerID,
		rec.ContainerName,
		rec.TGID,
		succInt,
		rec.Message,
		rec.Timestamp.Format(time.RFC3339Nano),
	)
	return err
}

// QueryEventsByContainer queries events for a given container ID.
func (s *SQLiteStorage) QueryEventsByContainer(containerID string, limit int) ([]*telemetry.SecurityEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query("SELECT raw_json FROM events WHERE container_id = ? ORDER BY seq_num ASC LIMIT ?", containerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*telemetry.SecurityEvent
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var ev telemetry.SecurityEvent
		if err := json.Unmarshal([]byte(raw), &ev); err == nil {
			events = append(events, &ev)
		}
	}
	return events, nil
}

// QueryAlertsBySeverity queries alerts matching a minimum severity.
func (s *SQLiteStorage) QueryAlertsBySeverity(severity string, limit int) ([]*detection.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query("SELECT raw_json FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?", severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*detection.Alert
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var al detection.Alert
		if err := json.Unmarshal([]byte(raw), &al); err == nil {
			alerts = append(alerts, &al)
		}
	}
	return alerts, nil
}

// Close closes the SQLite database handle.
func (s *SQLiteStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
