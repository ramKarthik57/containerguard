package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"cg-smoke-test/internal/detection"
	"cg-smoke-test/internal/telemetry"
)

// Storage handles local persistence of events and security alerts.
type Storage struct {
	mu        sync.Mutex
	eventFile *os.File
	alertFile *os.File
}

// NewStorage opens local JSON lines audit sinks.
func NewStorage(eventLogPath, alertLogPath string) (*Storage, error) {
	var ef, af *os.File
	var err error

	if eventLogPath != "" {
		ef, err = os.OpenFile(eventLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			return nil, fmt.Errorf("opening event log file %s: %w", eventLogPath, err)
		}
	}

	if alertLogPath != "" {
		af, err = os.OpenFile(alertLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			if ef != nil {
				ef.Close()
			}
			return nil, fmt.Errorf("opening alert log file %s: %w", alertLogPath, err)
		}
	}

	return &Storage{
		eventFile: ef,
		alertFile: af,
	}, nil
}

// WriteEvent writes a security event as a JSON line.
func (s *Storage) WriteEvent(event *telemetry.SecurityEvent) error {
	if s.eventFile == nil {
		return nil
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data = append(data, '\n')
	_, err = s.eventFile.Write(data)
	return err
}

// WriteAlert writes a detection alert as a JSON line.
func (s *Storage) WriteAlert(alert *detection.Alert) error {
	if s.alertFile == nil {
		return nil
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data = append(data, '\n')
	_, err = s.alertFile.Write(data)
	return err
}

// Close flushes and closes active files.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	if s.eventFile != nil {
		if err := s.eventFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.alertFile != nil {
		if err := s.alertFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
