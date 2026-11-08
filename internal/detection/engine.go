package detection

import (
	"fmt"
	"strings"
	"time"

	"cg-smoke-test/internal/lineage"
	"cg-smoke-test/internal/telemetry"
)

// Severity represents alert severity.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Alert represents a deterministic detection alert.
type Alert struct {
	ID          string                   `json:"id"`
	RuleID      string                   `json:"rule_id"`
	Title       string                   `json:"title"`
	Description string                   `json:"description"`
	Severity    Severity                 `json:"severity"`
	Timestamp   time.Time                `json:"timestamp"`
	Event       *telemetry.SecurityEvent `json:"event"`
	Lineage     string                   `json:"lineage"`
}

// Rule defines the interface for deterministic intrusion detection checks.
type Rule interface {
	ID() string
	Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert
}

// Engine evaluates deterministic rules against telemetry events.
type Engine struct {
	rules   []Rule
	tracker *lineage.LineageTracker
}

// NewEngine initializes the detection engine with standard deterministic rules.
func NewEngine(tracker *lineage.LineageTracker) *Engine {
	e := &Engine{
		tracker: tracker,
	}
	e.RegisterRule(&ContainerEscapeRule{})
	e.RegisterRule(&WritableDirExecutionRule{})
	e.RegisterRule(&InteractiveShellRule{})
	return e
}

// RegisterRule appends a rule to the engine.
func (e *Engine) RegisterRule(r Rule) {
	e.rules = append(e.rules, r)
}

// Evaluate evaluates all rules against an event.
func (e *Engine) Evaluate(event *telemetry.SecurityEvent) []*Alert {
	var alerts []*Alert
	for _, rule := range e.rules {
		if alert := rule.Evaluate(event, e.tracker); alert != nil {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// ContainerEscapeRule detects binaries frequently used for container namespace escapes.
type ContainerEscapeRule struct{}

func (r *ContainerEscapeRule) ID() string { return "CG-RULE-001" }

func (r *ContainerEscapeRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	// Only alert on containerized processes, ignore confirmed host actions
	if event.State != telemetry.AttributionResolved && event.State != telemetry.AttributionPending {
		return nil
	}

	exec := event.Filename
	suspicious := []string{"nsenter", "unshare", "capsh", "chroot", "modprobe", "insmod"}

	for _, s := range suspicious {
		if strings.HasSuffix(exec, "/"+s) || exec == s {
			chain := ""
			if tracker != nil {
				node, _ := tracker.GetProcess(event.Key)
				if node == nil {
					node, _ = tracker.FindProcessByTGID(event.CgroupID, event.TGID)
				}
				chain = tracker.FormatChain(node)
			}

			return &Alert{
				ID:          fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
				RuleID:      r.ID(),
				Title:       "Privileged Container Breakout Utility Executed",
				Description: fmt.Sprintf("Process executed utility '%s' often associated with namespace manipulation or privilege escalation", s),
				Severity:    SeverityCritical,
				Timestamp:   event.CapturedAt,
				Event:       event,
				Lineage:     chain,
			}
		}
	}

	return nil
}

// WritableDirExecutionRule detects execution from writable/temporary directories inside containers.
type WritableDirExecutionRule struct{}

func (r *WritableDirExecutionRule) ID() string { return "CG-RULE-002" }

func (r *WritableDirExecutionRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if event.State != telemetry.AttributionResolved {
		return nil
	}

	exec := event.Filename
	writableDirs := []string{"/tmp/", "/dev/shm/", "/var/tmp/"}

	for _, d := range writableDirs {
		if strings.HasPrefix(exec, d) {
			return &Alert{
				ID:          fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
				RuleID:      r.ID(),
				Title:       "Execution From Writable Directory",
				Description: fmt.Sprintf("Executable launched from writable memory/temp mount '%s'", exec),
				Severity:    SeverityHigh,
				Timestamp:   event.CapturedAt,
				Event:       event,
			}
		}
	}

	return nil
}

// ContainerShellRule detects shell binaries spawned inside a production container.
// Note: Intercepts binary path execution; terminal interactivity (pty/tty or -i) is not evaluated in 50% milestone.
type ContainerShellRule struct{}

// InteractiveShellRule is maintained as an alias for backward compatibility.
type InteractiveShellRule = ContainerShellRule

func (r *ContainerShellRule) ID() string { return "CG-RULE-003" }

func (r *ContainerShellRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if event.State != telemetry.AttributionResolved {
		return nil
	}

	exec := event.Filename
	shells := []string{"/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "/bin/zsh"}

	for _, s := range shells {
		if exec == s {
			return &Alert{
				ID:          fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
				RuleID:      r.ID(),
				Title:       "Shell Binary Executed Inside Container",
				Description: fmt.Sprintf("Shell binary '%s' executed in container %s (detects shell binary execution; terminal interactivity not evaluated)", s, event.ContainerName),
				Severity:    SeverityMedium,
				Timestamp:   event.CapturedAt,
				Event:       event,
			}
		}
	}

	return nil
}
