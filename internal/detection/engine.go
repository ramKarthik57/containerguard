package detection

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"cg-smoke-test/internal/lineage"
	"cg-smoke-test/internal/policy"
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

// Alert represents a deterministic detection alert enriched with threat context.
type Alert struct {
	ID               string                   `json:"id"`
	RuleID           string                   `json:"rule_id"`
	Title            string                   `json:"title"`
	Description      string                   `json:"description"`
	Severity         Severity                 `json:"severity"`
	MitigationAction string                   `json:"mitigation_action,omitempty"`
	MitreTechniques  []string                 `json:"mitre_techniques,omitempty"`
	Timestamp        time.Time                `json:"timestamp"`
	Event            *telemetry.SecurityEvent `json:"event"`
	Lineage          string                   `json:"lineage,omitempty"`
}

// Rule defines the interface for deterministic intrusion detection checks.
type Rule interface {
	ID() string
	Name() string
	Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert
}

// Engine evaluates deterministic rules against telemetry events.
type Engine struct {
	mu      sync.RWMutex
	rules   []Rule
	tracker *lineage.LineageTracker
}

// NewEngine initializes the detection engine with standard deterministic rules.
func NewEngine(tracker *lineage.LineageTracker) *Engine {
	e := &Engine{
		tracker: tracker,
	}
	// Register full Phase I + Phase II rule suite
	e.RegisterRule(&ContainerEscapeRule{})
	e.RegisterRule(&WritableDirExecutionRule{})
	e.RegisterRule(&ContainerShellRule{})
	e.RegisterRule(&SetuidExecutionRule{})
	e.RegisterRule(&FilelessExecutionRule{})
	e.RegisterRule(&ReconnaissanceRule{})
	e.RegisterRule(&DefenseEvasionRule{})
	return e
}

// RegisterRule appends a rule to the engine.
func (e *Engine) RegisterRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// SetRules cleanly replaces the current rule set (e.g. on policy reload).
func (e *Engine) SetRules(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// ConfigureFromPolicy updates the rule set based on dynamic policy definitions.
func (e *Engine) ConfigureFromPolicy(cfg *policy.Config) {
	if cfg == nil || len(cfg.Rules) == 0 {
		return
	}

	var newRules []Rule
	for _, rd := range cfg.Rules {
		if !rd.Enabled {
			continue
		}
		switch rd.ID {
		case "CG-RULE-001":
			newRules = append(newRules, &ContainerEscapeRule{
				CustomAction: rd.MitigationAction,
				CustomMitre:  rd.MitreAttack,
			})
		case "CG-RULE-002":
			newRules = append(newRules, &WritableDirExecutionRule{
				CustomAction: rd.MitigationAction,
				CustomMitre:  rd.MitreAttack,
				CustomPaths:  rd.Conditions.PathPrefixes,
			})
		case "CG-RULE-003":
			newRules = append(newRules, &ContainerShellRule{
				CustomAction: rd.MitigationAction,
				CustomMitre:  rd.MitreAttack,
				CustomShells: rd.Conditions.MatchBinaries,
			})
		case "CG-RULE-004":
			newRules = append(newRules, &SetuidExecutionRule{
				CustomAction: rd.MitigationAction,
				CustomMitre:  rd.MitreAttack,
			})
		case "CG-RULE-005":
			newRules = append(newRules, &FilelessExecutionRule{
				CustomAction: rd.MitigationAction,
				CustomMitre:  rd.MitreAttack,
			})
		case "CG-RULE-006":
			newRules = append(newRules, &ReconnaissanceRule{
				CustomAction:   rd.MitigationAction,
				CustomMitre:    rd.MitreAttack,
				CustomBinaries: rd.Conditions.MatchBinaries,
			})
		case "CG-RULE-007":
			newRules = append(newRules, &DefenseEvasionRule{
				CustomAction:   rd.MitigationAction,
				CustomMitre:    rd.MitreAttack,
				CustomBinaries: rd.Conditions.MatchBinaries,
			})
		default:
			// Generic custom declarative rule
			newRules = append(newRules, NewDynamicRule(rd))
		}
	}

	e.SetRules(newRules)
}

// Evaluate evaluates all active rules against an event.
func (e *Engine) Evaluate(event *telemetry.SecurityEvent) []*Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var alerts []*Alert
	for _, rule := range e.rules {
		if alert := rule.Evaluate(event, e.tracker); alert != nil {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// =========================================================================
// RULE 001: Container Breakout Utilities
// =========================================================================

type ContainerEscapeRule struct {
	CustomAction string
	CustomMitre  []string
}

func (r *ContainerEscapeRule) ID() string   { return "CG-RULE-001" }
func (r *ContainerEscapeRule) Name() string { return "Privileged Container Breakout Utility Executed" }

func (r *ContainerEscapeRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
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

			action := "kill"
			if r.CustomAction != "" {
				action = r.CustomAction
			}
			mitre := []string{"T1611", "T1068"}
			if len(r.CustomMitre) > 0 {
				mitre = r.CustomMitre
			}

			return &Alert{
				ID:               fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
				RuleID:           r.ID(),
				Title:            r.Name(),
				Description:      fmt.Sprintf("Process executed breakout utility '%s' associated with namespace manipulation or privilege escalation", s),
				Severity:         SeverityCritical,
				MitigationAction: action,
				MitreTechniques:  mitre,
				Timestamp:        event.CapturedAt,
				Event:            event,
				Lineage:          chain,
			}
		}
	}
	return nil
}

// =========================================================================
// RULE 002: Writable Directory Execution
// =========================================================================

type WritableDirExecutionRule struct {
	CustomAction string
	CustomMitre  []string
	CustomPaths  []string
}

func (r *WritableDirExecutionRule) ID() string   { return "CG-RULE-002" }
func (r *WritableDirExecutionRule) Name() string { return "Execution From Writable Directory" }

func (r *WritableDirExecutionRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if event.State != telemetry.AttributionResolved {
		return nil
	}

	exec := event.Filename
	writableDirs := []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/"}
	if len(r.CustomPaths) > 0 {
		writableDirs = r.CustomPaths
	}

	for _, d := range writableDirs {
		if strings.HasPrefix(exec, d) {
			action := "kill"
			if r.CustomAction != "" {
				action = r.CustomAction
			}
			mitre := []string{"T1059", "T1543"}
			if len(r.CustomMitre) > 0 {
				mitre = r.CustomMitre
			}

			return &Alert{
				ID:               fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
				RuleID:           r.ID(),
				Title:            r.Name(),
				Description:      fmt.Sprintf("Executable launched from writable memory/temp mount '%s'", exec),
				Severity:         SeverityHigh,
				MitigationAction: action,
				MitreTechniques:  mitre,
				Timestamp:        event.CapturedAt,
				Event:            event,
			}
		}
	}
	return nil
}

// =========================================================================
// RULE 003: Container Shell Ingress
// =========================================================================

type ContainerShellRule struct {
	CustomAction string
	CustomMitre  []string
	CustomShells []string
}

type InteractiveShellRule = ContainerShellRule

func (r *ContainerShellRule) ID() string   { return "CG-RULE-003" }
func (r *ContainerShellRule) Name() string { return "Interactive Container Shell Ingress" }

func (r *ContainerShellRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if event.State != telemetry.AttributionResolved {
		return nil
	}

	exec := event.Filename
	shells := []string{"/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "/bin/zsh"}
	if len(r.CustomShells) > 0 {
		shells = r.CustomShells
	}

	for _, s := range shells {
		if exec == s || strings.HasSuffix(exec, "/"+s) {
			action := "alert"
			if r.CustomAction != "" {
				action = r.CustomAction
			}
			mitre := []string{"T1059.004"}
			if len(r.CustomMitre) > 0 {
				mitre = r.CustomMitre
			}

			return &Alert{
				ID:               fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
				RuleID:           r.ID(),
				Title:            "Shell Binary Executed Inside Container",
				Description:      fmt.Sprintf("Shell binary '%s' executed in container %s", s, event.ContainerName),
				Severity:         SeverityMedium,
				MitigationAction: action,
				MitreTechniques:  mitre,
				Timestamp:        event.CapturedAt,
				Event:            event,
			}
		}
	}
	return nil
}

// =========================================================================
// RULE 004: Setuid Privilege Escalation Execution
// =========================================================================

type SetuidExecutionRule struct {
	CustomAction string
	CustomMitre  []string
}

func (r *SetuidExecutionRule) ID() string   { return "CG-RULE-004" }
func (r *SetuidExecutionRule) Name() string { return "Setuid Privilege Escalation Execution" }

func (r *SetuidExecutionRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if event.State != telemetry.AttributionResolved {
		return nil
	}

	// Flag SetuidExec or EUID != UID
	isSetuid := event.SetuidExec || (event.Raw.Flags&(1<<9) != 0) || (event.EUID != event.UID && event.EUID == 0)
	if !isSetuid {
		return nil
	}

	action := "freeze"
	if r.CustomAction != "" {
		action = r.CustomAction
	}
	mitre := []string{"T1548.001"}
	if len(r.CustomMitre) > 0 {
		mitre = r.CustomMitre
	}

	return &Alert{
		ID:               fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
		RuleID:           r.ID(),
		Title:            r.Name(),
		Description:      fmt.Sprintf("Process executed with elevated effective credentials (UID: %d -> EUID: %d)", event.UID, event.EUID),
		Severity:         SeverityCritical,
		MitigationAction: action,
		MitreTechniques:  mitre,
		Timestamp:        event.CapturedAt,
		Event:            event,
	}
}

// =========================================================================
// RULE 005: Fileless In-Memory Execution (memfd / execveat AT_EMPTY_PATH)
// =========================================================================

type FilelessExecutionRule struct {
	CustomAction string
	CustomMitre  []string
}

func (r *FilelessExecutionRule) ID() string   { return "CG-RULE-005" }
func (r *FilelessExecutionRule) Name() string { return "Fileless In-Memory Execution" }

func (r *FilelessExecutionRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if event.State != telemetry.AttributionResolved && event.State != telemetry.AttributionPending {
		return nil
	}

	// Flag AtEmptyPath or ATFlags & 0x1000
	isFileless := event.AtEmptyPath || (event.Raw.Flags&(1<<5) != 0) || (event.AtFlags&0x1000 != 0)
	if !isFileless {
		return nil
	}

	action := "kill"
	if r.CustomAction != "" {
		action = r.CustomAction
	}
	mitre := []string{"T1620", "T1059"}
	if len(r.CustomMitre) > 0 {
		mitre = r.CustomMitre
	}

	return &Alert{
		ID:               fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
		RuleID:           r.ID(),
		Title:            r.Name(),
		Description:      fmt.Sprintf("Execution invoked fileless via execveat with AT_EMPTY_PATH (dfd: %d, binary: %s)", event.Dfd, event.Filename),
		Severity:         SeverityHigh,
		MitigationAction: action,
		MitreTechniques:  mitre,
		Timestamp:        event.CapturedAt,
		Event:            event,
	}
}

// =========================================================================
// RULE 006: Anomalous Reconnaissance & Discovery Utilities
// =========================================================================

type ReconnaissanceRule struct {
	CustomAction   string
	CustomMitre    []string
	CustomBinaries []string
}

func (r *ReconnaissanceRule) ID() string   { return "CG-RULE-006" }
func (r *ReconnaissanceRule) Name() string { return "Reconnaissance & Discovery Utilities" }

func (r *ReconnaissanceRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if event.State != telemetry.AttributionResolved {
		return nil
	}

	exec := event.Filename
	reconBinaries := []string{"nmap", "tcpdump", "arp-scan", "masscan", "zmap"}
	if len(r.CustomBinaries) > 0 {
		reconBinaries = r.CustomBinaries
	}

	for _, b := range reconBinaries {
		if strings.HasSuffix(exec, "/"+b) || exec == b || event.Comm == b {
			action := "alert"
			if r.CustomAction != "" {
				action = r.CustomAction
			}
			mitre := []string{"T1046", "T1018"}
			if len(r.CustomMitre) > 0 {
				mitre = r.CustomMitre
			}

			return &Alert{
				ID:               fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
				RuleID:           r.ID(),
				Title:            r.Name(),
				Description:      fmt.Sprintf("Network reconnaissance / system discovery binary '%s' invoked in container %s", b, event.ContainerName),
				Severity:         SeverityMedium,
				MitigationAction: action,
				MitreTechniques:  mitre,
				Timestamp:        event.CapturedAt,
				Event:            event,
			}
		}
	}
	return nil
}

// =========================================================================
// RULE 007: Defense Evasion & History Tampering
// =========================================================================

type DefenseEvasionRule struct {
	CustomAction   string
	CustomMitre    []string
	CustomBinaries []string
}

func (r *DefenseEvasionRule) ID() string   { return "CG-RULE-007" }
func (r *DefenseEvasionRule) Name() string { return "Defense Evasion & History Tampering" }

func (r *DefenseEvasionRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if event.State != telemetry.AttributionResolved {
		return nil
	}

	exec := event.Filename
	evasionBinaries := []string{"shred", "wipefs", "srm"}
	if len(r.CustomBinaries) > 0 {
		evasionBinaries = r.CustomBinaries
	}

	for _, b := range evasionBinaries {
		if strings.HasSuffix(exec, "/"+b) || exec == b || event.Comm == b {
			action := "alert"
			if r.CustomAction != "" {
				action = r.CustomAction
			}
			mitre := []string{"T1070.003", "T1070.002"}
			if len(r.CustomMitre) > 0 {
				mitre = r.CustomMitre
			}

			return &Alert{
				ID:               fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.ID()),
				RuleID:           r.ID(),
				Title:            r.Name(),
				Description:      fmt.Sprintf("Potential defense evasion / anti-forensics tool '%s' invoked in container %s", b, event.ContainerName),
				Severity:         SeverityHigh,
				MitigationAction: action,
				MitreTechniques:  mitre,
				Timestamp:        event.CapturedAt,
				Event:            event,
			}
		}
	}
	return nil
}

// =========================================================================
// Dynamic Declarative Rule
// =========================================================================

type DynamicRule struct {
	def policy.RuleDefinition
}

func NewDynamicRule(def policy.RuleDefinition) *DynamicRule {
	return &DynamicRule{def: def}
}

func (r *DynamicRule) ID() string   { return r.def.ID }
func (r *DynamicRule) Name() string { return r.def.Name }

func (r *DynamicRule) Evaluate(event *telemetry.SecurityEvent, tracker *lineage.LineageTracker) *Alert {
	if r.def.Conditions.ContainerOnly {
		if event.State != telemetry.AttributionResolved && event.State != telemetry.AttributionPending {
			return nil
		}
	}

	for _, p := range r.def.Conditions.PathPrefixes {
		if strings.HasPrefix(event.Filename, p) {
			return r.buildAlert(event)
		}
	}

	for _, b := range r.def.Conditions.MatchBinaries {
		if strings.HasSuffix(event.Filename, "/"+b) || event.Filename == b || event.Comm == b {
			return r.buildAlert(event)
		}
	}

	if r.def.Conditions.RequireSetuidFlag && (event.SetuidExec || event.Raw.Flags&(1<<9) != 0 || event.EUID != event.UID) {
		return r.buildAlert(event)
	}

	if r.def.Conditions.RequireEmptyPathFlag && (event.AtEmptyPath || event.Raw.Flags&(1<<5) != 0 || event.AtFlags&0x1000 != 0) {
		return r.buildAlert(event)
	}

	return nil
}

func (r *DynamicRule) buildAlert(event *telemetry.SecurityEvent) *Alert {
	sev := SeverityMedium
	switch strings.ToUpper(r.def.Severity) {
	case "CRITICAL":
		sev = SeverityCritical
	case "HIGH":
		sev = SeverityHigh
	case "LOW":
		sev = SeverityLow
	}

	return &Alert{
		ID:               fmt.Sprintf("ALERT-%d-%s", event.SeqNum, r.def.ID),
		RuleID:           r.def.ID,
		Title:            r.def.Name,
		Description:      r.def.Description,
		Severity:         sev,
		MitigationAction: r.def.MitigationAction,
		MitreTechniques:  r.def.MitreAttack,
		Timestamp:        event.CapturedAt,
		Event:            event,
	}
}
