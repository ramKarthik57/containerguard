package detection

import (
	"testing"
	"time"

	"cg-smoke-test/internal/lineage"
	"cg-smoke-test/internal/policy"
	"cg-smoke-test/internal/telemetry"
)

func TestDetectionRules(t *testing.T) {
	tracker := lineage.NewLineageTracker(100, 1*time.Minute)
	engine := NewEngine(tracker)

	// 1. Host confirmed event executing nsenter should NOT trigger container breakout alert
	hostEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionHostConfirmed,
		Filename:      "/usr/bin/nsenter",
		Comm:          "nsenter",
		SeqNum:        1,
		CapturedAt:    time.Now(),
		ContainerID:   "host",
		ContainerName: "HOST",
	}
	alerts := engine.Evaluate(hostEv)
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts for host event, got %d", len(alerts))
	}

	// 2. Container event executing nsenter SHOULD trigger CRITICAL alert (Rule 001)
	contEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/usr/bin/nsenter",
		Comm:          "nsenter",
		SeqNum:        2,
		CapturedAt:    time.Now(),
		CgroupID:      400,
		TGID:          1234,
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	tracker.RecordExec(contEv)
	alerts = engine.Evaluate(contEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for container nsenter, got %d", len(alerts))
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", alerts[0].Severity)
	}
	if len(alerts[0].MitreTechniques) == 0 {
		t.Errorf("expected MITRE ATT&CK techniques, got none")
	}

	// 3. Container executing script from /tmp (Rule 002)
	tmpEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/tmp/exploit.sh",
		Comm:          "exploit.sh",
		SeqNum:        3,
		CapturedAt:    time.Now(),
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	alerts = engine.Evaluate(tmpEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for /tmp execution, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CG-RULE-002" {
		t.Errorf("expected rule CG-RULE-002, got %s", alerts[0].RuleID)
	}

	// 4. Container executing /bin/sh triggers CG-RULE-003
	shEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/bin/sh",
		Comm:          "sh",
		SeqNum:        4,
		CapturedAt:    time.Now(),
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	alerts = engine.Evaluate(shEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for /bin/sh execution, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CG-RULE-003" {
		t.Errorf("expected rule CG-RULE-003, got %s", alerts[0].RuleID)
	}

	// 5. Setuid execution triggers CG-RULE-004
	setuidEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/usr/bin/passwd",
		Comm:          "passwd",
		SeqNum:        5,
		CapturedAt:    time.Now(),
		UID:           1000,
		EUID:          0,
		SetuidExec:    true,
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	alerts = engine.Evaluate(setuidEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for setuid execution, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CG-RULE-004" {
		t.Errorf("expected rule CG-RULE-004, got %s", alerts[0].RuleID)
	}

	// 6. Fileless execution triggers CG-RULE-005
	filelessEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "memfd:payload",
		Comm:          "payload",
		SeqNum:        6,
		CapturedAt:    time.Now(),
		AtEmptyPath:   true,
		AtFlags:       0x1000,
		Dfd:           5,
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	alerts = engine.Evaluate(filelessEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for fileless execution, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CG-RULE-005" {
		t.Errorf("expected rule CG-RULE-005, got %s", alerts[0].RuleID)
	}

	// 7. Reconnaissance triggers CG-RULE-006
	reconEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/usr/bin/nmap",
		Comm:          "nmap",
		SeqNum:        7,
		CapturedAt:    time.Now(),
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	alerts = engine.Evaluate(reconEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for nmap execution, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CG-RULE-006" {
		t.Errorf("expected rule CG-RULE-006, got %s", alerts[0].RuleID)
	}

	// 8. Defense evasion triggers CG-RULE-007
	evasionEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/usr/bin/shred",
		Comm:          "shred",
		SeqNum:        8,
		CapturedAt:    time.Now(),
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}
	alerts = engine.Evaluate(evasionEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for shred execution, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CG-RULE-007" {
		t.Errorf("expected rule CG-RULE-007, got %s", alerts[0].RuleID)
	}
}

func TestConfigureFromPolicy(t *testing.T) {
	tracker := lineage.NewLineageTracker(100, 1*time.Minute)
	engine := NewEngine(tracker)

	cfg := &policy.Config{
		Rules: []policy.RuleDefinition{
			{
				ID:               "CUSTOM-001",
				Name:             "Custom Cryptominer Detect",
				Description:      "Detects xmrig miner",
				Severity:         "CRITICAL",
				Enabled:          true,
				MitigationAction: "kill",
				MitreAttack:      []string{"T1496"},
				Conditions: policy.RuleConditions{
					MatchBinaries: []string{"xmrig", "minerd"},
					ContainerOnly: true,
				},
			},
		},
	}

	engine.ConfigureFromPolicy(cfg)

	minerEv := &telemetry.SecurityEvent{
		State:         telemetry.AttributionResolved,
		Filename:      "/opt/xmrig",
		Comm:          "xmrig",
		SeqNum:        10,
		CapturedAt:    time.Now(),
		ContainerID:   "cont-target",
		ContainerName: "target-container",
	}

	alerts := engine.Evaluate(minerEv)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert from custom policy rule, got %d", len(alerts))
	}
	if alerts[0].RuleID != "CUSTOM-001" {
		t.Errorf("expected CUSTOM-001, got %s", alerts[0].RuleID)
	}
	if alerts[0].MitigationAction != "kill" {
		t.Errorf("expected kill action, got %s", alerts[0].MitigationAction)
	}
}
