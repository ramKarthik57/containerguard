package detection

import (
	"fmt"
	"testing"
	"time"

	"cg-smoke-test/internal/lineage"
	"cg-smoke-test/internal/telemetry"
)

// TestFalsePositiveEvaluationCorpus evaluates a rigorous 133-event benchmark:
// 120 Benign Events (developer commands, container healthchecks, web servers, routine diagnostics)
// 13 Adversarial Events (covering CG-RULE-001 through CG-RULE-007)
// Verifies:
// - False Positive Rate (FPR) = 0.00%
// - True Positive Rate (TPR) = 100.00%
// - Precision = 1.000, Recall = 1.000, F1-Score = 1.000
func TestFalsePositiveEvaluationCorpus(t *testing.T) {
	tracker := lineage.NewLineageTracker(1000, 5*time.Minute)
	engine := NewEngine(tracker)

	// 120 Benign container workloads across common production software
	benignCommands := []struct {
		filename string
		comm     string
	}{
		// Web servers & runtimes
		{"/usr/sbin/nginx", "nginx"},
		{"/usr/local/bin/node", "node"},
		{"/usr/bin/python3", "python3"},
		{"/usr/lib/jvm/java-17-openjdk/bin/java", "java"},
		{"/usr/bin/ruby", "ruby"},
		{"/usr/local/bin/php-fpm", "php-fpm"},
		{"/usr/bin/envoy", "envoy"},
		{"/usr/local/bin/traefik", "traefik"},
		{"/usr/bin/redis-server", "redis-server"},
		{"/usr/bin/postgres", "postgres"},
		{"/usr/sbin/mysqld", "mysqld"},
		{"/usr/bin/mongod", "mongod"},

		// Container healthchecks & network tools (routinely invoked by Docker/Kubernetes)
		{"/usr/bin/curl", "curl"},
		{"/usr/bin/wget", "wget"},
		{"/bin/ip", "ip"},
		{"/sbin/ip", "ip"},
		{"/bin/ss", "ss"},
		{"/usr/bin/ss", "ss"},
		{"/bin/netstat", "netstat"},
		{"/usr/bin/netstat", "netstat"},
		{"/usr/bin/dig", "dig"},
		{"/usr/bin/nslookup", "nslookup"},
		{"/usr/bin/ping", "ping"},
		{"/bin/hostname", "hostname"},
		{"/bin/cat", "cat"},
		{"/bin/echo", "echo"},
		{"/bin/date", "date"},
		{"/usr/bin/uptime", "uptime"},
		{"/usr/bin/grep", "grep"},
		{"/usr/bin/awk", "awk"},
		{"/usr/bin/sed", "sed"},
		{"/bin/sleep", "sleep"},
		{"/usr/bin/jq", "jq"},

		// Package managers & build tools
		{"/usr/bin/apt-get", "apt-get"},
		{"/usr/bin/dpkg", "dpkg"},
		{"/usr/bin/yum", "yum"},
		{"/sbin/apk", "apk"},
		{"/usr/bin/git", "git"},
		{"/usr/bin/make", "make"},
		{"/usr/bin/gcc", "gcc"},
		{"/usr/bin/pip", "pip"},
		{"/usr/local/bin/npm", "npm"},
		{"/usr/local/bin/yarn", "yarn"},
		{"/usr/bin/bundle", "bundle"},
		{"/usr/bin/cargo", "cargo"},

		// Core utilities
		{"/bin/ls", "ls"},
		{"/bin/cp", "cp"},
		{"/bin/mv", "mv"},
		{"/bin/rm", "rm"},
		{"/bin/mkdir", "mkdir"},
		{"/bin/rmdir", "rmdir"},
		{"/bin/chmod", "chmod"},
		{"/bin/chown", "chown"},
		{"/bin/tar", "tar"},
		{"/usr/bin/gzip", "gzip"},
		{"/usr/bin/bzip2", "bzip2"},
		{"/usr/bin/xz", "xz"},
		{"/usr/bin/unzip", "unzip"},
		{"/usr/bin/find", "find"},
		{"/usr/bin/sort", "sort"},
		{"/usr/bin/uniq", "uniq"},
		{"/usr/bin/wc", "wc"},
		{"/usr/bin/head", "head"},
		{"/usr/bin/tail", "tail"},
		{"/usr/bin/tr", "tr"},
		{"/usr/bin/cut", "cut"},
		{"/usr/bin/which", "which"},
		{"/usr/bin/id", "id"},
		{"/usr/bin/whoami", "whoami"},
		{"/bin/df", "df"},
		{"/usr/bin/du", "du"},
		{"/bin/free", "free"},
		{"/bin/ps", "ps"},
		{"/usr/bin/top", "top"},
		{"/usr/bin/htop", "htop"},
		{"/usr/bin/vmstat", "vmstat"},
		{"/usr/bin/iostat", "iostat"},
		{"/usr/bin/mpstat", "mpstat"},
		{"/usr/bin/sar", "sar"},
		{"/usr/bin/strace", "strace"},
		{"/usr/bin/lsof", "lsof"},
		{"/bin/sync", "sync"},
		{"/bin/true", "true"},
		{"/bin/false", "false"},
		{"/usr/bin/yes", "yes"},
		{"/usr/bin/env", "env"},
		{"/usr/bin/printenv", "printenv"},
		{"/usr/bin/basename", "basename"},
		{"/usr/bin/dirname", "dirname"},
		{"/usr/bin/readlink", "readlink"},
		{"/usr/bin/realpath", "realpath"},
		{"/usr/bin/stat", "stat"},
		{"/usr/bin/touch", "touch"},
		{"/usr/bin/diff", "diff"},
		{"/usr/bin/patch", "patch"},
		{"/usr/bin/tee", "tee"},
		{"/usr/bin/xargs", "xargs"},
		{"/usr/bin/seq", "seq"},
		{"/usr/bin/expr", "expr"},
		{"/usr/bin/test", "test"},
		{"/usr/bin/printf", "printf"},
		{"/usr/bin/sha256sum", "sha256sum"},
		{"/usr/bin/md5sum", "md5sum"},
		{"/usr/bin/base64", "base64"},
		{"/usr/bin/openssl", "openssl"},
		{"/usr/bin/ssh-keygen", "ssh-keygen"},
		{"/usr/bin/gpg", "gpg"},
		{"/usr/bin/supervisor", "supervisord"},
		{"/usr/bin/tini", "tini"},
		{"/usr/local/bin/dumb-init", "dumb-init"},
		{"/usr/bin/gunicorn", "gunicorn"},
		{"/usr/bin/uwsgi", "uwsgi"},
		{"/usr/local/bin/celery", "celery"},
		{"/usr/bin/crond", "crond"},
		{"/usr/sbin/rsyslogd", "rsyslogd"},
		{"/usr/bin/logrotate", "logrotate"},
		{"/usr/sbin/cron", "cron"},
		{"/usr/bin/tailscale", "tailscale"},
		{"/usr/bin/cilium", "cilium"},
		{"/usr/bin/flannel", "flannel"},
	}

	totalBenign := len(benignCommands)
	falsePositives := 0

	for i, cmd := range benignCommands {
		ev := &telemetry.SecurityEvent{
			State:         telemetry.AttributionResolved,
			Filename:      cmd.filename,
			Comm:          cmd.comm,
			SeqNum:        uint64(i + 1),
			CapturedAt:    time.Now(),
			CgroupID:      1000 + uint64(i),
			TGID:          20000 + uint32(i),
			UID:           1000,
			EUID:          1000,
			ContainerID:   "cont-benign-app",
			ContainerName: "prod-web-frontend",
		}
		tracker.RecordExec(ev)
		alerts := engine.Evaluate(ev)
		if len(alerts) > 0 {
			falsePositives++
			t.Errorf("False positive triggered on benign command %s: %s (Rule: %s)", cmd.filename, alerts[0].Title, alerts[0].RuleID)
		}
	}

	// 13 Adversarial Events across Rules 001 - 007
	type attackVector struct {
		name         string
		event        *telemetry.SecurityEvent
		expectedRule string
	}

	attacks := []attackVector{
		{
			name: "CG-RULE-001: nsenter container escape",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/usr/bin/nsenter",
				Comm:          "nsenter",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-001",
		},
		{
			name: "CG-RULE-001: unshare container breakout",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/usr/bin/unshare",
				Comm:          "unshare",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-001",
		},
		{
			name: "CG-RULE-001: capsh privilege modification",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/usr/sbin/capsh",
				Comm:          "capsh",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-001",
		},
		{
			name: "CG-RULE-002: execution from /tmp",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/tmp/dropper.elf",
				Comm:          "dropper.elf",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-002",
		},
		{
			name: "CG-RULE-002: execution from /dev/shm",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/dev/shm/rootkit",
				Comm:          "rootkit",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-002",
		},
		{
			name: "CG-RULE-003: interactive /bin/sh shell",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/bin/sh",
				Comm:          "sh",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-003",
		},
		{
			name: "CG-RULE-003: interactive /bin/bash shell",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/bin/bash",
				Comm:          "bash",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-003",
		},
		{
			name: "CG-RULE-004: setuid passwd escalation",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/usr/bin/passwd",
				Comm:          "passwd",
				UID:           1000,
				EUID:          0,
				SetuidExec:    true,
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-004",
		},
		{
			name: "CG-RULE-004: setuid su privilege escalation",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/bin/su",
				Comm:          "su",
				UID:           1000,
				EUID:          0,
				SetuidExec:    true,
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-004",
		},
		{
			name: "CG-RULE-005: fileless execution via AT_EMPTY_PATH",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "memfd:revshell",
				Comm:          "revshell",
				AtEmptyPath:   true,
				Dfd:           7,
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-005",
		},
		{
			name: "CG-RULE-006: nmap port sweep",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/usr/bin/nmap",
				Comm:          "nmap",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-006",
		},
		{
			name: "CG-RULE-006: tcpdump sniffing",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/usr/sbin/tcpdump",
				Comm:          "tcpdump",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-006",
		},
		{
			name: "CG-RULE-007: anti-forensic shredding",
			event: &telemetry.SecurityEvent{
				State:         telemetry.AttributionResolved,
				Filename:      "/usr/bin/shred",
				Comm:          "shred",
				ContainerID:   "cont-victim",
				ContainerName: "victim-container",
			},
			expectedRule: "CG-RULE-007",
		},
	}

	truePositives := 0
	for i, attack := range attacks {
		attack.event.SeqNum = uint64(5000 + i)
		attack.event.CapturedAt = time.Now()
		tracker.RecordExec(attack.event)
		alerts := engine.Evaluate(attack.event)
		if len(alerts) == 0 {
			t.Errorf("Failed to detect attack: %s", attack.name)
			continue
		}

		matched := false
		for _, a := range alerts {
			if a.RuleID == attack.expectedRule {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("Attack %s triggered alert %s, expected %s", attack.name, alerts[0].RuleID, attack.expectedRule)
		} else {
			truePositives++
		}
	}

	// Statistical Metrics Verification
	totalAttacks := len(attacks)
	totalCorpus := totalBenign + totalAttacks
	fpr := float64(falsePositives) / float64(totalBenign)
	tpr := float64(truePositives) / float64(totalAttacks)
	precision := float64(truePositives) / float64(truePositives+falsePositives)
	recall := tpr
	f1 := 2 * (precision * recall) / (precision + recall)

	fmt.Printf("\n=== ContainerGuard False-Positive Benchmark (133-Event Corpus) ===\n")
	fmt.Printf("Total Evaluated Events:  %d\n", totalCorpus)
	fmt.Printf("Benign Events:          %d (FP: %d, TN: %d)\n", totalBenign, falsePositives, totalBenign-falsePositives)
	fmt.Printf("Adversarial Events:     %d (TP: %d, FN: %d)\n", totalAttacks, truePositives, totalAttacks-truePositives)
	fmt.Printf("False Positive Rate (FPR): %.2f%%\n", fpr*100.0)
	fmt.Printf("True Positive Rate (TPR):  %.2f%%\n", tpr*100.0)
	fmt.Printf("Precision:                 %.4f\n", precision)
	fmt.Printf("Recall:                    %.4f\n", recall)
	fmt.Printf("F1-Score:                  %.4f\n", f1)
	fmt.Printf("===================================================================\n\n")

	if falsePositives != 0 {
		t.Fatalf("Benchmark failed: False Positive Rate must be 0.00%%, got %.2f%% (%d/%d)", fpr*100.0, falsePositives, totalBenign)
	}
	if truePositives != totalAttacks {
		t.Fatalf("Benchmark failed: True Positive Rate must be 100.00%%, got %.2f%% (%d/%d)", tpr*100.0, truePositives, totalAttacks)
	}
}
