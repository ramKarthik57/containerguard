# Security Policy

## Supported Versions

ContainerGuard is a research engineering project currently maintained at the **50% Verified Milestone**.

| Version / Milestone | Supported | Commit Checkpoint |
| :--- | :---: | :--- |
| **ContainerGuard 50% Verified Milestone** | :white_check_mark: | `b8f70f5f614a8927278ea031ff9c338791c40f01` |
| Earlier prototype tags (e.g. Phase F/H) | :x: | Replaced by 50% milestone |

---

## Reporting a Vulnerability

The ContainerGuard project takes security vulnerabilities and kernel safety seriously.

If you identify a security defect, kernel panic vulnerability, permission escalation flaw, or telemetry bypass vulnerability:

1. **Do not create a public GitHub issue or public discussion.**
2. **Confidential Reporting Channels:**
   - **Monitored Security Intake Mailbox:** Submit technical vulnerability reports directly to the maintainer security contact at **`ramkarthik57@gmail.com`** (please include `[ContainerGuard Security Advisory]` in the subject line).
   - **Encrypted Coordination:** For sensitive vulnerability reports, proof-of-concept exploits, or potential kernel-safety defects, coordinate confidential PGP encrypted communication with the repository maintainer via GitHub profile [ramKarthik57](https://github.com/ramKarthik57) before transmitting raw exploit materials.
   - **Repository Visibility Context:** This repository is currently hosted as a private research project. If and when the repository visibility is transitioned to public, GitHub Private Vulnerability Reporting (`Security` $\to$ `Advisories` $\to$ `Report a vulnerability`) will be configured and enabled as an integrated disclosure mechanism.

3. **Required Information in Disclosures:**
   - Detailed description of the vulnerability and attack vector.
   - Host environment details (Linux kernel version, cgroup mode, Docker runtime version).
   - Minimal reproduction script or proof of concept.
   - Proposed remediation or mitigation, if known.

We will acknowledge receipt within 48 hours, evaluate the technical impact against the 50% milestone architecture, and coordinate coordinated disclosure.
