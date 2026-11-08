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
   - **Encrypted Coordination:** For sensitive vulnerability reports, proof-of-concept exploits, or potential kernel-safety defects, coordinate confidential PGP encrypted communication with the maintainer prior to transmitting raw exploit materials. The maintainer will provide their PGP public key upon initial email outreach before sensitive artifacts are transferred.
   - **Repository Visibility Context:** This repository is currently hosted as a private research project. GitHub Private Vulnerability Reporting (`Security` → `Advisories` → `Report a vulnerability`) is a platform feature that can be enabled if and when the repository visibility is transitioned to public; until that time, direct email intake via `ramkarthik57@gmail.com` serves as the primary, monitored disclosure mechanism.

3. **Required Information in Disclosures:**
   - Detailed description of the vulnerability and attack vector.
   - Host environment details (Linux kernel version, cgroup mode, Docker runtime version).
   - Minimal reproduction script or proof of concept.
   - Proposed remediation or mitigation, if known.

We will acknowledge receipt within 48 hours, evaluate the technical impact against the 50% milestone architecture, and coordinate coordinated disclosure.
