# Security Policy

## Supported Versions

ContainerGuard is a research engineering project currently maintained at the **50% Verified Milestone**.

| Version / Milestone | Supported | Commit Checkpoint |
| :--- | :---: | :--- |
| **ContainerGuard 50% Verified Milestone** | :white_check_mark: | `b8f70f5f614a8927278ea031ff9c338791c40f01` |
| Earlier prototype tags (e.g. Phase F/H) | :x: | Replaced by 50% milestone |

---

## Reporting a Vulnerability

The ContainerGuard project takes security vulnerabilities seriously.

If you identify a security defect, kernel panic vulnerability, permission escalation flaw, or telemetry bypass vulnerability:

1. **Do not create a public GitHub issue.**
2. Report the vulnerability privately:
   - **GitHub Private Vulnerability Advisory (Primary Channel):** Navigate to the **Security** tab $\to$ **Advisories** $\to$ **Report a vulnerability** under `ramKarthik57/containerguard`. This provides an encrypted, authenticated, and access-controlled disclosure workflow directly with repository maintainers.
   - **Confidential Maintainer Contact (Fallback):** If GitHub Private Vulnerability Reporting is unavailable, coordinate confidential disclosure directly with the repository owner via GitHub profile [ramKarthik57](https://github.com/ramKarthik57) to establish an encrypted exchange channel prior to transmitting technical vulnerability details. Do not submit sensitive vulnerability payloads to public issues, discussions, or unverified noreply commit aliases.
3. Provide:
   - Detailed description of the vulnerability and attack vector.
   - Host environment details (kernel version, cgroup mode, Docker version).
   - Minimal reproduction script or proof of concept.
   - Proposed remediation, if known.

We will acknowledge receipt of the report, assess the technical impact, and prepare a coordinated fix.
