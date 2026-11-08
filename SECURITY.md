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
   - **GitHub Private Vulnerability Advisory:** If enabled on the repository, navigate to the **Security** tab $\to$ **Report a vulnerability** under `ramKarthik57/containerguard`.
   - **Direct Maintainer Contact:** If GitHub Private Vulnerability Reporting is unavailable, send disclosure details to the repository maintainer at `76729402+ramKarthik57@users.noreply.github.com` (with subject prefix `[ContainerGuard Security Advisory]`) or coordinate confidential disclosure via the GitHub profile [ramKarthik57](https://github.com/ramKarthik57).
3. Provide:
   - Detailed description of the vulnerability and attack vector.
   - Host environment details (kernel version, cgroup mode, Docker version).
   - Minimal reproduction script or proof of concept.
   - Proposed remediation, if known.

We will acknowledge receipt of the report, assess the technical impact, and prepare a coordinated fix.
