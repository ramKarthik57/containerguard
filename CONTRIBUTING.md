# Contributing to ContainerGuard

Thank you for your interest in the **ContainerGuard** research engineering project.

---

## 1. Project Phase & Scope Boundary

ContainerGuard is currently at its **50% Verified Milestone Checkpoint**.
- The core telemetry engine, eBPF tracepoints, attribution pipeline, and 50% acceptance components are **FROZEN**.
- **Phase II development is currently unauthorized.**
- Contributions at this stage are restricted to:
  1. Documentation clarifications and technical accuracy improvements.
  2. Reproducibility refinements and benchmark validation tooling.
  3. Safe CI and static verification scripts.
  4. Bug fixes in accepted 50% milestone components (must not alter accepted public APIs or introduce unverified features).

---

## 2. Contribution Workflow

1. **Fork or Branch:** Create a feature or documentation branch from `master` (e.g. `docs/clarify-ringbuf-capacity`).
2. **Commit Hygiene:** Follow conventional commit messages (`docs:`, `chore:`, `fix:`, `refactor:`). Never amend or rewrite historical release commits.
3. **Static Checks:** Ensure all Go code is formatted and vetted:
   ```bash
   gofmt -w .
   go vet ./...
   go test -v -race ./internal/...
   ```
4. **Pull Request:** Open a pull request using the provided [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md). Detail the rationale, changes made, and verification steps executed.

---

## 3. Code Standards & Behavioral Constraints

- **No Privilege Bypass:** Code changes must never circumvent permission checks, configure passwordless sudo, or compromise system security boundaries.
- **Documentation Integrity:** Preserve all existing comments, docstrings, and evidence references.
- **Honest Telemetry:** Never clamp, truncate, or adjust mathematical metrics to mask discrepancies. Maintain strict accounting conservation ($\text{Hooks} = \text{Submissions} + \text{Drops}$).
