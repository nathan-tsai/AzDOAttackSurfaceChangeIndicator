***THIS IS ONLY AN INDICATOR OF POTENTIAL ATTACK SURFACE CHANGES, NOT ACTUAL RISK EVALUATION, THIS IS ONLY TO ASSIST DEVELOPERS IN THE DESIGN/THREAT MODELING PHASE*

Continuous Threat Modeling Engine for Azure DevOps Pull Requests

This project implements a lightweight, iteration-aware threat modeling system for Azure DevOps pull requests. Its purpose is to provide visibility into potentially security-relevant architectural changes, not to calculate real security risk or exploitability. It is designed to signal shifts in the attack surface, helping reviewers focus on changes that may warrant human analysis.

What It Does

- Analyzes PR file changes
- Scans all files changed in the latest PR iteration.
- Identifies high-impact areas based on file path patterns, such as:

File path matches	Signal	Points
- auth, identity, rbac, permission, guard	Sensitive trust boundary modified	+2
- controller, routes, api	API surface changed	+1
- data, repository, dao	Data access layer modified	+1

Scores cumulative signals

- Adds points for each matching file.
- PRs with a score ≥ 2 trigger an advisory security impact section in the PR description.
- Crucially: The score represents only the presence and extent of architectural changes — it does not measure likelihood, impact, exploitability, or actual security risk.

Signals architectural surface changes only
- Highlights areas where the attack surface may have shifted.
- Does not perform a real threat model, risk calculation, or vulnerability verification.
- Comment changes, code logic, or runtime behavior are ignored — only file paths trigger signals.

Adds an advisory PR section
- Injects a collapsible <details> block summarizing observed signals.
- Developers can review, collapse, ignore, or delete the section freely.
- The section is informational only — it does not block builds, merges, or CI/CD pipelines.
- Automatically updates or removes the section on subsequent runs based on current PR changes.

Caches PR iteration IDs for efficiency
- Prevents rescanning unchanged PRs to reduce noise and API usage.

What It Does NOT Do
- Does not perform real threat modeling — it does not evaluate risk, likelihood, or potential exploitability.
- Does not detect actual vulnerabilities — SAST, DAST, or manual review is still required.
- Does not enforce security or permissions — it only flags potentially relevant areas.
- Does not parse code logic or runtime behavior — only file paths count.
- Does not impact developer workflows or CI/CD pipelines — advisory only.

Design Philosophy

- Surface-change signaling, not risk scoring: The engine exists to highlight potential attack surface changes for human review. It is a signal system, not a risk calculator.
- Lightweight and scalable: Works across all repositories and projects without repo-level modifications.
- Developer-friendly: Provides insight without creating noise or friction.
- Architecturally aware: Focuses on trust boundaries, API surfaces, and data access layers — areas where security-sensitive changes may occur.

Key Takeaways

- This system signals changes to the attack surface; it does not calculate real security risk.
- Score = potential surface change, not likelihood or impact of a vulnerability.
- Higher score → higher potential for security-relevant review, but not necessarily higher risk.
- Developers retain full control over the advisory section.
- Complements, but does not replace, threat modeling, SAST, or other security audits.
