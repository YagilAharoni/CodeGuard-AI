# CodeGuardAI Competitive Capability Plan (2026)

## Positioning Choice (Win One Field First)

**Field to dominate:** AI-assisted remediation for small and mid-size engineering teams that need fast security fixes, not enterprise complexity.

Why this field:
- Enterprise AppSec suites are broad but heavy.
- Your product already has strong foundations for this niche: quick scans, GitHub URL analysis, dependency CVE scanning, persona-based results, and PDF exports.
- Speed + clarity + fix quality can beat larger tools for this segment.

---

## Similar Products Reviewed

- Snyk Code
- Semgrep Code + Semgrep Assistant
- SonarQube
- Checkmarx One
- GitHub Advanced Security

Common capability themes among leaders:
1. In-flow developer experience (IDE/PR/CI)
2. High-signal prioritization (risk-aware, not just severity-aware)
3. Fast remediation with concrete fix suggestions or autofix
4. Unified visibility (history, governance, reports, compliance)
5. Strong integrations and workflow automation

---

## What CodeGuardAI Already Has (Strong Base)

Current baseline capabilities:
- Source code scan endpoint and UI workflow.
- GitHub repository scan support.
- Dependency CVE scan support (OSV-backed behavior in UI).
- Severity stats and finding-level remediation guidance.
- Report export and historical records.
- Auth, rate limits, and provider routing.

Gap summary versus category leaders:
- No pull request-native feedback loop yet.
- No issue deduplication and risk scoring model yet.
- No one-click patch application workflow.
- No policy-based quality/security gates.
- Limited team governance and SLA tracking.

---

## Adapted Capability Stack for CodeGuardAI

### 1) Smart Risk Prioritization Layer (Highest Priority)

What leaders do:
- Prioritize exploitability, reachability, and business context.

Adapted for CodeGuardAI:
- Add `risk_score` per finding using weighted model:
  - Severity weight
  - Reachability heuristics
  - Public exposure hints
  - Confidence score
  - Dependency exploit maturity signal (when available)
- Group duplicate issues across scans.
- Surface top 5 fix-first issues per scan.

Implementation fit:
- Backend: enrich finding model in API responses.
- Frontend: add “Fix First” panel in dashboard.

Success metric:
- 30% reduction in mean time to first fix (MTTFix-1).

---

### 2) AI Remediation Workbench (Signature Feature)

What leaders do:
- AI-assisted fixes with high confidence and low friction.

Adapted for CodeGuardAI:
- Per finding:
  - explain root cause in one sentence
  - generate minimal patch diff
  - include regression test suggestion
  - show confidence + rationale
- Add “Apply patch locally” mode (download patch or Git diff).

Implementation fit:
- Backend: add patch payload fields (`patch_diff`, `test_stub`, `fix_confidence`).
- Frontend: split-view before/after with copy/apply actions.

Success metric:
- 50% of high/medium findings resolved using generated patch guidance.

---

### 3) PR and CI Security Gates (Distribution Engine)

What leaders do:
- Security checks in pull requests and build pipelines.

Adapted for CodeGuardAI:
- Add GitHub App or token-based integration that:
  - scans PR diff only for fast feedback
  - comments findings directly on changed lines
  - blocks merge when policy is violated
- Add minimal CLI:
  - `codeguard scan --path .`
  - `codeguard ci --fail-on high`

Implementation fit:
- Backend: webhook endpoint + policy evaluation endpoint.
- DX: lightweight CLI wrapper over existing APIs.

Success metric:
- 70% of scans run pre-merge vs after merge.

---

### 4) Security Policy and SLA Governance

What leaders do:
- Team-level policies, compliance views, and deadlines.

Adapted for CodeGuardAI:
- Policy profiles:
  - startup default
  - fintech strict
  - custom policy
- SLA timer per severity (e.g., High = 7 days).
- “Aging vulnerabilities” and “ownership by repo/team” dashboards.

Implementation fit:
- Add policy storage and scan-to-policy evaluator.
- Add settings UI page for policy templates.

Success metric:
- 90% of high findings resolved within SLA window.

---

### 5) Knowledge Memory and Noise Suppression

What leaders do:
- Learn from triage to reduce repeated false positives.

Adapted for CodeGuardAI:
- Add triage outcomes:
  - accepted risk
  - false positive
  - fixed
- Reuse this memory to suppress repeats and raise confidence on known true positives.

Implementation fit:
- Extend history storage with triage state and rationale.
- Apply suppress/boost logic in prioritization step.

Success metric:
- 40% reduction in repeated non-actionable findings in 60 days.

---

## 90-Day Execution Plan

### Days 1-30 (Core Differentiator)
1. Add risk score model and top-issues ranking.
2. Add remediation workbench payload fields.
3. Update dashboard with “Fix First” panel and patch preview.

### Days 31-60 (Workflow Adoption)
1. Ship GitHub PR comments integration (MVP).
2. Add CI policy gates and fail thresholds.
3. Add triage state and dedupe memory.

### Days 61-90 (Governance + Growth)
1. Add policy templates and SLA tracking.
2. Add organization-level trend dashboards.
3. Add “security progress report” auto-generation for managers.

---

## Competitive Messaging You Can Use

- “Fastest path from finding to fix for real dev teams.”
- “High-signal AppSec: fewer alerts, better fixes.”
- “Built for teams that want security without enterprise overhead.”

---

## North-Star KPIs

- Mean time to first fix (MTTFix-1)
- % findings fixed in PR before merge
- False-positive reopen rate
- % scans passing policy gates
- Weekly active repos scanned

---

## Immediate Next Build Ticket Recommendation

Build this first:
- **Feature:** Risk-scored “Fix First” queue + patch-ready remediation payload.
- **Why first:** Highest user-perceived value with your existing architecture and fastest competitive impact.
