# ORG-5 — In-App Documentation Page & Realtime Policy Tightening

Completes the orgs phase. Frontend-centric; the only backend change is
migration `0012_tighten_realtime_policies` (absorbs the ORG-2 demo tradeoff)
plus the shared Suite 21.

## Content pipeline

`frontend/src/docs/content.ts` is the single content source: a typed
`DocSection[]` where each section declares `audience` (`user | org | both`)
and an optional `minRole` (`viewer | analyst | admin`), with body blocks of
kind `text | list | code | diagram | table`.

**Provenance rule:** examples are derived ONLY from real artifacts —
fixtures (`backend/tests/data/…`), executed curls (recorded with dates in
`frontend/src/docs/PROVENANCE.md`), suite-verified outputs
(`backend/scripts/run_all_tests.py` assertions), eval metrics
(`backend/tests/reports/eval_report.md`), or route transcriptions from
`backend/app/api/routes_*.py`. Invented outputs are forbidden; anything not
executed is marked illustrative.

**Mechanical verification:** `frontend/scripts/check-docs.mjs` (run:
`node scripts/check-docs.mjs`)
1. every feature guide (`guide-*`) carries ≥1 example block;
2. all TOC anchors resolve;
3. audience/minRole tags are valid, org sections declare minRole;
4. every api-reference row (method + path) matches a REAL route parsed from
   `backend/app/api/routes_*.py` (multi-router files supported).
The checker caught two real transcription errors during authoring (quarantine
routes live under `/enforcement/*`, not `/db/*`) — the mechanism works.

## Sections (15)

| id | audience | minRole |
| --- | --- | --- |
| overview-quickstart | both | — |
| guide-phishing, guide-url, guide-deepfake, guide-impersonation, guide-log-analysis, guide-email-connectors, guide-quarantine-senders, guide-security-history, guide-notifications | user/both (see tags) | — |
| scanning-architecture | both | — |
| org-guide | org | viewer |
| api-reference | both | — |
| failure-taxonomy | both | — |
| troubleshooting | both | — |

Feature guides follow the uniform skeleton: what it detects → steps →
example input (real fixture) → example output (executed or suite-verified) →
indicator table → honest limitations (eval findings quoted, never hidden).

## Page & gating

`frontend/src/pages/Docs.tsx` at `/docs` (nav entry "Documentation", scope
`both`, System section): left sticky TOC, top search filtering titles and
serialized bodies, code blocks with copy buttons + provenance footnotes,
diagrams as styled `<pre>`. Theme tokens only; no new dependencies.

Gating matrix:

| Context | org-audience sections | minRole sections |
| --- | --- | --- |
| Personal workspace | rendered with an "Organization feature" badge | RoleGuard-style role check |
| Org workspace, viewer+ role | fully rendered | analyst/admin sections render the access-denied panel below the viewer set |
| Org workspace, analyst/admin | fully rendered | fully rendered |

## Realtime tightening (D4, deferred from ORG-2)

Migration `0012_tighten_realtime_policies` drops the permissive
`USING (true)` authenticated SELECT policies added in 0009 and installs
membership-gated ones:

- `org_log_events_realtime_select`: `cyberguard.org_member_role(organization_id, auth.uid()::text) IS NOT NULL`
- `alerts_realtime_select`: membership for org rows; `owner_user_id = auth.uid()::text` for personal rows

Guards: SQLite/vanilla-PG (no `auth.uid()`) is a clean no-op for the gated
creation — permissive policies are still dropped (deny-by-default for a role
that can never authenticate there anyway). User-plane baseline policies (TO
`cyberguard_api`, owner-scoped) are untouched. Verified by Suite 21
(`scripts/test_org_realtime_policies.py`, 9 checks): policy presence,
predicate inspection via `pg_get_expr`, cross-org denial through
`org_member_role` resolution, baseline-policy integrity, and the guard.

## Hard rules honored

No changes to detection/ML/enforcement code, theme, or the Phase 7
notification path; user-mode surface changes are limited to the nav entry
and the `/docs` route. No new dependencies.
