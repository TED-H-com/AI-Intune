# Design: Fleet error logging, Hub upload, and automatic GitHub Issues

Status: proposal (2026-10-29). Scope: AI-Intune agent + Hub, BAT connector, bat-server, Fleet Monitor.

## Problem
In the last 10 days ~85 AI-Intune commits (11 fixes) and ~100 bat-agent-connector commits (13 fixes) landed; most fixes were found by hand (ssh, screenshots). No machine keeps a structured error record, so the same failure is rediscovered repeatedly.

## Goals
1. Every fleet machine keeps a local, rotated, structured error log for the AI-Intune agent.
2. The same records are uploaded to the Hub and readable via an authenticated read-only API (for Grok Bot).
3. BAT components (connector, tunnels, coding sessions, Fleet Monitor, bat-server) emit the same record format, pullable from the Hub.
4. Recurring errors are filed automatically as GitHub Issues: deduplicated, rate limited, secrets redacted.

## Record format (JSON Lines, shared by all components)
```json
{"ts":"RFC3339","machine_id":"...","component":"intune-agent|bat-connector|bat-tunnel|bat-session|fleet-monitor|bat-server",
 "version":"x.y.z","level":"error|warn","code":"stable.dotted.code","msg":"redacted text",
 "fingerprint":"sha256(component|code|normalized_msg)[:16]","count":1,"context":{}}
```
`code` is a stable identifier (e.g. `agent.hub_call.timeout`, `tunnel.respawn_failed`, `session.resume.too_large`). `fingerprint` normalizes numbers, paths, UUIDs, ports and hex out of `msg`.

## Local storage
- Linux/macOS: `/var/log/ai-intune/errors.jsonl` (agent) and `~/.bat/logs/errors.jsonl` (BAT).
- Windows: `%ProgramData%\AI-Intune\logs\errors.jsonl`, `%LOCALAPPDATA%\BAT\logs\errors.jsonl`.
- Rotation: 10 MB x 5 files; identical fingerprints within 60 s collapse into one record with `count`.
- Local copy is authoritative; upload never deletes it.

## Redaction (before writing to disk, again on Hub ingest)
Remove: Authorization/Bearer values, `token=`/`password=`/`secret=` query and env pairs, URLs with userinfo, GitHub tokens (`gh[pousr]_…`, `github_pat_…`), private-key blocks, JWTs, Tailscale/Cloudflare keys, email-like strings in paths. Unit tests carry a corpus of known secret shapes; ingest rejects records still matching.

## Upload to Hub
- Agent tails its spool and POSTs batches (≤200 records, ≤256 KB) to `POST /api/v1/machines/{id}/errors` with the existing machine credential; idempotent by `(machine_id, fingerprint, ts)`.
- BAT components write to their local file; the AI-Intune agent (already on each machine) ships BAT files too, so BAT needs no Hub credential.
- Offline: spool keeps an upload cursor; resumes with fast retry (PR #131 helper).
- Hub stores in a separate SQLite table (off the contended writer path, cf. #119), retention 30 days, aggregated per fingerprint.
- Read API: `GET /api/v1/errors?since=&component=&machine=` and `GET /api/v1/errors/top` behind a read-only API token scoped `errors:read` (new; not the admin password).

## Automatic GitHub Issues
A Hub job (every 15 min) promotes aggregated fingerprints:
- Threshold: ≥3 occurrences or ≥2 machines in 24 h, level=error.
- Routing: `intune-*` → TED-H-com/AI-Intune (issues must be enabled); BAT components → TED-H-com/bat-agent-connector.
- Dedup: issue body carries `<!-- fp:FINGERPRINT -->`; search open issues by marker; if found, add a comment at most once per 24 h with updated counts; closed issue + recurrence after a fix version → reopen with label `regression`.
- Rate limit: ≤5 new issues/hour, ≤20/day per repo; overflow summarized in one digest issue.
- Content: code, component, versions, machines (IDs only), first/last seen, 5 redacted sample lines. Labels: `auto-filed`, `component:*`.
- Credential: fine-grained token (Issues:write only). Bitwarden is the source of truth; the operator places it in a root-only 0600 file on the Hub VM, path given by `ERROR_ISSUES_TOKEN_FILE`. The Hub refuses to file if the file is missing, not 0600, or not root-owned. No token in env vars, repo or images.
- Flag: `ERROR_ISSUES_ENABLED` defaults to false; `ERROR_ISSUES_DRY_RUN=true` logs what would be filed without calling GitHub.

## Rollout (small PRs)
1. Shared record schema + redactor + tests (AI-Intune `internal/errlog`).
2. Agent local error log + rotation.
3. Hub ingest endpoint + table + read API (feature flag off).
4. Agent uploader (including BAT log files).
5. BAT connector / Fleet Monitor / tunnel / session writers (bat-agent-connector).
6. bat-server writer (better-agent-terminal).
7. Issue filer job (dry-run mode first: logs what it would file).
Deployment is manual and separate: Hub (GCE VM `ai-intune-hub`, us-east1-b) first (flag off), then agents canary on one machine, then fleet.

## Non-goals
Full log shipping, metrics, tracing; changing machine credentials.
