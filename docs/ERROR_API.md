# Hub error API

The Hub error API is disabled by default. Set `ERROR_INGEST_ENABLED=true` to enable all three routes; otherwise they return 404.

Set `ERROR_READ_TOKEN_FILE` to a file containing a dedicated opaque bearer token (surrounding whitespace is trimmed). Restrict file permissions to the Hub service account. The Hub loads the file when routes are initialized; restart after rotation. A missing, unreadable, or empty file denies all reads. This credential grants only `errors:read`; machine and administrator credentials do not grant read access.

- `POST /api/v1/machines/{id}/errors`: existing machine bearer credential; target and record machine IDs must match the authenticated machine (an omitted record machine ID is filled in). Body is a JSON array of at most 200 shared `errlog.Record` values and at most 256 KiB. Each record requires a timestamp, component, code, fingerprint, error/warn level and count between 1 and 1,000,000. The Hub redacts metadata, messages and nested context again and drops records that still contain recognized secrets or cannot retain the record schema after redaction. Response: `{"inserted":1,"dropped":0}`. Repeated `(machine_id,fingerprint,ts)` values do not update existing records or counts.
- `GET /api/v1/errors?since=&component=&machine=&limit=`: dedicated read bearer token. Returns a JSON record array, newest first. `since` is RFC3339 (default: 30 days ago); component and machine are exact matches; limit defaults to 200 and accepts 1–1000.
- `GET /api/v1/errors/top?since=`: same token and timestamp default; returns up to 200 fingerprint groups ordered by total count, with `fingerprint`, `first_seen`, `last_seen`, `count`, and distinct `machines`. Counts sum uploaded record counts within the selected timestamp window.

Error telemetry is stored in `<hub database path>.errors.sqlite` with its own WAL and writer. A batch commits in one transaction before acknowledgment, without acquiring the fleet database writer. Include this file and its SQLite WAL state in any backup that must preserve error history. Schema creation is additive and idempotent at store open, following the main store schema initialization pattern.

The existing automatic/manual prune workflow expires error records after 30 days using Hub receive time, including the newest record. Dry runs include the error count, and applied prune counts are recorded in the main retention log. Aggregates are computed from retained records, so pruning also removes their contributions.

This step adds no uploader, UI, issue filing, or deployment.
