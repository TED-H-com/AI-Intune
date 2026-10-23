# Secret providers

The local defaults require no external service. Configuration holds references,
never values. `internal/secrets` dispatches `Get(ctx, ref)`, `List(ctx, scope)`
and `Health(ctx)` by URI scheme. List enumerates configured references only.

- `env://NAME` reads a process environment variable.
- `file:///absolute/path#KEY` reads an env-style file. URI-escape path/key
  characters. Blank/comment lines, `export `, and matching quotes are supported;
  duplicate keys use the last value. No shell expansion; one MiB read limit.
- `bws://Shared/API_KEY` reads a Bitwarden Secrets Manager project/key.
  Project UUIDs also work: `bws://11111111-1111-1111-1111-111111111111/API_KEY`.
  Names are exact and must be usable as URI hosts; use UUIDs for other names.
  Escape special key characters. Empty values are missing. Duplicate matching
  project names or keys fail rather than selecting an arbitrary value.

`Secret` redacts fmt and JSON output. Only integration boundaries call `Reveal()`;
consumers must keep revealed strings out of logs and responses. References and
names are metadata: never put secret values in them. Backend errors use fixed
classes; raw command output and stderr never enter errors or status responses.

## Bitwarden configuration

Install the official `bws` binary from Bitwarden; no personal-vault `bw serve`
is used. Set `CLAWCTL_SECRETS_CONFIG` to an absolute JSON configuration path on
Hub or agent. Without it, env/file behavior and the unconfigured bws placeholder
remain unchanged. Example (all names and paths are placeholders):

```json
{
  "references": [
    {"name": "service-api", "ref": "bws://Shared/API_KEY"}
  ],
  "bws": {
    "binary": "/usr/local/bin/bws",
    "server_url": "https://vault.bitwarden.com",
    "token_ref": "file:///var/lib/example-secrets/token.env#BWS_TOKEN",
    "timeout_seconds": 10,
    "ttl_seconds": 60,
    "cache_dir": "/var/lib/example-secrets/cache",
    "deny_projects": ["Confidential", "22222222-2222-2222-2222-222222222222"]
  }
}
```

Provision `BWS_TOKEN` in that private env-style file outside application config.
Alternatively use `token_ref: "env://SERVICE_BWS_TOKEN"`. Only env/file token refs
are accepted. The token is re-read for each command, passed solely through the
child's `BWS_ACCESS_TOKEN`, and never placed in argv. The selected source env
variable and inherited `BWS_*` variables are removed from the child environment.
The parent environment is not modified. Protect process access and token files
with the service account's OS permissions.

Binary defaults to `bws`, server to US cloud `https://vault.bitwarden.com`;
EU uses `https://vault.bitwarden.eu`. For self-hosting, supply the HTTPS server
base URL. Credentials/query strings in server URLs are rejected. The explicit
`--server-url` overrides CLI server configuration. Commands are executed directly,
without a shell: `bws project list --output json` and
`bws secret list <project_id> --output json`, plus that server flag. See the
[official CLI documentation](https://bitwarden.com/help/secrets-manager-cli/).
Timeout defaults to 10 seconds per subprocess; expiry kills the command and
bounds pipe cleanup. Output is limited to eight MiB; stderr is discarded.

Project names resolve to UUIDs with an in-memory TTL cache. UUID refs skip name
lookup unless a denylist is configured. With a denylist, IDs also resolve through
project metadata so switching between a name and ID cannot bypass denial.
Deny checks happen before value commands and before cache reads are returned.
Use both immutable IDs and names in the Hub denylist, and deny access in the
machine account grants too. A name-only policy follows metadata refreshed at
TTL expiry; UUIDs avoid rename ambiguity. Directly denied names/IDs never invoke
bws; alias checks may list project metadata but never fetch denied values.

## Cache and lifecycle

Only requested values are retained in memory for `ttl_seconds` (default 60).
Fresh reads avoid bws; expired reads try the source again. A failed refresh may
return the last known good value while health records the source failure. An
optional `cache_dir` persists each requested ref atomically, file mode `0600`,
directory mode `0700`. It must be an absolute, dedicated private directory;
existing directory permissions are restricted at startup. Public/nonregular
cache files are ignored. Files contain plaintext values: protect backups and
local account access accordingly. Cache files are scoped by server, token ref,
and secret ref; tokens themselves are never persisted there.

LKG has **no maximum stale age**: enabling persistence deliberately favors
availability during outages, including across restarts. Leave `cache_dir` unset
to disable disk persistence. Successful missing/empty results evict the ref;
missing projects, denials and caller cancellation do not use stale fallback.
Failures (including authentication, malformed output and timeouts) can use LKG.
Revocation cannot be discovered while offline. For immediate revocation, stop
consumers, delete the dedicated cache directory and restart them. Also purge
caches when changing machine account grants or token identity at an existing
token ref. Rotate source values normally; healthy refresh observes them after
TTL expiry. A fresh Test fetch bypasses value caches and fallback entirely.
Do not use availability-first LKG where immediate offline revocation is required.

`BWS.Status()` exposes configured, reachable and last error class without a
network call; reachable means the last command succeeded, not a continuous
probe. `Health(ctx)` actively lists project metadata, never values. Unconfigured
bws remains `ErrNotConfigured`. Classes include `token_unavailable`,
`command_failed`, `timeout`, `invalid_json`, `ambiguous_project`, `ambiguous_key`,
and `cache_io`; no backend text, token or value is returned.

## Hub page and notify compatibility

`/secrets` and `GET /v1/operator/secrets` require the operator Admin capability
and disable response caching. The JSON endpoint retains its reference-status
array. The page additionally shows bws backend health metadata. Per-ref status is
present/missing/error; present can mean LKG during an outage. Configure all refs
that should appear in `references`; arbitrary caller-selected lookups are not
exposed. Channel configuration uses the same Hub registry for value resolution.

Admin-only `POST /secrets/test` accepts only configured refs, enforces the same
origin/CSRF protection as channel mutations, and reports present/missing/error,
never a value or backend diagnostic. The operator service records intent before
fetch and completion afterward, with authenticated actor, reference and audit
time. Audit failure prevents fetching or reporting success. Test failures use
fixed-text outcomes. Configuration remains local; the page does not edit secrets.

`--notify-env` / `CLAWCTL_NOTIFY_ENV` still designate the existing notify file.
The four legacy Telegram/webhook refs appear alongside configured refs. Notify
retains file parsing, trimming, permission warnings, validation, command
precedence and re-reading per delivery. It does not fall back to process env.

## Agent pull and future brokered delivery

Pull is implemented with the same scoped backend on the consuming host:

```sh
clawctl-agent secrets-pull --config /etc/example/secrets.json \
  --ref bws://Shared/API_KEY --output /var/lib/example-secrets/delivered/api-key
```

Only refs in that local configuration are allowed. The destination must be
absolute in a private directory (created `0700` if absent). The command writes
the raw value atomically with mode `0600`, never to stdout. Retrieval attempts
and outcomes log local UID, configured ref, UTC log time and success only.
Schedule repeated pulls with the host's scheduler when rotation is needed; each
invocation can use the optional disk LKG. No Hub enrollment is required for local
pull. Use distinct read-only role machine accounts for Hub and agent groups;
keep restricted project tokens solely on authorized agents.

The existing enrolled-agent channel authenticates a bearer before WebSocket
upgrade and periodically checks revocation (`agent_terminal_link.go`). However,
`internal/agentrelay` only permits session-scoped PTY open/input/resize/close
frames, and the agent dispatches them to terminal sessions. It has no secret
message type, recipient/ref grant ledger, secure file destination contract or
acknowledgment protocol. Terminal inputs can be recorded. This is not a suitable
secret transport, so brokered delivery is deliberately not implemented.

A future broker needs explicit `delivery_mode: brokered|pull` consumer bindings,
per-agent/ref authorization independent of project access, a versioned secret
frame outside terminal recording, replay/expiry controls and revocation checks.
Hub must resolve only allowed refs after committing an audit intent, send over
the authenticated encrypted channel, and audit recipient, actor, ref, time and
fixed outcome. Agent must validate destination policy, atomically write `0600`
in a `0700` directory, and acknowledge delivery without echoing values. Failed or
uncertain deliveries need explicit retry/idempotency semantics. Until those
contracts exist, use pull; no delivery_mode config field is accepted here.
