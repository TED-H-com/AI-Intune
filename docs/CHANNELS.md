# Channels phase 3

The `internal/channels` package provides outbound Telegram, Discord, and generic
webhook delivery.
`Provider` exposes `Name`, `Kind`, `Send(context.Context, Message) error`, and
`Health(context.Context) (HealthStatus, error)`. Telegram and generic webhook
health report whether credentials resolve and configuration is usable. Discord
health contacts the remote service without sending a message: bot mode uses
`GET /users/@me`; webhook mode GETs the resolved webhook URL. A ready channel
can still fail delivery.

## Credentials and compatibility

Configuration contains credential references, never credential values:

- Discord bot: `env://DISCORD_BOT_TOKEN` in `TokenRef` and
  `env://DISCORD_CHANNEL_ID` in `ChatRef` (the existing destination reference field).
  The resolved destination must be a numeric channel ID.
- Discord webhook: `env://DISCORD_WEBHOOK_URL` in `URLRef`. Bot and webhook
  modes are mutually exclusive; generic webhook signing fields are unsupported.
- Telegram: `env://TELEGRAM_BOT_TOKEN` and `env://TELEGRAM_CHAT_ID`.
- Webhook: `env://CLAWCTL_NOTIFY_WEBHOOK_URL`, with optional
  `env://CLAWCTL_NOTIFY_WEBHOOK_SECRET`.
- File references use `file:///absolute/path/notify.env#KEY`. Resolve through the
  existing `internal/secrets` registry. Additional registered providers can resolve
  supported references; `bws://project/key` remains unavailable until configured.

Telegram sends the existing form payload with link previews disabled and truncates
after 3,900 Unicode code points, retaining the existing suffix. Webhooks send
`kind`, `text`, and UTC RFC3339 `sent_at`, with optional HMAC-SHA256
`X-Clawctl-Signature`. Both retain the 20-second timeout, one MiB response limit,
`clawctl-hub` user agent, and refusal to follow redirects. Webhooks require HTTPS,
except literal loopback and Tailscale CGNAT addresses, matching existing behavior.

The existing `CLAWCTL_NOTIFY_ENV`, `CLAWCTL_NOTIFY_CMD`, precedence, payloads,
notification ledger, and retry schedule remain unchanged. Built-in delivery now
uses these providers and resolves a single file snapshot per attempt, preserving
rotation without restarting. On first startup with usable legacy channels, their
references are imported into the management inventory once. Removing an imported
entry does not cause it to reappear after restart.

The phase 1 inventory and test sends are managed independently of the existing
automated notification configuration. Editing/removing inventory entries does not
rewrite the host's env file or change automated notification destinations.
New inventory entries are available for test delivery; automated routing is future
work. To change existing automated notifications, update the existing env file.

Provider diagnostics redact resolved values. Credential resolution failures and
HTTP errors returned by the UI are fixed text. The channel HTML/JSON projections
contain only identifiers, kind, health, and bindings; channel credential values
and references are hidden. Bot inventory displays metadata and token references,
never resolved credentials. Resolved values are short-lived transport inputs and
are never persisted to channel configuration or audit details.

## Administration and bindings

Open **Channels** in the Hub navigation. Operators with `view` may inspect channel
health and bindings. The independent `admin` capability permits creating/updating
a channel, deleting it, sending a test, and adding/removing bindings. Full admins
also need `view` to see the page, matching the existing non-hierarchical capability
model. Reference fields are entered anew when replacing a configuration.

All mutations are POST forms protected by the same Hub operator boundary and Go
CrossOriginProtection as other forms. Cross-site browser requests are forbidden;
there is no separate synchronizer token requirement. Channels mutations additionally
require an Origin header or Sec-Fetch-Site: same-origin; requests missing both
are rejected, including non-browser clients. CrossOriginProtection validates the
origin evidence before the form handler runs. Channel/binding changes and
audit evidence commit atomically. Test sends persist intent before contacting
the remote endpoint, fail closed if that audit write fails, and record a fixed-text
outcome. An intent without a completion after a crash means delivery is uncertain;
it is not automatically retried.

SQLite schema initialization adds `outbound_channels`, `channel_bindings`, and a
one-time inventory initialization marker to existing and new databases.
A binding associates one channel with a registered machine ID (the agent identity).
Duplicate pairs and unknown machines/channels are rejected. Channel deletion
removes its bindings in the same audited transaction. Bindings have no routing,
inbound command, or authorization effect. Metadata is retained until explicitly
removed; machine data disclosure includes these records.

## Discord delivery and bot registry

Discord bot delivery POSTs JSON to /channels/{id}/messages with Authorization:
Bot &lt;resolved token&gt;. Webhook delivery POSTs to the resolved webhook URL.
Both send content and disable automatic mentions using allowed_mentions.parse=[].
Messages above 2,000 Unicode code points are rejected. Discord uses the existing
20-second request timeout, one MiB response limit, and redirect refusal.
The API base defaults to https://discord.com/api/v10 and can be overridden by
NewDiscordForAPI for transport tests.

HTTP 429 retries at most twice (three attempts total), using Retry-After seconds
or an HTTP date, falling back to JSON retry_after seconds. Each wait is bounded
to five seconds and respects context cancellation. Other HTTP failures are not
retried. Discord diagnostics use fixed text or HTTP status codes; response
bodies, transport URLs, webhook token paths, and resolved credentials are never
returned or logged.

The separate channel_bots inventory stores a unique name, kind (discord/telegram),
registered host machine ID, agent type (hermes/openclaw/other), token secret
reference, status (active/disabled/unknown), and optional notes. Existing databases
receive this table through the idempotent schema initialization used by channel
inventory. Operators with view can inspect it in HTML and the Channels JSON API.
Admins can add/update by name or remove entries; mutations require origin
evidence, are protected by the existing capability boundary, and commit audit
evidence atomically. Never enter credentials in names or notes. Token references
are displayed, but are never resolved for registry views. Registry status is
operator-maintained metadata, independent of channel health and delivery.
Registry records are included in machine data disclosure and retained until
explicitly removed. Existing channel bindings retain their original meaning.

## Inbound chat commands (opt-in)

Inbound is **off by default**. Set `CLAWCTL_CHANNELS_INBOUND_CONFIG` to a local
JSON file and restart the Hub. Each entry must explicitly set `enabled: true`.
There is no polling worker or Discord gateway, and no always-on gateway process.
Example (all identifiers are placeholders):

```json
[
  {
    "id": "telegram-operations",
    "kind": "telegram",
    "enabled": true,
    "destination": "CHAT_ID",
    "self_id": "BOT_USER_ID",
    "token_ref": "env://TELEGRAM_BOT_TOKEN",
    "secret_ref": "env://TELEGRAM_WEBHOOK_SECRET",
    "approval_seconds": 600
  },
  {
    "id": "discord-operations",
    "kind": "discord",
    "enabled": true,
    "destination": "CHANNEL_ID",
    "self_id": "APPLICATION_BOT_USER_ID",
    "public_key_ref": "env://DISCORD_PUBLIC_KEY",
    "approval_seconds": 600
  }
]
```

Configure each provider to POST to `/v1/channels/CHANNEL_CONFIG_ID/inbound` on
its HTTPS Hub URL. Telegram setWebhook must use the resolved webhook secret as
`secret_token`; its `X-Telegram-Bot-Api-Secret-Token` is compared using constant-time
hash comparison. Only ordinary messages and callback queries are accepted.
Telegram replies use the webhook response's `sendMessage` method (including inline
keyboards); no extra Bot API request is needed. The token reference is validated
as reference-only configuration; outbound Bot API delivery resolves tokens through
the existing secret registry. Do not put resolved tokens in this JSON file.
Discord resolves the hex-encoded Ed25519 application public key through the same
registry, verifies timestamp + exact request body, enforces a five-minute clock
window in both directions, and handles signed PING, application commands, and
button components. Register slash commands externally: `status`, `machines`,
`jobs`, `alerts`, and `ack-alert` with one required string option `alert_id`.
Discord read responses are ephemeral; approval cards are visible in the configured
channel so other allowlisted humans can approve. All Discord responses disable mentions. Unknown users receive no
reply (HTTP 204), including on Discord; the provider may display its own timeout.

Only the configured destination is accepted. Bot senders, the configured self
ID, Telegram messages sent via bots or channel identities, stale Telegram messages
(older than ten minutes), and unsupported event types are ignored. Telegram
update IDs and Discord interaction IDs are deduplicated in SQLite for 24 hours,
including across Hub restarts. The cache holds at most 10,000 live keys and fails
closed at capacity. Telegram's message age check and Discord's signature timestamp
window prevent old events from becoming valid when those keys expire. Limits are
10 events per user per minute and 60 per configured channel per minute; buckets
are process-local, bounded to 4,096 entries, and reset on restart. Request bodies
are limited to 64 KiB. Use provider delivery retries with the original event ID.

On **Channels**, admins map each provider user ID to an existing Hub account ID.
These mappings are independent of outbound inventory and machine bindings. Only
allowlisted humans can issue commands or approve. Roles come from the current Hub
account, using the same account-to-principal function as local web sessions and
`Principal.Has` capability checks. The current local account schema supports only
admins; unknown future roles fail closed. Disabled accounts and removed mappings
immediately lose chat access. This version maps local Hub identities; it does not
infer Tailscale identity from chat profile names. Allowlist mutations use existing
admin and browser-origin checks and commit audit evidence atomically. Allowlist
metadata is visible only to admins; viewers see enabled status and pending actions.

Read commands call the same `operator.Service` as the web UI: `status` gives fleet
counts; `machines` and `jobs` return up to ten IDs and totals; `alerts` returns up
to ten recent disk alert IDs. Responses avoid raw agent evidence and job payloads.
`ack-alert ALERT_ID` is the sole mutation in this phase. It requires the same admin
capability and canonical disk-alert preview/apply API as the web UI. Its approval
card names the exact target and expiry. Any allowlisted human with admin capability
can Approve or Deny; requesters may approve their own requests. The approval stores
the exact preview digest and request and is bound to its channel and destination.
Both requester and approver permissions are rechecked at apply time. Expiry defaults
to ten minutes and may be configured from one to 600 seconds. Pending approvals
are capped at 1,000. Deny and Approve both consume the card once in an audited
transaction before execution. A crash after consumption can leave execution
uncertain; no automatic retry occurs. Inspect the canonical action audit before
issuing another request. Expired approval records are pruned when creating new cards.

There is a positive command set plus an explicit dangerous-domain denylist:
delete/retire, MFA/auth/password changes, token creation, enrollment, secrets,
terminals, and scripts are unavailable, including through approval buttons.
Unknown commands cannot invoke arbitrary Hub routes. Chat cannot change roles,
allowlists, configuration, or credentials. Provider authentication runs outside the
browser session boundary on one explicitly classified inbound route; it does not
relax any operator route or browser CSRF rule.

Command receipt, unknown users, bots, rate denials, blocked commands, approval
requests/decisions and execution outcomes are audited. Successful mutations also
retain canonical action audit evidence with the approving Hub identity and
`chat-allowlist` authentication provenance. Audit failure prevents command
execution or approval creation/consumption. Raw request bodies, provider signatures,
credential values, backend errors and command text are never included in chat audit
records or diagnostics. Inbound status projections omit credential references and
values. State is retained locally until expiry/pruning or explicit mapping removal;
audit records follow the existing Hub audit retention policy.
