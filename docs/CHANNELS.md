# Channels phase 2

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

## Future providers and inbound commands

No Discord inbound endpoint, polling worker, or gateway connection is implemented.
A future Discord gateway WebSocket needs an always-on process. On Fly, it would
keep the machine awake and prevent normal scale-to-zero; allowing the machine to
sleep risks missed events. Deployment and event recovery policy remain future work.

`InboundHandler` is an optional interface and documentation hook only; no
provider implements it and no inbound HTTP endpoint or polling worker exists.
Future inbound commands must authenticate provider signatures/tokens, allowlist
identities and destinations, resolve authorized machine bindings, and enforce
the existing Hub permissions. Destructive actions require explicit human approval
bound to the exact action and target; a chat message alone must never authorize
them.

Loop protection must include stable provider event IDs, durable deduplication
with bounded retention, origin/correlation metadata, rejection of the bot's own
messages, bounded hop counts, and rate limits. Outbound notifications must not be
interpreted as commands, and transport retries must reuse event identity.
