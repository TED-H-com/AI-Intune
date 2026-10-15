# Channels phase 1

The `internal/channels` package provides outbound Telegram and webhook delivery.
`Provider` exposes `Name`, `Kind`, `Send(context.Context, Message) error`, and
`Health(context.Context) (HealthStatus, error)`. Health reports whether credentials
resolve and configuration is usable; it does not contact the remote service or
send a message. A ready channel can still fail delivery.

## Credentials and compatibility

Configuration contains credential references, never credential values:

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
HTTP errors returned by the UI are fixed text. The Channels HTML/JSON projections
contain only identifiers, kind, health, and bindings; neither credential values nor
references are returned. Resolved values are short-lived transport inputs and are
never persisted to channel configuration or audit details.

## Administration and bindings

Open **Channels** in the Hub navigation. Operators with `view` may inspect channel
health and bindings. The independent `admin` capability permits creating/updating
a channel, deleting it, sending a test, and adding/removing bindings. Full admins
also need `view` to see the page, matching the existing non-hierarchical capability
model. Reference fields are entered anew when replacing a configuration.

All mutations are POST forms protected by the same Hub operator boundary and Go
CrossOriginProtection as other forms. Cross-site browser requests are forbidden;
there is no separate synchronizer token requirement. Channel/binding changes and
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

## Future providers and inbound commands

Discord can implement the same outbound interface using registry credential
references, its own payload/size/rate-limit rules, and secret-safe diagnostics.
It is not included in phase 1.

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
