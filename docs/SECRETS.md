# Secret providers

Phase 1 keeps the public default local and generic: environment and env-style
files require no external service. Configuration holds references, never secret
values. The `internal/secrets` registry selects a `SecretProvider` by URI scheme;
providers implement `Get(ctx, ref)`, `List(ctx, scope)`, and `Health(ctx)`.
The registry lists configured references only (optionally filtered by URI prefix),
not every environment variable or filesystem entry. Register backends at startup.
The registered `bws` backend returns “not configured” until Phase 2; consequently
aggregate registry health reports that backend unavailable even when local
providers work. A missing or empty value is `ErrMissing`; read/validation failures
are errors. Callers must not log backend errors or include them in status APIs.

## References

- `env://NAME` reads a process environment variable.
- `file:///absolute/path#KEY` reads KEY from a KEY=VALUE file. URI-escape special
  path and key characters. The parser ignores blank/comment lines, accepts
  `export ` and matching single/double quotes, and performs no shell expansion.
  Duplicate keys use the last value. Reads retain the legacy one MiB limit.
- `bws://project/key` identifies a planned Bitwarden Secrets Manager secret.

`Secret` has private storage and redacts String, GoString, every fmt verb, and
JSON output. Consumers explicitly call `Reveal()` at the integration boundary;
once revealed, the caller is responsible for keeping that string out of logs and
responses. Do not place secret values in names, references, or errors.

## Notify compatibility and status

`--notify-env` and `CLAWCTL_NOTIFY_ENV` remain paths to the existing notify file.
The four existing Telegram/webhook keys are represented internally as file URIs.
Notify startup, delivery, and notify-check resolve them through the registry.
File parsing, trimming, permission warnings, channel validation, legacy command
precedence, and re-reading on delivery for rotation remain supported. Notify does
not fall back to process environment values.

The read-only `/secrets` page and `GET /v1/operator/secrets` list configured names,
references, and `present`, `missing`, or `error` status. They never return resolved
values or backend error details. Both require the existing operator `Admin`
capability, with a shared authorization check for future operator-admin scope
support, and disable response caching. The navigation link is admin-only.
No secret editing or arbitrary caller-supplied reference lookup is exposed.

## Planned Phase 2: Bitwarden Secrets Manager

This is a design for an example deployment, not an implemented backend. Phase 1
keeps its local defaults and the `bws` placeholder returning `ErrNotConfigured`.
Bitwarden Secrets Manager would be the source of truth for managed secrets.

### Example organization and access

A Bitwarden Secrets Manager Free plan example uses 2 users, 3 projects, and
3 machine accounts. Projects categorize secrets; machine accounts represent
roles shared across appropriate hosts, not one account per machine. For example:

| Project category | Work role | Home role | Hub role |
| --- | --- | --- | --- |
| Personal | No | Read | No |
| FreeTWAI | Read | Read | Read |
| Confidential | Read | No | No |

The two users administer the organization. The three machine accounts are Work,
Home, and Hub, with read-only access to the projects each role needs. These names
and grants are illustrative, not built-in categories or a required topology.
Provision role tokens only to hosts assigned that role; sharing a role means
revoking its access can affect multiple hosts.

Recommend keeping the most sensitive project (Confidential in this example)
unreadable by the Hub. Authorized role accounts pull those secrets directly, so
the Hub does not receive or cache their values.

### Delivery modes

Support both modes in the same deployment, selected by the consuming role and
secret reference independently of the provider URI scheme:

- **Hub-brokered (`brokered`):** the Hub's machine account reads only its allowed
  projects and pushes the authorized subset to enrolled agents over the existing
  authenticated channel. Enforce per-agent authorization before delivery; Hub
  project access alone does not authorize every agent. Agents write delivered
  secrets with mode `0600`. Audit deliveries and failures using reference,
  recipient, time, and outcome metadata, never secret values or tokens.
- **Agent-pull (`pull`):** an agent uses its own scoped role token to read allowed
  projects directly from Bitwarden Secrets Manager. The token belongs to its
  role's machine account, not a dedicated per-host machine account. Persisted
  secrets use mode `0600`; record safe retrieval outcome metadata. Use this mode
  for projects the Hub must not read.

The planned delivery configuration field is `delivery_mode`, with values
`brokered` or `pull`. It belongs to the consuming role/reference binding, not the
`bws://project/key` URI. `SecretProvider` remains the value-resolution interface;
register a provider configured for the consumer's delivery mode at startup. A
brokered agent resolves from its delivered local cache, while a pull agent
resolves through its scoped backend. Separate consumer registries can therefore
use the same reference with different delivery modes. This field is documented
for Phase 2 only: Phase 1 adds no configuration parsing, routing, or delivery
behavior.

### Cache and lifecycle

Cache last known values for temporary outages in both modes: at the Hub for
projects it may read, and on agents for secrets they receive or pull. Use `0600`
for secret/cache files and restrict access to their containing directories. Define
freshness, expiry, rotation, revocation, cache deletion, and outage behavior before
enabling the backend, including when expired values must fail closed. Report
cache freshness and failures without exposing values or backend error details.
Audit metadata must not contain values or tokens. Token provisioning and cache
storage must keep plaintext values out of application configuration, logs, and
status APIs.

Never use `bw serve`; the personal vault CLI server is not the machine secret
delivery architecture. Neither delivery mode uses it.
